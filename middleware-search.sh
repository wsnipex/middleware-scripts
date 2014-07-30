searchprocs="apache httpd java tomcat jboss websphere python perl"
searchpkgs="apache apache2 java tomcat jboss python perl"
searchdirs="/opt /etc /export"
fskeywords="[aA]pache java [tT]omcat [jJ][bB]oss"
procfilter=(bash sh LLAWP javasrv)

PS=${PS:-"ps ax"}
GREP=${GREP:-"grep"}
AWK=${AWK:-"awk"}
SED=${SED:-"sed"}
HOST=${HOST:-"host"}

# global vars
declare -a duplicates
java_tmpfile="/tmp/${$}.java"
#--------------#

function exit_handler {
  echo "$(basename $0): User aborted, cleaning up"
  rm -f $java_tmpfile
  exit 2
}

function get_env {
  local os=$(uname)
  case $os in 
    SunOS)
      OS="solaris"
      pkgmanager="pkginfo"
      [ $(command_exists /usr/ucb/ps) -eq 0 ] && PS="/usr/ucb/ps -axwww"
      [ $(command_exists /usr/xpg4/bin/grep) -eq 0 ] && GREP="/usr/xpg4/bin/grep"
      [ $(command_exists /usr/bin/nawk) -eq 0 ] && AWK="/usr/bin/nawk"
      [ $(command_exists /usr/bin/sed) -eq 0 ] && SED="/usr/bin/sed"
      [ $(command_exists /usr/sbin/host) -eq 0 ] && HOST="/usr/sbin/host"
      ;;
    Linux)
      OS="linux"
      [ -f /etc/redhat-release ] && pkgmanager="rpm -qa"
      [ -f /etc/debian_version ] && pkgmanager="dpkg -l"
      [ $(command_exists /usr/bin/awk) -eq 0 ] && AWK="/usr/bin/awk"
      [ $(command_exists /bin/sed) -eq 0 ] && SED="/bin/sed"
      [ $(command_exists /usr/bin/host) -eq 0 ] && HOST="/usr/bin/host"

      ;;
    *)
      OS="unknown"
      ;;
  esac   
  HOSTNAME="$($HOST $(hostname))"
}

function command_exists {
  command -v $1 >/dev/null 2>&1
  echo $?
}

function is_inarray {
  local e
  for e in "${@:2}"; do [ "$e" == "$1" ] && return 0; done
  return 1
}

function sort_array {
  local arr
  arr=($(for e in $*; do echo $e ; done | sort))
  echo "${arr[@]}"
}

function check_return_code {
  local command=$1
  local ret=$2
  if [ $ret -ne 0 ]; then
    echoerr "\"ERROR executing $command\"" 
    return 1
  fi
}

function echoerr {
  cat <<< "$@" 1>&2;
}

function set_newest_java {
  local command=$1
  local newver=$2
  local oldver
  local oldcmd
  local tmp

  [ -f $java_tmpfile ] && read -r oldver oldcmd <<<$(cat $java_tmpfile)
  tmp=$(echo -e "${oldver}\n${newver}" | sort -r | head -n 1)
  [ "$tmp" != "$oldver" ] && echo "$tmp" "$command" > $java_tmpfile
  return 0
}

function get_newest_java {
  local ver
  local cmd

  if [ -f $java_tmpfile ]; then
    read -r ver cmd <<<$(cat $java_tmpfile)
    echo $cmd
  fi
  return 0
}

function check_versions {
  local process=$1
  local input=$2
  local pid
  local command
  local output=""

  read -r pid command <<< ${input/@/ }
  if is_inarray "$command" "${procfilter[@]}"; then
     [ ${DEBUG} ] && echoerr "INFO skipping $command"
     return 1
  fi

  case $process in
    apache|httpd)
      local ap_ld_path=$(dirname $command)/../lib
      [ -x $command ] && output=$(LD_LIBRARY_PATH=${ap_ld_path}:$LD_LIBRARY_PATH $command -v 2>&1 | cut -d " " -f 3 ; exit ${PIPESTATUS[0]})
      check_return_code $command $?
      ;;
    tomcat)
      local java_home="$(dirname $command)/.."
      local jps="${java_home}/bin/jps"
      [ -x "$jps" ] || jps="$(dirname $(get_newest_java))/jps"
      local catalina_home=$(${jps} -lv | $GREP $pid | $SED 's/^.*-Dcatalina.home=\(.*\) .*$/\1/g')
      if [ -z "${catalina_home}" ]; then echoerr "ERROR: failed to detect CATALINA_HOME"; return 1; fi
      local tomcat_command="CATALINA_HOME=${catalina_home} JAVA_HOME=${java_home} sh ${catalina_home}/bin/catalina.sh version"
      output=$(eval ${tomcat_command} | $GREP "Server version" | cut -d " " -f 4 ; exit ${PIPESTATUS[0]})
      if ! check_return_code "$tomcat_command" $?; then return 1; fi
      ;;
    java)
      [ -x $command ] && output=$($command -version 2>&1 | head -1 | cut -d " " -f 3- | tr -d \" )
      if ! check_return_code $command $?; then return 1; fi
      set_newest_java "$command" "$output"
      ;;
    jboss)
      local java_home="$(dirname $command)/.."
      local jinfo="${java_home}/bin/jinfo"
      [ -x ${jinfo} ] || jinfo="$(dirname $(get_newest_java))/jinfo"
      local jboss_home=$(${jinfo} $pid 2>&1 | $GREP jboss.home.dir | cut -d " " -f 3)
      if [ -z "${jboss_home}" ]; then
        echoerr "INFO: failed to detect JBOSS_HOME - trying classpath..."
        local classpath=$($PS | $GREP $pid | $SED 's/^.*-classpath \(.*\) .*$/\1/g')
        IFS=":" read -a cparr <<< "$classpath"
        for p in ${cparr[@]}; do
          if $(echo "$p" | $GREP -v Main | $GREP -qi jboss) ; then
            local jbtmp=$p
          ([ -d $jbtmp ] || [ -f $jbtmp ]) && jboss_home=$(echo $(dirname $jbtmp) | $SED -e 's/bin//g' -e 's/lib//g' | sort -u)
          fi
        done
      fi
      if [ ! -d "${jboss_home}" ]; then echoerr "ERROR: failed to detect JBOSS_HOME"; return 1; fi
      local jboss_command="JBOSS_HOME=${jboss_home} JAVA_HOME=${java_home} sh ${jboss_home}/bin/run.sh -V"
      output=$(eval ${jboss_command} | $GREP -E "^JBoss" | cut -d " " -f 1-2 ; exit ${PIPESTATUS[0]})
      if ! check_return_code "$jboss_command" $?; then return 1; fi
      ;;
    websphere)
      local ws_home=$(echo $command | $SED 's|\(.*AppServer\).*$|\1/bin|')
      output=$(${ws_home}/versionInfo.sh | $GREP -v Directory | $AWK '/^Version/ { if (length($2)>=4) print $2 }')
      if ! check_return_code "${ws_home}/versionInfo.sh" $?; then return 1; fi
      ;;
    python)
      output=$($command -V 2>&1 | $AWK '{ print $2 }')
      if ! check_return_code "$command" $?; then return 1; fi
      ;;
    *)
      echo "NA"
      ;;
  esac
  if [ -n "${output}" ] && [ "${output}" != "not found" ]; then
    echo "${output},"
  fi
  unset output
  return 0
}

function search_processes {
  local output
  local p
  local t
  local r

  ([ ${DEBUG} ] || [ ${SHOW_PROCS} ]) && echo '#---- checking running processes ----#'
  for p in $searchprocs ; do
    t=$($PS | $GREP -iE '[^org.]'"$p" | $GREP -vE 'grep|/bash' | $AWK '{ print $1"@"$5 }')
    ([ ${DEBUG} ] || [ ${SHOW_PROCS} ]) && echo "${p}: $t"
    declare result_$p="$t"
  done

  echo '#---- checking versions --------------#'
  for p in $searchprocs ; do
    output=()
    v=result_$p
    res=${!v}
    if [ ${#res} -gt 0 ]; then
      if [ $(echo $res | $GREP -qE " "; echo $?) -eq 0 ]; then
        read -a subres <<<$res
      else
        subres=$res
      fi

      for r in ${subres[@]} ; do
      local c="${r/*@/}"
      if ([ "$p" = "apache" ] || [ "$p" = "httpd" ] || [ "$p" = "java" ] ) && is_inarray "${c}" "${duplicates[@]}"; then : ; else
        duplicates=("${duplicates[@]}" "${c}")
        [ ${DEBUG} ] && echo "CHECK: $p $r"
        t="$(check_versions $p $r)"
        if ! is_inarray "$t" "${output[@]}"; then
          output=("${output[@]}" "$t")
        fi
      fi
      done
    fi
    echo "${p}; $(sort_array "${output[@]}")"
    unset output subres r t p
  done
  echo '#------------------------------------#'
}

function search_packages {
  local res
  local pkg
  
  echo '#---- checking packages ---------------#'
  if [ -z "$pkgmanager" ]; then
   echo "ERROR: unknown package manager, skipping package checks"
   return
  fi

  for pkg in $searchpkgs ; do
    echo -n "${pkg}: "
    res=$($pkgmanager | $GREP $pkg)
    echo $res
  done
}

function search_filesystem {
  local name
  local res
  local num=1
  local findstring="find"

  for dir in $searchdirs ; do
    [ -d $dir ] && findstring="${findstring} ${dir}"
  done

  for name in $fskeywords ; do
    [ $num -eq 1 ] && findstring="${findstring} -type d -name '*${name}*' "
    [ $num -gt 1 ] && findstring="${findstring} -o -type d -name '*${name}*' " 
    num=$(( $num +1 )) 
  done

  echo '#---- checking filesystem ---------------#'
  echo "# running: $findstring #"
  eval ${findstring} 2>/dev/null
}


###
# Main
###
trap exit_handler 1 2 6 15

get_env
echo '#--------------------------------------#'
echo "# OS: $OS - hostname: $HOSTNAME #"
search_processes
#search_packages
#search_filesystem

# cleanup
rm $java_tmpfile
