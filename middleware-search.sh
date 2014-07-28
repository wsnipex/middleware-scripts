searchprocs="apache httpd java tomcat jboss"
searchpkgs="apache apache2 java tomcat jboss"
searchdirs="/opt /etc /export"
fskeywords="[aA]pache java [tT]omcat [jJ][bB]oss"
procfilter=(bash sh LLAWP)

PS=${PS:-"ps -ef"}
GREP=${GREP:-"grep"}
#--------------#

function get_env {
  local os=$(uname)
  HOST="$(host $(hostname))"
  case $os in 
    SunOS)
      OS="solaris"
      pkgmanager="pkginfo"
      [ $(command_exists /usr/ucb/ps) -eq 0 ] && PS="/usr/ucb/ps -axwww"
      [ $(command_exists /usr/xpg4/bin/grep) -eq 0 ] && GREP=/usr/xpg4/bin/grep
      ;;
    Linux)
      OS="linux"
      [ -f /etc/redhat-release ] && pkgmanager="rpm -qa"
      [ -f /etc/debian_version ] && pkgmanager="dpkg -l"
      ;;
    *)
      OS="unknown"
      ;;
  esac   
}

function command_exists {
  command -v $1 >/dev/null 2>&1
  echo $?
}

function is_inarray () {
  local e
  for e in "${@:2}"; do [ "$e" == "$1" ] && return 0; done
  return 1
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

function check_versions {
  local process=$1
  local input=$2
  local pid
  local command
  local output=""

  read -r pid command <<< ${input/@/ }
  if is_inarray "$command" "${procfilter[@]}"; then
     [ ${DEBUG} ] && echo "INFO skipping $command"
     return 1
  fi
  if is_inarray "$command" "${duplicates[@]}"; then
     [ ${DEBUG} ] && echo "INFO skipping duplicate $command"
     [ ${DEBUG} ] && echo "dups: ${duplicates[@]}"
     return 1
  else
     duplicates=(${duplicates[@]} "$command")
  fi

  case $process in
    apache|httpd)
      local ap_ld_path=$(dirname $command)/../lib
      [ -x $command ] && output=$(LD_LIBRARY_PATH=${ap_ld_path}:$LD_LIBRARY_PATH $command -v 2>&1 | cut -d " " -f 3 ; exit ${PIPESTATUS[0]})
      check_return_code $command $?
      ;;
    tomcat)
      local java_home="$(dirname $command)/.."
      local catalina_home=$(${java_home}/bin/jps -lv | $GREP $pid | sed 's/^.*-Dcatalina.home=\(.*\) .*$/\1/g')
      [ ${DEBUG} ] && echo "INFO java_home=${java_home} catalina_home=$catalina_home"
      output=$(CATALINA_HOME=${catalina_home} JAVA_HOME=${java_home} ${catalina_home}/bin/version.sh  | $GREP "Server version" | cut -d " " -f 4 ; exit ${PIPESTATUS[0]})
      if ! check_return_code $command $?; then return 1; fi
      ;;
    java)
      [ -x $command ] && output=$($command -version 2>&1 | head -1 | cut -d " " -f 3- | tr -d \" )
      if ! check_return_code $command $?; then return 1; fi
      ;;
    jboss)
      [ $(echo $command | $GREP -q run ; echo $?) -eq 0 ] && output=$($command -V 2>&1) #|| echo "run.sh not found, process is $command"
      check_return_code $command $?
      ;;
    *)
      echo "NA"
      ;;
  esac
  if [ $? -eq 0 ] && [ "${output}" != "not found" ]; then
    echo "${output},"
  fi
  unset output
}

function search_processes {
  local output
  local p
  local t
  local r

  ([ ${DEBUG} ] || [ ${SHOW_PROCS} ]) && echo '#---- checking running processes ----#'
  for p in $searchprocs ; do
    t=$($PS | $GREP -iE [^org.]$p | $GREP -vE "grep|/bash" | awk '{ print $1"@"$5 }')
    ([ ${DEBUG} ] || [ ${SHOW_PROCS} ]) && echo "${p}: $t"
    declare result_$p="$t"
  done

  echo '#---- checking versions --------------#'
  for p in $searchprocs ; do
    output=("$p")
    v=result_$p
    res=${!v}
    if [ ${#res} -gt 0 ]; then
      if [ $(echo $res | $GREP -qE " "; echo $?) -eq 0 ]; then
        read -a subres <<<$res
      else
        subres=$res
      fi

      for r in ${subres[@]} ; do
        [ ${DEBUG} ] && echo "CHECK: $p $r"
        t="$(check_versions $p $r)"
        if ! is_inarray "$t" "${output[@]}"; then
          output=("${output[@]}" "$t")
        fi
      done
    fi
    echo "${output[@]}"
    unset output subres r
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
get_env
echo '#--------------------------------------#'
echo "# OS: $OS - hostname: $HOST #"
search_processes
#search_packages
#search_filesystem
