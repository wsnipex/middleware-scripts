#####################################################################
#                                                                   #
# middlewaresearch.sh                    Wolfgang Schupp 2014       #
#                                                                   #
# collects information for common middleware software running       #
# on linux, solaris, aix                                            #
#                                                                   #
# Note: this script does not specify a shebang on purpose.          #
# Its designed to run on the default shells found on the supported  #
# OSs, specifically bash >= v2 and ksh >= 88                        #
#                                                                   #
#####################################################################

#----------------------- CONFIG ------------------------------------#

searchprocs="apache httpd java tomcat jboss websphere python perl php"
searchpkgs="apache apache2 java tomcat jboss python perl php"
searchdirs="/opt /etc /export"
fskeywords="[aA]pache java [tT]omcat [jJ][bB]oss"
procfilter="bash sh LLAWP javasrv"
output_fieldseparator=';'
output_valueseparator=' '
java_tmpfile="/tmp/${$}.java"
proc_filter_file="/tmp/${$}.filter"
ssh_opts="-o BatchMode=yes -o ConnectTimeout=5 -o ForwardX11=no"


PS=${PS:-"ps ax"}
GREP=${GREP:-"grep"}
AWK=${AWK:-"awk"}
SED=${SED:-"sed"}
HOST=${HOST:-"host"}



#------------------------- FUNCTIONS -------------------------------#
function usage {
  echo "usage $(basename $0)
  [-h | --help]               ... this help
  [-p | --procs]              ... show processes in output        [default no]
  [-d | --debug]              ... enable debug output, implies -p [default no]
  [-t | --trace]              ... enable trace output, implies -d [default no]
  [-c | --csv]                ... enable CSV output               [default no]
  [-r | --remote] [user@]host ... enable remote execution via ssh [default no]
  [-f | --file]   filename    ... read [user@]remotehost from file.
                                  format: 1 line per host
                                  implies -r
  [-q | --quiet]              ... no unnecessary output           [default no]
                                  useful with in combination with -c and -f
  "
}

function exit_handler {
  echo "$(basename $0): User aborted, cleaning up"
  rm -f $java_tmpfile $proc_filter_file
  exit 2
}

function get_env {
  typeset os=$(uname)
  case $os in 
    SunOS)
      OS="solaris"
      pkgmanager="pkginfo"
      [ $(command_exists /usr/ucb/ps) -eq 0 ] && PS="/usr/ucb/ps -axwww"
      [ $(command_exists /usr/xpg4/bin/grep) -eq 0 ] && GREP="/usr/xpg4/bin/grep"
      [ $(command_exists /usr/bin/nawk) -eq 0 ] && AWK="/usr/bin/nawk"
      [ $(command_exists /usr/bin/sed) -eq 0 ] && SED="/usr/bin/sed"
      [ $(command_exists /usr/sbin/host) -eq 0 ] && HOST="/usr/sbin/host"
      [ $(command_exists /usr/proc/bin/pfiles) -eq 0 ] && PFILES="/usr/proc/bin/pfiles"
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
  HOSTNAME="$($HOST $(hostname) | $AWK '{ print $1 }')"
}

function command_exists {
  command -v $1 >/dev/null 2>&1
  echo $?
}

function is_inarray {
  ([ "$#" -lt 2 ] || [ -z "$1" ] || [ -z "$2" ]) && return 1
  if echo "$2" | $GREP -q "$1"; then
    return 0;
  else
    return 1
  fi
}

function sort_array {
  typeset e
  sorted=$(for e in $*; do echo "${e}${output_valueseparator}"; done | sort)
  echo $sorted
}

function check_return_code {
  typeset command="$1"
  typeset ret="$2"
  typeset output="$3"
  if [ $ret -ne 0 ]; then
    echoerr "ERROR executing $command"
    [ $TRACE ] && echoerr "TRACE output: "$output" return: $ret"
    return 1
  fi
}

function echoerr {
  echo "$@" 1>&2;
}

function set_newest_java {
  typeset command="$1"
  typeset newver="$2"

  if [ -f $java_tmpfile ]; then
    typeset oldver=$($AWK '{ print $1 }' $java_tmpfile)
    typeset oldcmd=$($AWK '{ print $2 }' $java_tmpfile)
  fi
  typeset tmp=$(echo -e "${oldver}\n${newver}" | sort -r | head -n 1)
  [ "$tmp" != "$oldver" ] && echo "$tmp" "$command" > $java_tmpfile
  return 0
}

function get_newest_java {
  if [ -f $java_tmpfile ]; then
    typeset ver=$($AWK '{ print $1 }' $java_tmpfile)
    typeset cmd=$($AWK '{ print $2 }' $java_tmpfile)
    echo $cmd
  fi
  return 0
}

function set_procfilter {
  echo "$1" >> $proc_filter_file
}

function is_inprocfilter {
  [ -f $proc_filter_file ] || return 1
  $GREP -q "$1" $proc_filter_file && return 0
  return 1
}


function check_versions {
  typeset process=$1
  typeset input=$2

  typeset pid=$(echo $input | $AWK -F"@" '{ print $1 }')
  typeset command=$(echo $input | $AWK -F"@" '{ print $2 }')
  if is_inprocfilter "$command"; then
     [ ${DEBUG} ] && echoerr "INFO skipping $command"
     return 1
  fi

  case $process in
    apache|httpd)
      typeset ap_ld_path=$(dirname $command)/../lib
      [ -x $command ] && output=$(LD_LIBRARY_PATH=${ap_ld_path}:$LD_LIBRARY_PATH ${command} -v 2>&1 | cut -d " " -f 3 | $SED 's|Apache/||' ; exit ${PIPESTATUS[0]})
      check_return_code "$command" "$?" "$output"
      ;;
    java)
      if [ -x $command ]; then
        typeset output=$(${command} -version 2>&1 | head -1 | cut -d " " -f 3- | tr -d \"; exit ${PIPESTATUS[0]})
        typeset ret=$?
        if ! check_return_code "$command" "$ret" "$output"; then return 1; fi
        echo "$output" | $GREP -Eq "[0-9\.]{3}_" || return 1
        set_newest_java "$command" "$output"
      else
        set_procfilter "$command"
        [ $DEBUG ] && echoerr "DEBUG $command not executeable"
        return 1
      fi
      ;;
    tomcat)
      typeset java_home="$(dirname $command)/.."
      typeset jps="${java_home}/bin/jps"
      if [ ! -x "$jps" ]; then
        jps="$(dirname $(get_newest_java))/jps)"
        [ -x "$jps" ] && typeset catalina_home=$(${jps} -lv | $GREP $pid | $SED 's/^.*-Dcatalina.home=\(.*\) .*$/\1/g')
      fi
      [ $TRACE ] && echoerr "TRACE catalina_home1: ${catalina_home}"
      [ ! -d "${catalina_home}" ] && typeset catalina_home=$($PS | $GREP $pid | $SED 's/^.*-Dcatalina.home=\(.*\) -.*/\1/g')
      [ $TRACE ] && echoerr "TRACE catalina_home2: ${catalina_home}"
      if [ ! -d "${catalina_home}" ]; then
        [ $DEBUG ] && echoerr "INFO failed to detect CATALINA_HOME - trying classpath..."
        typeset classpath=$($PS | $GREP $pid | $SED -e 's/^.*-classpath \(.*\) .*$/\1/g' -e 's/:/ /g')
        [ $TRACE ] && echoerr "TRACE classpath: $classpath"
        for p in ${classpath}; do
          if $(echo "$p" | $GREP -v Main | $GREP -qi tomcat) ; then
            typeset tctmp=$p
            if [ -d $tctmp ] || [ -f $tctmp ]; then
              typeset catalina_home_t=$(echo $(dirname $tctmp) | $SED -e 's/bin//g' -e 's/lib//g' | sort -u)
              [ -f ${catalina_home_t}/bin/catalina.sh ] && typeset catalina_home="$catalina_home_t"
              [ $TRACE ] && echoerr "TRACE catalina_home3: ${catalina_home}"
            fi
          fi
        done
      fi
      if [ ! -d "${catalina_home}" ]; then
        echoerr "ERROR failed to detect CATALINA_HOME"
        [ $TRACE ] && echoerr "TRACE catalina_home_final: ${catalina_home}"
        return 1
      fi
      typeset tomcat_command="CATALINA_HOME=${catalina_home} JAVA_HOME=${java_home} sh ${catalina_home}/bin/catalina.sh version"
      [ $TRACE ] && echoerr "TRACE tomcat_command: $tomcat_command"
      typeset output=$(eval ${tomcat_command} | $GREP -iE "version.*tomcat" | $SED 's/.*\([0-9]\{1,2\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/' ; exit ${PIPESTATUS[0]})
      if ! check_return_code "$tomcat_command" "$?" "$output" || [ -z "$output" ]; then
        typeset tomcat_command="JAVA_HOME=${java_home} sh ${catalina_home}/bin/catalina.sh"
        typeset output=$(eval ${tomcat_command} 2>&1 | $GREP CATALINA_HOME | $SED 's/.*-\([0-9]\{1,2\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/'; exit ${PIPESTATUS[1]})
      fi
      if ! check_return_code "$tomcat_command" "$?" "$output"; then set_procfilter "$command"; return 1; fi
      ;;
    jboss)
      typeset java_home="$(dirname $command)/.."
      typeset jinfo="${java_home}/bin/jinfo"
      [ -x ${jinfo} ] || jinfo="$(dirname $(get_newest_java))/jinfo"
      typeset jboss_home=$(${jinfo} $pid 2>&1 | $GREP jboss.home.dir | cut -d " " -f 3)
      if [ -z "${jboss_home}" ]; then
        [ $DEBUG ] && echoerr "INFO failed to detect JBOSS_HOME - trying classpath..."
        typeset classpath=$($PS | $GREP $pid | $SED -e 's/^.*-classpath \(.*\) .*$/\1/g' -e 's/:/ /g')
        [ $TRACE ] && echoerr "TRACE classpath: ${classpath} | sort -u)"
        for p in ${classpath}; do
          if $(echo "$p" | $GREP -v Main | $GREP -qi jboss) ; then
            typeset jbtmp=$p
            if [ -d $jbtmp ] || [ -f $jbtmp ]; then
              typeset jboss_home=$(echo $(dirname $jbtmp) | $SED -e 's/bin//g' -e 's/lib//g' | sort -u)
              [ -f ${jboss_home}/bin/run.sh ] && break
            fi
          fi
        done
      fi
      if [ ! -d "${jboss_home}" ]; then
        echoerr "ERROR failed to detect JBOSS_HOME"
        [ $TRACE ] && echoerr "TRACE jboss_home: ${jboss_home}"
        return 1
      fi
      typeset jboss_command="JBOSS_HOME=${jboss_home} JAVA_HOME=${java_home} sh ${jboss_home}/bin/run.sh -V"
      typeset output=$(eval ${jboss_command} | $GREP -i "build" | $SED -e 's/[jJ][bB][oO][sS][sS]//' -e 's/(.*)//'; exit ${PIPESTATUS[0]})
      if ! check_return_code "$jboss_command" "$?" "$output"; then set_procfilter "$command"; return 1; fi
      ;;
    websphere)
      typeset ws_home=$(echo $command | $SED 's|\(.*AppServer\).*$|\1/bin|')
      typeset output=$(${ws_home}/versionInfo.sh | $GREP -v Directory | $AWK '/^Version/ { if (length($2)>=4) print $2 }')
      if ! check_return_code "${ws_home}/versionInfo.sh" "$?" "$output"; then set_procfilter "$command"; return 1; fi
      ;;
    python)
      typeset output=$($command -V 2>&1 | $AWK '{ print $2 }')
      if ! check_return_code "$command" "$?" "$output"; then set_procfilter "$command"; return 1; fi
      ;;
    perl)
      typeset output=$($command -v | $GREP "This is perl" | $SED 's/.*v\([0-9]\{1,2\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/')
      if ! check_return_code "$command" "$?" "$output"; then set_procfilter "$command"; return 1; fi
      ;;
    php)
      typeset output=$($command -v | head -n 1 | sed 's/^PHP \([0-9]\{1,2\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/')
      if ! check_return_code "$command" "$?" "$output"; then set_procfilter "$command"; return 1; fi
      ;;
    *)
      echo "NA"
      ;;
  esac
  if [ $? -eq 0 ] && [ -n "${output}" ] && [ "${output}" != "not found" ]; then
    echo "${output}"
  fi
  unset output
  return 0
}

function search_processes {
  typeset f='grep|/bash'
  typeset duplicates_proc
  typeset duplicates_net
  typeset csv_out
  typeset r
  typeset t
  typeset p

  [ $BE_QUIET ] || echo '#---- checking versions --------------#'
  [ ${SHOW_PROCS} ] && echo '#---- checking running processes ----#'
  for p in $searchprocs ; do
    [ "$p" == "apache" ] && ef='|org.apache'
    [ "$p" == "jboss" ] && ef='|jbossall-client'
    [ "$p" == "websphere" ] && ef='|InformationServer'
    typeset t=$($PS | $GREP -i "${p}" | $GREP -vE "${f}${ef}" | $AWK '{ print $1"@"$5 }')
    [ ${SHOW_PROCS} ] && echo "PROCESSES ${p}: $t"
    unset ef


    for r in ${t} ; do
      typeset pid=$(echo $r | $AWK -F"@" '{ print $1 }')
      typeset c=$(echo $r | $AWK -F"@" '{ print $2 }')
      if ([ "$p" = "apache" ] || [ "$p" = "httpd" ] || [ "$p" = "java" ] ) && is_inarray "${c}" "${duplicates_proc}"; then : ; else
        duplicates_proc="${duplicates_proc} ${c}"
        [ ${DEBUG} ] && echoerr "PROCCHECK: $p $r"
        t="$(check_versions $p $r)"
        if ! is_inarray "$t" "${output}"; then
          typeset output=""${output}" "${t}""
        fi
      fi
      if [ "$p" = "java" ] || is_inarray "${pid}" "${duplicates_net}"; then : ; else
        duplicates_net=""${duplicates_net}" "${pid}""
        [ ${DEBUG} ] && echoerr "NETCHECK: $p $pid"
        typeset n="$(get_proc_tcpports $pid)"
        if ! is_inarray "$n" "${net}"; then
          typeset net=""${net}" "${n}""
        fi
      fi
      unset pid c
    done
    unset r t n

    if [ $CSV_OUTPUT ]; then
      typeset csv="$(sort_array "${output}")${output_fieldseparator}$(sort_array "${net}")"
      typeset csv_header="${csv_header}${p}_version;${p}_IPs;"
      typeset csv_out="${csv_out}${output_fieldseparator}${csv}"
    else
      echo "${p}${output_fieldseparator}$(sort_array "${output}")${output_fieldseparator}$(sort_array "${net}")" | $SED 's/[()]//g'
    fi
    unset output net subres r t p
  done
  [ $CSV_OUTPUT ] && [ ! $BE_QUIET ] && echo "hostname;${csv_header}"
  [ $CSV_OUTPUT ] && echo "${HOSTNAME}${csv_out}" | $SED 's/[()]//g'
  [ $BE_QUIET ] || echo '#------------------------------------#'
  unset p
}

function get_proc_tcpports {
  typeset pid="$1"
  typeset ret
  typeset ips

  case "$OS" in
  solaris)
    ips=$($PFILES $pid 2>/dev/null | $AWK '/sockname: AF_INET/ {x=$3;y=$5; getline; if($0 !~ /peername/ )  print x":"y }' | sort -u | $SED 's/0.0.0.0:0//g' | tr '\n' ' '; exit ${PIPESTATUS[0]})
    ret=$?
    echo "$ips" | $GREP -Eq "([0-9]{1,3}\.){3}[0-9]{1,3}" || ret=1
    ;;
  linux)
    ips=$(netstat -anltp 2>/dev/null | $AWK "/LISTEN.*$pid/ {print \$4}"; exit ${PIPESTATUS[0]})
    ret=$?
    ;;
  *)
    echoerr "ERROR get_proc_tcpports: unknown OS"
    return 1
    ;;
  esac

  [ ${DEBUG} ] && echoerr "IPS $pid: ${ips}"
  if [ $ret -eq 0 ]; then
    echo "$ips"
  else
    echoerr "ERROR checking listen IPs for pid: $pid return code: $?"
  fi
  unset pid ret ips
}

function search_packages {
  [ $BE_QUIET ] || echo '#---- checking packages ---------------#'
  if [ -z "$pkgmanager" ]; then
   echo "ERROR: unknown package manager, skipping package checks"
   return
  fi

  for pkg in $searchpkgs ; do
    echo -n "${pkg}: "
    typeset res=$($pkgmanager | $GREP $pkg)
    echo $res
  done
}

function search_filesystem {
  typeset num=1
  typeset findstring="find"

  for dir in $searchdirs ; do
    [ -d $dir ] && findstring="${findstring} ${dir}"
  done

  for name in $fskeywords ; do
    [ $num -eq 1 ] && findstring="${findstring} -type d -name '*${name}*' "
    [ $num -gt 1 ] && findstring="${findstring} -o -type d -name '*${name}*' " 
    num=$(( $num +1 )) 
  done

  [ $BE_QUIET ] || echo '#---- checking filesystem ---------------#'
  [ $BE_QUIET ] || echo "# running: $findstring #"
  eval ${findstring} 2>/dev/null
}

function ssh_exec {
  typeset rhost="$1"

  [ $DEBUG ] && echoerr "checking remote shell"
  typeset rshell=$(ssh ${ssh_opts} $rhost -C "command -v bash")
  [ $? -eq 0 ] || typeset rshell=$(ssh $rhost -C "command -v ksh")
  if [ -z "$rshell" ]; then
    echoerr "ERROR could not determine remote shell for host $rhost, skipping"
    return 1
  else
    [ $DEBUG ] && echoerr "remote shell: $rshell"
    ssh ${ssh_opts} $rhost "cat | $rshell /dev/stdin" "$REMOTE_OPTS" < "$MYSELF"
  fi
}

function read_remotefile {
  typeset remotehost
  cat $RHFILE | $SED '/^#/d' | while read remotehost ; do
    [ -z "$remotehost" ] && continue
    ssh_exec "$remotehost"
  done
  exit 0
}

###
# Main
###
MYSELF=$0

# get options
while :; do
  case $1 in
    -h | --help)
      usage
      exit 0
      ;;
    -q | --quiet)
      BE_QUIET=true
      REMOTE_OPTS="$REMOTE_OPTS -q"
      shift
      ;;
    -p | --procs)
      SHOW_PROCS=true
      REMOTE_OPTS="$REMOTE_OPTS -p"
      shift
      ;;
    -d | --debug)
      SHOW_PROCS=true
      DEBUG=true
      REMOTE_OPTS="$REMOTE_OPTS -d"
      shift
      ;;
    -t | --trace)
      SHOW_PROCS=true
      DEBUG=true
      TRACE=true
      REMOTE_OPTS="$REMOTE_OPTS -t"
      shift
      ;;
    -c | --csv)
      CSV_OUTPUT=true
      REMOTE_OPTS="$REMOTE_OPTS -c"
      shift
      ;;
    -r | --remote)
      RHOST=$2
      [ -z $RHOST ] && echoerr "no hostname given" && exit 2
      REMOTE_EXEC=true
      shift 2
      ;;
    -f | --file)
      RHFILE=$2
      [ -z "$RHFILE" ] && echoerr "no filename given" && exit 2
      [ ! -f $RHFILE ] && echoerr "file $RHFILE not found" && exit 2
      READ_RHFILE=true
      REMOTE_EXEC=true
      shift 2
      ;;
    --)
      shift
      break
      ;;
    -*)
      echoerr "WARN: Unknown option (ignored): $1"
      shift
      ;;
    *)
      break
      ;;
  esac
done

trap exit_handler 1 2 6 15

if [ $REMOTE_EXEC ]; then
  if [ $READ_RHFILE ]; then
    read_remotefile
  else
    ssh_exec "$RHOST"
  fi
else
  get_env
  echo "$procfilter" | tr ' ' '\n' > $proc_filter_file
  [ $BE_QUIET ] || echo '#--------------------------------------#'
  [ $BE_QUIET ] || echo "# OS: $OS - hostname: $HOSTNAME #"

  search_processes
  #search_packages
  #search_filesystem

  # cleanup
  rm -f $java_tmpfile $proc_filter_file
fi
