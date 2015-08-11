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

# processes to search for
searchprocs="apache httpd java tomcat jboss websphere C:D MQ python perl php mysql"

# system packages to search for. NOTE: checking system packages in currently disabled
searchpkgs="apache apache2 java tomcat jboss python perl php"

# file system locations to check. NOTE: this is currently disabled
searchdirs="/opt /etc /export"
fskeywords="[aA]pache java [tT]omcat [jJ][bB]oss"

# processes to exclude from search
procfilter="bash /bin/sh tail ssh LLAWP javasrv snoop tcpdump less more vi gzip grep rsync tnameserv ARCHIVELOGS InformationServer"

# CSV Output separator
output_fieldseparator=';'

# Normal Output separator
output_valueseparator=' '

# Internal temp vars
java_tmpfile="/tmp/${$}.java"
proc_filter_file="/tmp/${$}.filter"

# SSH Options
ssh_opts="-o BatchMode=yes -o ConnectTimeout=5 -o ForwardX11=no -o StrictHostKeyChecking=no -o ServerAliveInterval=10 -o ServerAliveCountMax=3"

# Additional DNS domains to check non FQDN hosts/IPs against
dnsdomains=""


# define default toolset, can be overridden by setting the corresponding ENV var
PS=${PS:-"ps ax"}
GREP=${GREP:-"grep"}
AWK=${AWK:-"awk"}
SED=${SED:-"sed"}
HOST=${HOST:-"host"}
ID=${ID:-"id"}

#------------------------- FUNCTIONS -------------------------------#
function usage {
  echo "usage $(basename $0)
  [-h | --help]               ... this help
  [-S | --searchprocs]        ... processes to search for         [default all]
  [-D | --domains]            ... additional DNS domains to search[default none]
  [-p | --procs]              ... show processes in output        [default no]
  [-i | --interfaces]         ... show tcp listen ips of processes[default no]
  [-d | --debug]              ... enable debug output, implies -p [default no]
  [-t | --trace]              ... enable trace output, implies -d [default no]
  [-c | --csv]                ... enable CSV output               [default no]
  [-I | --inventory]          ... enable inventory output format  [default no]
  [-r | --remote] [user@]host ... enable remote execution via ssh [default no]
  [-f | --file] filename [-n] ... read [user@]remotehost from file.
                                  format: 1 line per host
                                  implies -r
  [-n | --numthreads]         ... number of threads               [default 1]
                                  only valid in combination with -f
  [-s | --sudo]               ... use sudo to gain root
                                  in remote execution mode        [default no]
  [-q | --quiet]              ... no unnecessary output           [default no]
                                  useful with in combination with -c and -f
  "
}

function exit_handler {
  # Called when the script is aborted, cleans up temp files

  echo "$(basename $0): User aborted, cleaning up"
  CPIDS=$(jobs -p)
  [ -n "$CPIDS" ] && kill $CPIDS
  rm -f $java_tmpfile $proc_filter_file
  exit 2
}

function get_env {
  # checks the OS we're running on and sets our toolset to appropriate values
  # The goal is the have the same functionality and behavior on all supported OSs

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
      [ $(command_exists /usr/sbin/nslookup) -eq 0 ] && NSLOOKUP="/usr/sbin/nslookup"
      [ $(command_exists /usr/proc/bin/pfiles) -eq 0 ] && PFILES="/usr/proc/bin/pfiles"
      [ $(command_exists /usr/xpg4/bin/id) -eq 0 ] && ID="/usr/xpg4/bin/id"

      EXTRA_LIB_PATH="/usr/sfw/lib"
      ;;
    Linux)
      OS="linux"
      [ -f /etc/redhat-release ] && pkgmanager="rpm -qa"
      [ -f /etc/debian_version ] && pkgmanager="dpkg -l"
      [ $(command_exists /usr/bin/awk) -eq 0 ] && AWK="/usr/bin/awk"
      [ $(command_exists /bin/sed) -eq 0 ] && SED="/bin/sed"
      [ $(command_exists /usr/bin/host) -eq 0 ] && HOST="/usr/bin/host"
      [ $(command_exists /usr/bin/nslookup) -eq 0 ] && NSLOOKUP="/usr/bin/nslookup"
      ;;
    AIX)
      OS="aix"
      [ $(command_exists /usr/bin/ps) -eq 0 ] && PS="/usr/bin/ps axww"
      [ $(command_exists lsof) -eq 0 ] && LSOF=$(command -v lsof)
      ;;
    *)
      OS="unknown"
      ;;
  esac   
  # try to resolve current hostname and username
  $HOST $(hostname) >/dev/null 2>&1 && HOSTNAME="$($HOST $(hostname) | $AWK '{ print $1 }')"
  [ -z "$HOSTNAME" ] && HOSTNAME="$($NSLOOKUP $(hostname) 2>/dev/null | $AWK '/Name:/ {print $2}')"
  ([ -z "$HOSTNAME" ] || [ "$HOSTNAME" = "Host" ]) && HOSTNAME="$(hostname)"
  USER=$($ID -un)
}

function command_exists {
  # used to test if a given command is available

  command -v $1 >/dev/null 2>&1
  typeset ret=$?
  echo $ret
  return $ret
}

function is_inarray {
  # internal function. Checks if input param $1 is in the "array" of input param $2
  # Since we have to support ksh, this does not use real arrays, but a crude wrapper

  ([ "$#" -lt 2 ] || [ -z "$1" ] || [ -z "$2" ]) && return 1
  if echo "$2" | $GREP -q "$1"; then
    return 0;
  else
    return 1
  fi
}

function sort_array {
  # internal function. Returns a sorted version of all input $*

  typeset e
  sorted=$(for e in $*; do echo "${e}${output_valueseparator}"; done | sort -u)
  echo $sorted
}

function check_return_code {
  # internal function.
  # Input:
  #        executed command       $1
  #        return code of command $2
  #        output of command      $3
  # Returns:
  #         0 on successful command
  #         1 on error

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
  # Outputs formatted message of input $@ to stderr

  [ $ERR_SHOW_HOST ] && typeset outprefix="${HOSTNAME}:"
  echo "${outprefix} $@" 1>&2;
}

function set_newest_java {
  # Internal function, keeps track of the highest Java version found on the system
  # by writing it to a temp file
  # Input:
  #        java_binary  $1
  #        java_version $2

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
  # Outputs the java binary of the highest version found on the system

  if [ -f $java_tmpfile ]; then
    typeset ver=$($AWK '{ print $1 }' $java_tmpfile)
    typeset cmd=$($AWK '{ print $2 }' $java_tmpfile)
    echo $cmd
  fi
  return 0
}

function set_procfilter {
  # Adds input param $1 to the list of process filters

  echo "$1" >> $proc_filter_file
}

function is_inprocfilter {
  # Checks if input param $1 is in the list of processes to be filtered/ignored
  # Returns:
  #          0 if input is in the list
  #          1 if input is not in the list

  [ -f $proc_filter_file ] || return 1
  $GREP -q "$1" $proc_filter_file && return 0
  return 1
}

function get_proc_env {
  # Checks if a process has a given ENV var set in its process environment
  # Input:
  #       process_id   $1
  #       env_variable $2
  #
  # Output:
  #         value of env_variable
  #
  # Returns:
  #          0   if env_variable is set
  #          >=1 if env_variable is not set

  typeset pid="$1"
  typeset var="$2"

  if [ "$OS" = "solaris" ]; then
    typeset pvar=$(pargs -e -a $pid 2>/dev/null | $GREP " ${var}=" | $SED "s/.*${var}=\(.*\)$/\1/"; exit ${PIPESTATUS[0]})
  elif [ "$OS" = "linux" ]; then
    typeset pvar=$(strings -a /proc/$pid/environ | $GREP "^${var}=" | $SED "s/.*${var}=\(.*\)$/\1/"; exit ${PIPESTATUS[0]})
  elif [ "$OS" = "aix" ]; then
    typeset pvar=$(ps eww $pid | tr ' ' "\n" | $GREP "${var}" | $SED "s/.*${var}=\(.*\)$/\1/")
  fi
  ret=$?
  [ $TRACE ] && echoerr "TRACE get_proc_env - pvar: $pvar ret: $ret"
  echo "${pvar}"
  return $ret
}

function get_runtime_user {
  # Resolves the effective username of a given process
  # Input:  process_id $1
  # Output: username

  typeset pid="$1"

  if [ "$OS" = "aix" ]; then
    typeset rtuser=$(/usr/bin/ps -p $pid -o user= | tr -d " ")
  else
    # try to get the user from the process environment first
    typeset rtuser=$(get_proc_env "$pid" "USERNAME")
    [ -z "${rtuser}" ] && rtuser=$(get_proc_env "$pid" "USER")
    # use ps as last resort
    [ -z "${rtuser}" ] && rtuser=$(${PS}u | $GREP "$pid" | $AWK -v pid=$pid '{ if ($2 == pid) print $1 }')
  fi
  echo ${rtuser} | tr -d "\n"
}

function get_proc_fullpath {
  # Resolves the absolute path of a given process
  # Input:
  #        process_id $1
  #        command    $2
  #
  # Output:
  #        absolute path of process binary
  #
  # Returns:
  #          0 if path was found
  #        >=1 on error

  typeset pid="$1"
  typeset command="$2"

  if [ "$OS" = "solaris" ]; then
    typeset pcmd=$(pargs -l $pid 2>/dev/null | $AWK '{ print $1 }'; exit ${PIPESTATUS[0]})
  elif [ "$OS" = "linux" ]; then
    typeset pcmd=$(get_real_path "/proc/$pid/exe")
  elif [ "$OS" = "aix" ]; then
    typeset pcmd=$(svmon -P $pid -c -j | grep "/${command}" | sed "s|[\t ]*\(/.*/${command}\)[\t ]*|\1|g")
  fi
  ret=$?
  [ $TRACE ] && echoerr "TRACE get_proc_fullpath - pcmd: $pcmd ret: $ret"

  if [ -f "${pcmd}" ] && [ $ret -eq 0 ]; then
    echo "${pcmd}"
    return 0
  fi
  return $ret
}

function get_real_path {
  # Resolves an input path $1 to its real absolute path on the file system
  # Useful if symlinks are undesirable
  #
  # Input: path
  # Output full absolute real path

  typeset path="$1"
  readlink "$path" >/dev/null 2>&1 && readlink -f "$path" && return 0
  command_exists perl >/dev/null 2>&1 && typeset rpath=$(perl -e 'use Cwd "abs_path"; print abs_path(${ARGV[0]})' $path)
  if [ -f $rpath ] || [ -d $rpath ]; then
    echo $rpath
  else
    echo $path
  fi
  return 0
}

function check_zone {
  # Checks if a given process is running inside the same Solaris Zone as this script
  #
  # Input:   process_id
  # Returns:
  #          0 if pid is in the same zone
  #          1 if pid is not in the same zone

  typeset pid="$1"
  ([ $OS = "solaris" ] && [ "$(uname -r | cut -c3,4)" -ge 10 ]) || return 0
  typeset curzone=$(/usr/bin/zonename 2>/dev/null)
  typeset pzone="$(/usr/bin/ps -efZ -o zone,pid 2>/dev/null | $GREP $pid | $GREP -v grep | $AWK '{ print $1 }' | sort -u)"
  if [ "$curzone" = "global" ] && [ "$curzone" != "$pzone" ]; then
    [ $DEBUG ] && echoerr "ERROR: pid $pid is in another zone: $pzone"
    return 1
  fi
  return 0
}

function get_csv_header {
  # Outputs the formated header for CSV output format

  typeset csv_header="hostname${output_fieldseparator}"OS"${output_fieldseparator}"
  for p in $searchprocs; do
    if [ $SHOW_IPS ]; then
      csv_header="${csv_header}${p}_version${output_fieldseparator}${p}_IPs${output_fieldseparator}"
    else
      csv_header="${csv_header}${p}_version${output_fieldseparator}"
    fi
  done
  echo "${csv_header}"
}

function get_cmdb_header {
  # Outputs the formated header for CMDB (CSV) output format

  echo "Hostname${output_fieldseparator}OS${output_fieldseparator}Component${output_fieldseparator}Version${output_fieldseparator}Binary Path${output_fieldseparator}Username${output_fieldseparator}Listen IPs"
}

function check_versions {
  # Checks the software version of a given process (see searchprocs)
  #
  # Input:
  #         process name $1
  #         params       $2 in the format process_id@command
  #
  # Output: 
  #         process_version_string
  #
  # Returns:
  #         0 on success
  #         1 on error

  typeset process=$1
  typeset input=$2

  # split params into PID and command name
  typeset pid=$(echo $input | $AWK -F"@" '{ print $1 }')
  typeset command=$(echo $input | $AWK -F"@" '{ print $2 }')

  # bail if command is in our filter
  if is_inprocfilter "$command" || ! check_zone "$pid"; then
     [ ${DEBUG} ] && echoerr "INFO skipping $command"
     return 1
  fi

  # make sure command exists and resolve it to its absolute real path
  if [ ! -f "$command" ]; then
    typeset pcmd="$(get_proc_fullpath "$pid" "$command")"
    [ $DEBUG ] && echoerr "DEBUG check_versions - $command full path: $pcmd"
    if [ -f "$pcmd" ] && ! is_inprocfilter "$pcmd"; then
      command=$pcmd
    else
      echoerr "DEBUG check_versions - $command does not exist"
      set_procfilter "$command"
      return 1
    fi
    unset pcmd
  fi

  # check for our software versions
  # this can be pretty hackish since we're dealing with dozens of different versions on multiple OSs,
  # and differing behavior
  case $process in
    apache|httpd) # Apache HTTPD
      # resolve the path to httpd binary, then call it with -v to get the version
      # improperly installed apaches need to have LD_LIBARAY_PATH set to find its libs...
      typeset ap_ld_path="$(dirname $command)/../lib:$(get_proc_env "$pid" "LD_LIBRARY_PATH")"
      [ -x $command ] && output=$(LD_LIBRARY_PATH=${ap_ld_path}:$LD_LIBRARY_PATH:${EXTRA_LIB_PATH} ${command} -v 2>&1 | cut -d " " -f 3 | $SED 's|Apache/||' ; exit ${PIPESTATUS[0]})
      check_return_code "$command" "$?" "$output"
      ;;

    java) # JAVA
      if [ -x $command ]; then
        typeset output=$(${command} -version 2>&1 | head -1 | cut -d " " -f 3- | tr -d \"; exit ${PIPESTATUS[0]})
        typeset ret=$?
        if ! check_return_code "$command" "$ret" "$output"; then return 1; fi
        echo "$output" | $GREP -Eq "[0-9\.]{3}" || return 1
        set_newest_java "$command" "$output"
      else
        set_procfilter "$command"
        [ $DEBUG ] && echoerr "DEBUG $command not executeable"
        return 1
      fi
      ;;

    tomcat) # Apache Tomcat
      # find JAVA_HOME and CATALINA_HOME of the running tomcat
      # try the process environment first
      typeset java_home=$(get_proc_env "$pid" "JAVA_HOME")
      typeset catalina_home=$(get_proc_env "$pid" "CATALINA_HOME")
      [ ! -d "$catalina_home" ] && catalina_home=$(get_proc_env "$pid" "TOMCAT_HOME")
      [ ! -d "$catalina_home" ] && catalina_home=$(get_proc_env "$pid" "\-Dcatalina.home")

      # that would have been too easy... lets try harder
      if [ ! -d "$catalina_home" ]; then
        [ $DEBUG ] && echoerr "DEBUG tomcat - catalina_home not found, trying jps and friends"
        java_home="$(dirname $command)/.."
        typeset jps="${java_home}/bin/jps"
        if [ ! -x "$jps" ]; then
          jps="$(dirname $(get_newest_java))/jps)"
          # parse output of jps command, you can often find the catalina.home define in there
          [ -x "$jps" ] && typeset catalina_home=$(${jps} -lv | $GREP $pid | $SED 's/^.*-Dcatalina.home=\(.*\) .*$/\1/g')
        fi
        [ $TRACE ] && echoerr "TRACE catalina_home1: ${catalina_home}"
        # still no dice? try to parse ps output, it sometimes shows the define
        [ ! -d "${catalina_home}" ] && typeset catalina_home=$($PS | $GREP $pid | $SED 's/^.*-Dcatalina.home=\(.*\) -.*/\1/g')
        [ $TRACE ] && echoerr "TRACE catalina_home2: ${catalina_home}"
        if [ ! -d "${catalina_home}" ]; then # still nothing...
          [ $DEBUG ] && echoerr "INFO failed to detect CATALINA_HOME - trying classpath..."
          # getting desperate, lets parse the whole java classpath
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
        if [ ! -d "${catalina_home}" ]; then # FAIL, giving up
          echoerr "ERROR failed to detect CATALINA_HOME of pid $pid command $command"
          [ $TRACE ] && echoerr "TRACE catalina_home_final: ${catalina_home}"
          return 1
        fi
      fi

      # at this point, we know where we should be able to find catalina.sh
      if [ -f "${catalina_home}/bin/catalina.sh" ]; then
        catalina_home=$(get_real_path ${catalina_home})
        typeset tomcat_command="CATALINA_HOME=${catalina_home} JAVA_HOME=${java_home} sh ${catalina_home}/bin/catalina.sh version"
      elif [ $(echo ${catalina_home} | $GREP -Eq "^/usr/share/"; echo $?) -eq 0 ]; then
        # In case this is a system package install, binaries are in different dirs from data files
        typeset tomcat_tmp=$(echo ${catalina_home} | $SED 's|^/usr/share/||g')
        [ $(command_exists $tomcat_tmp) -eq 0 ] && typeset tomcat_command="CATALINA_HOME=${catalina_home} JAVA_HOME=${java_home} sh ${tomcat_tmp} version"
        # special case for some system package
        [ $(command_exists /usr/bin/dtomcat5) -eq 0 ] && typeset tomcat_command="CATALINA_HOME=${catalina_home} JAVA_HOME=${java_home} sh /usr/bin/dtomcat5 version"
      fi

      # now we call our binary and parse its output. It can differ vastly between tomcat verions and OEM changes
      # the regexs might have room for improvement, but beware that a single small change can easily break some
      # obscure tomcat version detection.
      # You are adviced to _thouroughly_ test changes here.
      typeset output=$(eval ${tomcat_command} | $GREP -iE "version.*tomcat|^Server number" | $SED -e 's/.* \([0-9]\{1,2\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/' -e 's/[^0-9\.]//g' -e '/^$/d' | head -1 ; exit ${PIPESTATUS[0]})
      typeset ret=$?
      [ $TRACE ] && echoerr "TRACE tomcat_command: $tomcat_command OUT: $output Ret: $?"
      if ! check_return_code "$tomcat_command" "$ret" "$output" || [ -z "$output" ]; then
        # some error happened, tomcat version not yet detected
        if echo "$catalina_home" | $GREP -Eq "^/usr/apache"; then
          # seems we hit a system package on Solaris
          [ $DEBUG ] && echoerr "INFO: tomcat $catalina_home seems to be a system package, trying package manager"
          [ "$OS" = "solaris" ] && typeset output="pkg:$(pkginfo -l SUNWtcatr 2>/dev/null | awk '/VERSION:/ { print $2 }' | $SED 's/,.*//g'; exit ${PIPESTATUS[0]})"
        else
          # some tomcats don't output ANY version string, our only hope is that CATALINA_HOME path contains a version
          typeset tomcat_command="JAVA_HOME=${java_home} sh ${catalina_home}/bin/catalina.sh"
          typeset output=$(eval ${tomcat_command} 2>&1 | $GREP CATALINA_HOME | $SED 's/.*-\([0-9]\{1,2\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/'; exit ${PIPESTATUS[1]})
          typeset ret=$?
          [ -z "$output" ] && output="$(echo ${catalina_home} | $SED -e 's/.*\([0-9]\{1,2\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/' | $GREP -E "^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}"; exit ${PIPESTATUS[2]})*" && typeset ret=$?
        fi
      fi
      # finally make sure our output at least looks like a version string, otherwise blacklist this process
      if ! echo "$output" | $GREP -Eq "[0-9\.]{3}" || ! check_return_code "$tomcat_command" "$ret" "$output"; then set_procfilter "$command"; return 1; fi
      ;;

    jboss) # JBOSS
      # Get JAVA_HOME and JBOSS_HOME of the running process
      # try process environment first
      typeset java_home=$(get_proc_env "$pid" "JAVA_HOME")
      typeset jboss_home=$(get_proc_env "$pid" "JBOSS_HOME")

      # JBOSS_HOME not found, parse output of jinfo, you can often find the define in there
      if [ ! -d "$jboss_home" ]; then
        [ $DEBUG ] && echoerr "DEBUG tomcat - jboss_home not found, trying jps and friends"
        typeset java_home="$(dirname $command)/.."
        typeset jinfo="${java_home}/bin/jinfo"
        # if jinfo is not found in the current JVM, lets see if we have a newer JVM that has it
        [ -x ${jinfo} ] || jinfo="$(dirname $(get_newest_java))/jinfo"
        typeset jboss_home=$(${jinfo} $pid 2>&1 | $GREP jboss.home.dir | cut -d " " -f 3)
        if [ -z "${jboss_home}" ]; then
          # still no JBOSS_HOME, lets parse the Java class path as last resort
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
        if [ ! -d "${jboss_home}" ]; then # FAIL, giving up
          echoerr "ERROR failed to detect JBOSS_HOME of pid $pid command $command"
          [ $TRACE ] && echoerr "TRACE jboss_home: ${jboss_home}"
          return 1
        fi
      fi

      # Jboss6 has switched to standalone.sh instead of run.sh, so lets check this first
      if [ -f ${jboss_home}/bin/standalone.sh ]; then # Jboss >= 6
        jboss_command="sh ${jboss_home}/bin/standalone.sh -V JBOSS_HOME=${jboss_home} JAVA_HOME=${java_home} 2>/dev/null"
        typeset jb6=true
      elif [ -f ${jboss_home}/bin/run.sh ]; then # Jboss <= 5
        typeset jboss_command="sh ${jboss_home}/bin/run.sh -V JBOSS_HOME=${jboss_home} JAVA_HOME=${java_home}"
      fi
      if [ -n "${jboss_command}" ]; then
        # some Jboss versions/installs can hang indefinitely, which would cause this script to never finish
        # therefore, we'll use a wrapper function that will kill a hanging process after a few seconds
        if [ ${jb6} ]; then # Jboss >= 6
          typeset output="$(exec_with_timeout "${jboss_command}" | $GREP -E "^[jJ][bB]oss" | $SED 's/^[jJ][bB]oss.* \([0-9]\{1,2\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}.* \)[(].*$/\1/'; exit ${PIPESTATUS[2]})"
          typeset ret=$?
        else # Jboss <= 5
          typeset jb_out=$(exec_with_timeout "${jboss_command}")
          typeset output="$(echo $jb_out | tr ' ' "\n" | $SED -n '/^\([0-9]\{1,2\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/p'; exit ${PIPESTATUS[2]})"
          typeset ret=$?
        fi
        if [ -z "${output}" ]; then
          output="$(echo $jb_out | $GREP JBOSS_HOME | $SED 's/.*\([0-9]\{1,2\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/'; exit ${PIPESTATUS[2]})"
          typeset ret=$?
        fi
        [ $TRACE ] && echoerr "TRACE JBOSS_VERSION ${output}"
        if ! check_return_code "$jboss_command" "$ret" "$output"; then set_procfilter "$command";  return 1; fi
      else
        # we didn't find standalone.sh or run.sh yet
        # maybe JBOSS_HOME is a symlink or was overridden via env var
        typeset jb_tmp=$(get_real_path ${jboss_home})
        jboss_home="$(echo $jb_tmp | $SED 's|^\(.*[jJ][bB]oss-[0-9].[0-9].[0-9][\.A-Z]*/\).*$|\1|g')"
        jboss_command="sh ${jboss_home}/bin/run.sh -V"
        if [ -f $jboss_home/bin/run.sh ]; then
          typeset jb_out=$(exec_with_timeout "${jboss_command}")
          typeset output="$(echo $jb_out | tr ' ' "\n" | $SED -n '/^\([0-9]\{1,2\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/p')"
        else
          echoerr "ERROR failed to detect JBOSS_HOME of pid $pid command $command"; return 1
        fi
      fi
      ;;

    websphere) # IBM Websphere
      # find versionInfo.sh
      typeset ws_home=$(echo $command | $SED 's|\(.*AppServer\).*$|\1/bin|')
      [ -f ${ws_home}/versionInfo.sh ] || typeset ws_home="$(get_proc_env "$pid" "was.install.root")/bin"
      [ -f ${ws_home}/versionInfo.sh ] || return 1
      typeset output=$(${ws_home}/versionInfo.sh 2>&1 | $GREP -v Directory | $AWK '/^Version/ { if (length($2)>=4) print $2 }')
      ret=$?
      [ $TRACE ] && echoerr "websphere version: ${output}"
      if ! check_return_code "${ws_home}/versionInfo.sh" "$ret" "$output"; then set_procfilter "$command"; return 1; fi
      ;;

    C:D) # Connect Direct
      # we're assuming C:D is always running under cduser
      if [ $($GREP -q cduser /etc/passwd; echo $?) -eq 0 ]; then
        typeset output=$(su - cduser -c 'direct << "EOF quit; EOF" 2>/dev/null' | $GREP -E "Version|Connect:Direct" | $SED 's/.* \([0-9\.]\)/\1/' | cut -d " " -f1 | $GREP -E "[0-9\.]{3}")
        if [ -z "$output" ]; then
          # on some installs the above fails, lets try differently
          typeset directcmd=$(su - cduser -c ". .profile ; /usr/bin/command -v direct")
          typeset output=$(su - cduser -c "echo 'quit;' | ${directcmd} 2>/dev/null" | $GREP -E "Version|Connect:Direct" | $SED 's/.* \([0-9\.]\)/\1/' | cut -d " " -f1 | $GREP -E "[0-9\.]{3}")
        fi
        if ! check_return_code "$command" "$?" "$output"; then return 1; fi
      else
        echoerr "ERROR - C:D procs running, but cduser not found"
      fi
      ;;

    MQ) # IBM MQ
      # find dspmqver or mqver
      typeset mq_home="$(dirname $command)"
      if [ -f ${mq_home}/dspmqver ]; then
        typeset output=$(${mq_home}/dspmqver | $AWK '/Version:/ { print $2 }')
      elif [ -f ${mq_home}/mqver ]; then
        typeset output=$(${mq_home}/mqver | $AWK '/Version:/ { print $2 }')
      else
        # todo: check pkg manager
        echoerr "ERROR: MQ detected, but neither dspmqver nor mqver exist in ${mq_home}"
        return 1
      fi
      ;;

    python)
      $command -V 2>/dev/null || return 1
      typeset output=$($command -V 2>&1 | $AWK '{ print $2 }')
      if ! check_return_code "$command" "$?" "$output"; then set_procfilter "$command"; return 1; fi
      ;;

    perl)
      typeset output=$($command -v | $GREP "This is perl" | $SED 's/.*v\([0-9]\{1,2\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/')
      if ! check_return_code "$command" "$?" "$output"; then set_procfilter "$command"; return 1; fi
      ;;

    php)
      typeset output=$($command -v | head -n 1 | $SED 's/^PHP \([0-9]\{1,2\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*/\1/')
      if ! check_return_code "$command" "$?" "$output"; then set_procfilter "$command"; return 1; fi
      ;;

    mysql)
      # find mysqladmin in the same path as mysqld
      typeset mysql_admin="$(dirname $command)/mysqladmin"
      [ $TRACE ] && echoerr "TRACE mysql_admin: ${mysql_admin}"
      if [ ! -x $mysql_admin ]; then
        [ $TRACE ] && echoerr "TRACE mysql_admin: ${mysql_admin} not executeable or does not exist"
        # lets check PATH
        command_exists mysqladmin >/dev/null 2>&1 && typeset mysql_admin="mysqladmin"
      fi
      [ $TRACE ] && echoerr "TRACE mysql_admin: ${mysql_admin}"
      typeset output="$($mysql_admin -V | $SED -e 's/Distrib//' -e 's/.*\([0-9]\{1,3\}\.[0-9]\{1,3\} .*\), .*/\1/g' -e 's/[ ]\{1,3\}/_/'; exit ${PIPESTATUS[0]})"
      if ! check_return_code "$command" "$?" "$output"; then output="failed to detect version"; fi
      ;;

    *)
      # command passed is not in our list, should not happend
      echo "NA"
      ;;

  esac
  # output our version string
  if [ $? -eq 0 ] && [ -n "${output}" ] && [ "${output}" != "not found" ]; then
    echo "${output}"
  fi
  unset output
  return 0
}

function search_processes {
  # searches for all running processes in $searchprocs, gets the version and tcp info,
  # then outputs formated results to stdout
  # This function does the heavy lifting of piecing everything together

  typeset f='grep|/bash'  # filter
  typeset duplicates_proc # stores duplicate processes
  typeset duplicates_net  # stores duplicate listen IPs/ports
  typeset csv_out         # temp var for CSV output mode
  typeset r
  typeset t
  typeset p
  typeset e

  [ $BE_QUIET ] || echo '#---- checking versions --------------#'
  [ ${SHOW_PROCS} ] && echo '#---- checking running processes ----#'
  for p in $searchprocs ; do
    # first add additional stuff to filter for certain processes
    # needed to get rid of false positives when grepping ps output or to reduce duplicates
    [ "$p" == "apache" ] && ef='|org.apache|java|rotatelogs'
    [ "$p" == "java" ] && ef='|tnameserv'
    [ "$p" == "tomcat" ] && ef='|astro'
    [ "$p" == "jboss" ] && ef='|jbossall-client|astro'
    [ "$p" == "websphere" ] && ef='|InformationServer'
    [ "$p" == "C:D" ] && e='|cdpmgr|cdstatm'
    [ "$p" == "MQ" ] && e='xxxx|runmqlsr|amq[cfhlprxz]|amqr|runmq'
    [ "$p" == "python" ] && ef="|java"
    [ "$p" == "perl" ] && ef="|perldtn"
    [ "$p" == "mysql" ] && e="d" && ef="_safe"

    # grep ps output for our processes and format it as $PID@command
    typeset t=$($PS | $GREP -iE "${p}${e}" | $GREP -vE "${f}${ef}" | $AWK '{ print $1"@"$5 }')
    [ ${SHOW_PROCS} ] && echo "PROCESSES ${p}: $t"
    # special C:D handling
    [ "$p" == "C:D" ] && echo ${t} | $GREP -q cdpmgr && t="$(echo ${t} | tr ' ' '\n' | grep cdpmgr)"
    unset ef e

    # walk over our list of $PID@command
    for r in ${t} ; do
      typeset pid=$(echo $r | $AWK -F"@" '{ print $1 }') # PID
      typeset c=$(echo $r | $AWK -F"@" '{ print $2 }') # command
      [ $TRACE ] && echoerr "pid: $pid c=$c"

      # if our command is apache or java there can be multiple processes/threads belonging to the same instance,
      # so filter out duplicates
      if (([ "$p" = "apache" ] || [ "$p" = "httpd" ] || [ "$p" = "java" ]) && is_inarray "${c}" "${duplicates_proc}") && [ "${CMDB}" != "true" ]; then : ; else
        # add process to our "already seen" list
        duplicates_proc="${duplicates_proc} ${c}"
        [ ${DEBUG} ] && echoerr "PROCCHECK: $p $r"

        # get the version string
        t="$(check_versions $p $r)"

        # only add the version to output, if it's not a duplicate
        # this is for normal output mode
        if ! is_inarray "$t" "${output}"; then
          typeset output=""${output}" "${t}""
        fi
        # in CMDB mode every instance of each process is reported
        [ ${CMDB} ] && [ -n "${t}" ] && typeset cmdbout="${HOSTNAME}${output_fieldseparator}${OS}${output_fieldseparator}${p}${output_fieldseparator}${t}${output_fieldseparator}${c}${output_fieldseparator}"
      fi

      # get and output listen IPs if requested
      # duplicates are skipped
      if [ $SHOW_IPS ] && [ "$p" != "java" ] && ! is_inarray "${pid}" "${duplicates_net}"; then
        duplicates_net=""${duplicates_net}" "${pid}""
        [ ${DEBUG} ] && echoerr "NETCHECK: $p $pid"

        # get listen IPs
        typeset n="$(get_proc_tcpports $pid)"
        if ! is_inarray "$n" "${net}"; then
          typeset net=""${net}" "${n}""
          # in CMDB mode, results are output for each process again
          [ ${CMDB} ] && [ -n "${t}" ] && [ -n "${n}" ] && ! $(is_inprocfilter "$c") && echo "${cmdbout}$(get_runtime_user "$pid")${output_fieldseparator}${n}${output_fieldseparator}"
        fi
      fi
      unset pid c cmdbout
    done
    unset r t n

    # piece the output string together
    if [ "${CMDB}" != "true" ]; then
      [ $SHOW_IPS ] && typeset ips_out="${output_fieldseparator}$(sort_array "${net}")"
      if [ $CSV_OUTPUT ]; then
        # CSV mode
        typeset csv="$(sort_array "${output}")"${ips_out}""
        typeset csv_out="${csv_out}${output_fieldseparator}${csv}"
      else
        # standard mode
        echo "${p}${output_fieldseparator}$(sort_array "${output}")"${ips_out}"" | $SED 's/[()]//g'
      fi
    fi
    unset output net subres r t p
  done

  # Finally output results for normal mode
  if [ "${CMDB}" != "true" ]; then
    [ $CSV_OUTPUT ] && [ ! $BE_QUIET ] && echo "$(get_csv_header)"
    [ $CSV_OUTPUT ] && echo "${HOSTNAME}${output_fieldseparator}${OS}${csv_out}" | $SED 's/[()]//g'
    [ $BE_QUIET ] || echo '#------------------------------------#'
  fi
  unset p
}

function get_proc_tcpports {
  # Checks the listen IP/port of a process
  #
  # Input:  process_id
  # Output: list of IP/port combinations

  typeset pid="$1"
  typeset ret
  typeset ips

  case "$OS" in
  solaris)
    # only check if the process is running in the current zone
    check_zone "$pid" || return 1
    ips=$($PFILES $pid 2>/dev/null | $AWK '/sockname: AF_INET/ {x=$3;y=$5; getline; if($0 !~ /peername/ )  print x":"y }' | sort -u | $SED 's/0.0.0.0:0//g' | tr '\n' ' '; exit ${PIPESTATUS[0]})
    ret=$?
    echo "$ips" | $GREP -Eq "([0-9]{1,3}\.){3}[0-9]{1,3}|:::[0-9]{2,5}" || ret=1
    ;;
  linux)
    ips=$(netstat -anltp 2>/dev/null | $AWK "/LISTEN.*$pid/ {print \$4}" | tr '\n' ' '; exit ${PIPESTATUS[0]})
    ret=$?
    ;;
  aix)
    # AIX needs lsof installed
    [ -z "$LSOF" ] && ips="N/A" && return 1
    ips=$($LSOF -iTCP -a -n -P -p $pid | grep LISTEN | $AWK '{print $9}' | sort -u | tr '\n' ' ')
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
    [ $DEBUG ] && echoerr "ERROR get_proc_tcpports - checking listen IPs for pid: $pid return code: $?"
  fi
  unset pid ret ips
}

function search_packages {
  # Check for installed system packages

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

function exec_with_timeout {
  # Internal helper function that executes a given command and kills it after a timeout of 10 sec
  # if it didn't finish earlier
  #
  # Input: command to execute with optional arguments
  # Output: command output

  typeset timeout="10"
  typeset command="$1" # first input is treated as command, all following as args
  shift

  # read passed in command arguments
  for arg in "$@"; do
   typeset args="$args '$arg'"
  done
  [ $TRACE ] && echoerr "exec_with_timeout: command: $command" 

  # run in a subshell and get the PID
  ( $command $args 2>/dev/null) & pid=$!
  (
    t=0
    # loop for $timeout secs
    while [ $t -lt $timeout ]; do
      sleep 1
      # check if process did already terminate on its own
      kill -0 $pid || exit 0
      # increment timer
      let t=$t+1
    done

    # timeout happened
    # be nice and try a normal kill first
    kill $pid && kill -0 $pid || exit 0
    sleep 2
    # still running, get out the hammer
    kill -9 $pid
  ) >/dev/null 2>&1
}



function ssh_exec {
  # execute ourself remotely over ssh, without copying the script
  #
  # Input:  hostname to run on
  # Output: remote script output on stdout/err

  typeset rhost="$1"
  typeset remoteuser
  typeset remotehost
  typeset SUDO

  # check if the passed hostname contains a username part
  if [ $(echo $rhost | $GREP -q "@"; echo $?) -ne 0 ]; then
    remoteuser="root@" # default is to run as root
  else
    # split username and hostname
    remoteuser="$(echo ${rhost} | ${AWK} -F"@" '{print $1}')@"
    rhost=$(echo ${rhost} | ${AWK} -F"@" '{print $2}')

    # running as non-root, but --sudo option not given
    [ "$remoteuser" != "@" ] && [ "$remoteuser" != "root@" ] && [ ! $USE_SUDO ] && echoerr "WARN: using a non-root user, but sudo option not given. This can cause incomplete results!"
  fi

  # resolve hostname
  remotehost=$(get_fqdn $rhost)
  [ "${remotehost}" != "NOT_FOUND" ] && rhost=$remotehost || echoerr "ERROR: could not resolve ${rhost}"
  [ $DEBUG ] && echoerr "checking remote shell for ${remoteuser}${rhost}"

  # check if we need to use sudo
  [ $USE_SUDO ] && [ "$(echo "${remoteuser}${rhost}" | ${AWK} -F"@" '{print $1}')" != "root" ] && SUDO="sudo"

  # check which shell is available on the host: bash or ksh needed
  typeset rshell=$(ssh ${ssh_opts} ${remoteuser}${rhost} -C "command -v bash")
  [ -z "$rshell" ] && typeset rshell=$(ssh ${ssh_opts} ${remoteuser}${rhost} -C "command -v ksh")
  if [ -z "$rshell" ]; then
    # no useable shell found
    echoerr "ERROR could not determine remote shell for host $rhost, skipping"
    return 1
  else
    [ $DEBUG ] && echoerr "remote shell: $rshell"
    # pipe ourself through ssh, passing needed options
    {
      printf '%s\n' "set -- $REMOTE_OPTS"
      cat "$MYSELF"
    } | ssh ${ssh_opts} ${remoteuser}${rhost} "$SUDO $rshell -s"
  fi
}

function read_remotefile {
  # Job control helper function
  # implements shell compatible poor man's "multi threading"
  # very useful for parallel processing big lists of hostnames

  typeset remotehost
  typeset curjobs

  if [ $BE_QUIET ]; then
    echo "$(get_csv_header)"
  fi

  # traverse our hostname file, ignoring comments and empty lines
  for remotehost in $(cat $RHFILE | $SED '/^#/d'); do
    [ -z "$remotehost" ] && continue
    [ $DEBUG ] && echoerr "DEBUG read_remotefile: checking host $remotehost"

    # check how much jobs are running
    curjobs=$(jobs | wc -l)
    while [ $MAX_THREADS -ne 1 ] && [ $curjobs -ge $MAX_THREADS ]; do
      # max num of jobs running, lets wait for some to finish
      [ $TRACE ] && echoerr "TRACE read_remotefile: job num $curjobs >= max $MAX_THREADS"
      sleep 5
      curjobs=$(jobs | wc -l)
    done

    # now we have room to start a new job
    if [ $MAX_THREADS -eq 1 ]; then
      ssh_exec "${remotehost}"
    else
      ssh_exec "${remotehost}" &
      typeset waitpids="$waitpids ${!}"
    fi
  done

  # wait for all jobs to finish
  wait $waitpids
  exit 0
}

function get_fqdn {
  # resolve the FQDN of a given hostname or IP
  #
  # Input:  hostname or IP
  # Output:
  #         FQDN if found
  #         NOT_FOUND on error
  # Returns:
  #         0 on success
  #         1 on error

  typeset rhost=$1
  typeset domain

  nslookup ${rhost}  >/dev/null 2>&1 && echo ${rhost} && return 0
  for domain in $dnsdomains; do
    [ $TRACE ] && echoerr "TRACE get_fqdn: resolving ${rhost}.${domain}"
    nslookup ${rhost}.${domain} >/dev/null 2>&1 && echo ${rhost}.${domain} && return 0
  done
  echo "NOT_FOUND"
  return 1
}

###
# Main
###
MYSELF=$0
MYPID=$$
MAX_THREADS=1

# parse command options
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
    -i | --interfaces)
      SHOW_IPS=true
      REMOTE_OPTS="$REMOTE_OPTS -i"
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
    -H | --showhost)
      ERR_SHOW_HOST=true
      shift
      ;;
    -c | --csv)
      CSV_OUTPUT=true
      REMOTE_OPTS="$REMOTE_OPTS -c"
      shift
      ;;
    -r | --remote)
      RHOST=$2
      [ -z $RHOST ] && echoerr "Input ERROR: no hostname given" && exit 2
      REMOTE_EXEC=true
      shift 2
      ;;
    -f | --file)
      RHFILE=$2
      [ -z "$RHFILE" ] && echoerr "Input ERROR: no filename given" && exit 2
      [ ! -r $RHFILE ] && echoerr "Input ERROR: file $RHFILE not found" && exit 2
      READ_RHFILE=true
      REMOTE_EXEC=true
      REMOTE_OPTS="$REMOTE_OPTS -H"
      shift 2
      ;;
    -n | --numthreads)
      MAX_THREADS=$2
      case $MAX_THREADS in
        ''|*[!0-9]*)
          echoerr "Input ERROR: $MAX_THREADS is not an integer"
          exit 2 ;;
      esac
      shift 2
      ;;
    -s | --sudo)
      USE_SUDO=true
      shift
      ;;
    -S | --searchprocs)
      searchprocs=$2
      shift 2
      [ -z "$searchprocs" ] && echoerr "ERROR: option -S needs an argument" && exit 2
      REMOTE_OPTS="$REMOTE_OPTS -S "$searchprocs""
      ;;
    -D | --domains)
      dnsdomains=$2
      [ -z "$dnsdomains" ] && echoerr "ERROR: option -D needs an argument" && exit 2
      shift 2
      ;;
    -I | --inventory)
      CMDB=true
      REMOTE_OPTS="$REMOTE_OPTS -I -i -q"
      shift
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

# trap some signals, so we can clean up
trap exit_handler 1 2 6 15

if [ $REMOTE_EXEC ]; then
  # Remote execution mode
  [ ${CMDB} ] && echo "$(get_cmdb_header)"
  # check if we have an input file
  if [ $READ_RHFILE ]; then
    read_remotefile
  else
    ssh_exec "$RHOST"
  fi
else
  # local execution mode
  get_env
  echo "$procfilter" | tr ' ' '\n' > $proc_filter_file
  [ $BE_QUIET ] || echo '#--------------------------------------#'
  [ $BE_QUIET ] || echo "# OS: $OS - hostname: $HOSTNAME - id: $USER #"

  search_processes
  #search_packages
  #search_filesystem

  # cleanup
  rm -f $java_tmpfile $proc_filter_file
fi
