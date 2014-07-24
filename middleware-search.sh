#--- CONFIG ---#
searchprocs="apache httpd java tomcat jboss"
searchpkgs="apache apache2 java tomcat jboss"
searchdirs="/opt /etc /export"
fskeywords="apache Apache java tomcat Tomcat jboss jBoss Jboss"
#--------------#

function get_os {
  local os=$(uname)
  HOST="$(host $(hostname))"
  case $os in 
    SunOS)
      OS="solaris"
      pkgmanager="pkginfo"
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

function check_return_code {
  local command=$1
  local ret=$2
  if [ $ret -ne 0 ]; then
    echo -n "ERROR executing $command "
  else
    echo -n "OK "
  fi
}

function check_versions {
  local process=$1
  local command=$2
  local output=""

  echo -n "${process}: "
  case $process in
    httpd)
      [ -x $command ] && output=$($command -v 2>&1)
      check_return_code $command $?
      echo $output
      ;;
    tomcat)
      [ $(echo $command | grep -q catalina ; echo $?) -eq 0 ] && output=$($command version 2>&1)
      check_return_code $command $?
      echo $output
      ;;
    java)
      [ -x $r ] && output=$($command -version 2>&1 | head -1 | cut -d " " -f 3-)
      check_return_code $command $?
      echo $output
      ;;
    jboss)
      [ $(echo $command | grep -q run ; echo $?) -eq 0 ] && output=$($command -V 2>&1) || echo "run.sh not found, process is $command"
      check_return_code $command $?
      ;;
    *) ;;
  esac
}

function search_processes {
  echo '#---- checking running processes ----#'
  for p in $searchprocs ; do
    echo -n "${p}: "
    t=$(ps -ax | grep $p | grep -v grep | awk '{print $5}' | sort -u)
    echo $t
    declare result_$p="$t"
  done

  #echo '#------------------------------------#'

  echo '#---- checking versions --------------#'
  for p in $searchprocs ; do
    v=result_$p
    res=${!v}
    if [ ${#res} -gt 0 ]; then
      if [ $(echo $res | grep -qE " "; echo $?) -eq 0 ]; then
        read -a subres <<<$res
      else
        subres=$res
      fi

      for r in ${subres[@]} ; do
        check_versions $p $r
      done
    fi
    unset subres r
  done
  echo '#------------------------------------#'
}

function search_packages {
  local res
  local pkg
  
  echo '#---- checking packages ---------------#'
  if [ -z $pkgmanager ]; then
   echo "ERROR: unknown package manager, skipping package checks"
   return
  fi

  for pkg in $searchpkgs ; do
    echo -n "${pkg}: "
    res=$($pkgmanager | grep $pkg) 
    echo $res
  done
}

function search_filesystem {
  local name
  local res
  local num=1
  local findstring="find $searchdirs -type d -name "

  for name in $fskeywords ; do
    [ $num -eq 1 ] && findstring="${findstring} '*${name}*' "
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
get_os
echo '#--------------------------------------#'
echo "# OS: $OS - hostname: $HOST #"
search_processes
search_packages
search_filesystem

