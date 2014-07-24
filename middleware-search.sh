searchprocs="apache httpd java tomcat jboss"
searchpkgs="apache apache2 java tomcat jboss"
searchdirs="/opt /etc /export"
fskeywords="[aA]pache java [tT]omcat [jJ][bB]oss"

PS=${PS:-"ps"}
GREP=${GREP:-"grep"}
#--------------#

function get_env {
  local os=$(uname)
  HOST="$(host $(hostname))"
  case $os in 
    SunOS)
      OS="solaris"
      pkgmanager="pkginfo"
      [ $(command_exists /usr/bin/ps) -eq 0 ] && PS=/usr/bin/ps
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

function check_return_code {
  local command=$1
  local ret=$2
  if [ $ret -ne 0 ]; then
    echo -n "ERROR executing $command "
  fi
}

function check_versions {
  local process=$1
  local command=$2
  local output=""

  echo -n "${process}: "
  case $process in
    httpd)
      local ap_ld_path=$(dirname $command)/../lib
      [ -x $command ] && output=$(LD_LIBRARY_PATH=${ap_ld_path}:$LD_LIBRARY_PATH $command -v 2>&1 | cut -d " " -f 3)
      check_return_code $command $?
      echo $output
      ;;
    tomcat)
      [ $(echo $command | $GREP -q catalina ; echo $?) -eq 0 ] && output=$($command version 2>&1)
      check_return_code $command $?
      echo $output
      ;;
    java)
      [ -x $command ] && output=$($command -version 2>&1 | head -1 | cut -d " " -f 3-)
      check_return_code $command $?
      echo $output
      ;;
    jboss)
      [ $(echo $command | $GREP -q run ; echo $?) -eq 0 ] && output=$($command -V 2>&1) || echo "run.sh not found, process is $command"
      check_return_code $command $?
      ;;
    *)
      echo "NA"
      ;;
  esac
}

function search_processes {
  echo '#---- checking running processes ----#'
  for p in $searchprocs ; do
    echo -n "${p}: "
    t=$($PS -e -o comm | $GREP $p | $GREP -v grep | sort -u)
    echo $t
    declare result_$p="$t"
  done

  #echo '#------------------------------------#'

  echo '#---- checking versions --------------#'
  for p in $searchprocs ; do
    v=result_$p
    res=${!v}
    if [ ${#res} -gt 0 ]; then
      if [ $(echo $res | $GREP -qE " "; echo $?) -eq 0 ]; then
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
search_packages
search_filesystem
