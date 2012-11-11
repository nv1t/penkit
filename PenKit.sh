#!/bin/bash
######################################################################################
# PenKit.sh
#*************************************************************************************
#
# [Description]: Script to automate the pulling, installing, and updating of
#                penetration testing source code and tools. This script is meant to
#                assist security professionals in quickly building pentest systems
#                and to allow for the use of development, version controlled software
#                to utilize bleeding edge features.
#
# [Supported Software]: Currently, PenKit supports the following tools, however,
#                       anyone with basic scripting knowledge can modify to include
#                       any tool that suits their needs.
#
#                       {Version Controlled Sources}:
#                                                     AirCrack-NG
#                                                     Arachni
#                                                     Kismet
#                                                     Nmap
#                                                     Reaver
#                                                     ZAP
#
#                       {Version Controlled Tools}..:
#                                                     Artillery
#                                                     BeEF
#                                                     DNSEnum
#                                                     DNSRecon
#                                                     Metasploit2
#                                                     Metasploit3
#                                                     PushPin
#                                                     SET
#                                                     SQLMap
#                                                     SQLNinja
#                                                     SSLyze
#                                                     W3af
#                                                     WPScan
#
#                       {Manually Updated Sources}..:
#                                                     Crunch
#                                                     Hydra
#
#                       {Manually Updated Tools}....:
#                                                     Burp
#                                                     Fierce
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

######################################################################################
# Configuration Variables (Modify As Needed)
#*************************************************************************************
#=====================================================================================
# Directory Variables
#-------------------------------------------------------------------------------------
src_dir=/PATH/TO/SOURCES/DIRECTORY
tls_dir=/PATH/TO/TOOLS/DIRECTORY
#=====================================================================================
# Version Controlled Sources
#-------------------------------------------------------------------------------------
src_nms='AirCrack-NG Arachni Kismet Nmap Reaver ZAP'
#=====================================================================================
# Manually Updated Sources
#-------------------------------------------------------------------------------------
man_src='Crunch Hydra'
#=====================================================================================
# Version Controlled Tools
#-------------------------------------------------------------------------------------
tls_nms='Artillery BeEF DNSEnum DNSRecon Metasploit2 Metasploit4 PushPin SET SQLMap
SQLNinja SSLyze W3af WPScan'
#=====================================================================================
# Manually Updated Tools
#-------------------------------------------------------------------------------------
man_tls='Burp Fierce'
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

######################################################################################
# Global Variables (Do Not Modify Below Here)
#*************************************************************************************
#=====================================================================================
# Screen Settings (Comment to Debug)
#-------------------------------------------------------------------------------------
scr_com='screen -d -m -S PenKit'
#=====================================================================================
# Script Requirements
#-------------------------------------------------------------------------------------
req_utl='unzip git svn screen wget'
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

######################################################################################
# Title Function
#*************************************************************************************
func_title(){
  clear
  echo '=========================================================================='
  echo ' PenKit.sh | [Version]: 0.6.0 | [Updated]: 11.11.2012'
  echo '=========================================================================='
  echo ' [By]: Michael Wright (@TheMightyShiv) | https://github.com/TheMightyShiv'
  echo '=========================================================================='
  echo
}
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

######################################################################################
# Job Monitor Function
#*************************************************************************************
func_jobmon(){
  if [ "$scr_com" == '' ]
  then
    echo ' |'
  else
    echo -n ' |-[*] Waiting On Jobs To Finish'
    jobs=`ps x|grep -i "$scr_com"|awk '!/grep -i/'|wc -l`
    while [ "$jobs" -gt '0' ]
    do
      echo -n '.'
      jobs=`ps x|grep -i "$scr_com"|awk '!/grep -i/'|wc -l`
      sleep 10
    done
    echo
    echo ' |'
  fi
}
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#=====================================================================================
# Finished Function
#-------------------------------------------------------------------------------------
func_fin(){
  echo '[*] Finished.'
  echo
}
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

######################################################################################
# Install All Dependencies Function
#*************************************************************************************
func_dependencies(){
  #===================================================================================
  # Get OS Information
  #-----------------------------------------------------------------------------------
  echo '[ Supported Operating Systems ]'
  echo
  echo ' [1] Debian 7+'
  echo ' [2] Ubuntu 12.'
  echo
  read -p '[>] Enter Your OS Version (1-2): ' os
  #===================================================================================
  # Validate Selection & Privileges
  #-----------------------------------------------------------------------------------
  if [[ "${os}" != [1-2] ]]
  then
    func_title
    func_dependencies
  fi
  if [ `whoami` != 'root' ]
  then
    func_title
    echo '[Error]: You must run this option with root privileges.'
    echo
    exit 1
  fi
  #===================================================================================
  # Install All Dependencies
  #-----------------------------------------------------------------------------------
  case ${os} in
    1|2)
      apt-get install libssl-dev libsqlite3-dev build-essential autoconf automake \
      make bison flex subversion git mercurial ruby1.9.3 python-dev rake \
      libcurl4-openssl-dev libxml2-dev libxslt1-dev libpcre3-dev libsvn-dev \
      libfbclient2 firebird-dev libafpclient0 libncp-dev libssh-dev libncurses5-dev \
      libpcap-dev libcap-dev zip unzip rar unrar p7zip-full libeventmachine-ruby \
      libnl-dev libnet-ip-perl libnet-dns-perl libnet-netmask-perl libxml-writer-perl \
      libterm-readline-gnu-perl libio-socket-ssl-perl libnetpacket-perl python-nltk \
      python-soappy python-lxml python-svn python-scapy python2.7-dev python-pip \
      graphviz python-gtk2 python-gtksourceview2 libcanberra-gtk-module

      easy_install pybloomfiltermmap

      gem install bundler rspec pg
      ;;
    *)
      func_title
      echo '[Error]: Something terrible happened...'
  esac
}
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

######################################################################################
# Install Function
#*************************************************************************************
func_install(){
  #===================================================================================
  # Prepare Source Directory
  #-----------------------------------------------------------------------------------
  echo '[*] Preparing Sources Directory'
  mkdir -p ${src_dir}
  echo ' |-[*] Changing Directory'
  cd ${src_dir}
  echo ' |'
  #===================================================================================
  # Begin Version Controlled Sources Pull
  #-----------------------------------------------------------------------------------
  echo '[*] Beginning Sources Pull'
  for source in $src_nms
  do
    if [ -d $source ]
    then
      echo " |-[!] $source Installed. Skipping..."
    else
      case $source in
        [aA][iI][rR][cC][rR][aA][cC][kK]-[nN][gG])
          echo ' |-[+] AirCrack-NG Started (SVN)'
          $scr_com svn co http://trac.aircrack-ng.org/svn/trunk $source
          ;;
        [aA][rR][aA][cC][hH][nN][iI])
          echo ' |-[+] Arachni Started (Git)'
          $scr_com git clone git://github.com/Arachni/arachni.git $source
          ;;
        [kK][iI][sS][mM][eE][tT])
          echo ' |-[+] Kismet Started (Git)'
          $scr_com git clone https://www.kismetwireless.net/kismet.git $source
          ;;
        [nN][mM][aA][pP])
          echo ' |-[+] Nmap Started (SVN)'
          $scr_com svn co https://svn.nmap.org/nmap $source
          ;;
        [rR][eE][aA][vV][eE][rR])
          echo ' |-[+] Reaver Started (SVN)'
          $scr_com svn co http://reaver-wps.googlecode.com/svn/trunk $source
          ;;
        [zZ][aA][pP])
          echo ' |-[+] ZAP Started (SVN)'
          $scr_com svn co http://zaproxy.googlecode.com/svn/trunk $source
          ;;
        *)
          echo " |-[!] $source Unsupported. Skipping..."
          ;;
      esac
    fi
  done
  func_jobmon
  #===================================================================================
  # Begin Manually Updated Sources Pull
  #-----------------------------------------------------------------------------------
  echo '[*] Beginning Manual Source Pulls'
  for source in ${man_src}
  do
    if [ -d ${source}-* ]
    then
      echo " |-[!] $source Installed. Skipping..."
    else
      case $source in
        [cC][rR][uU][nN][cC][hH])
          echo ' |-[+] Downloading Crunch 3.2 Source'
          wget -q http://downloads.sourceforge.net/project/crunch-wordlist/crunch-wordlist/crunch-3.2.tgz
          echo ' |  |-[*] Decompressing Tarball'
          tar -zxf crunch-3.2.tgz
          echo ' |  |-[*] Renaming Directory'
          mv crunch3.2 Crunch-3.2
          echo ' |  |-[-] Removing Tarball'
          rm crunch-3.2.tgz
          ;;
        [hH][yY][dD][rR][aA])
          echo ' |-[+] Downloading Hydra 7.3 Source'
          wget -q http://www.thc.org/releases/hydra-7.3.tar.gz
          echo ' |  |-[*] Decompressing Tarball'
          tar -zxf hydra-7.3.tar.gz
          echo ' |  |-[*] Renaming Directory'
          mv hydra-7.3 Hydra-7.3
          echo ' |  |-[-] Removing Tarball'
          rm hydra-7.3.tar.gz
          ;;
        *)
          echo " |-[!] ${source} Unsupported. Skipping..."
      esac
    fi
  done
  echo ' |'
  #===================================================================================
  # Prepare Tools Directory
  #-----------------------------------------------------------------------------------
  echo '[*] Preparing Tools Directory'
  mkdir -p $tls_dir
  echo ' |-[*] Changing Directory'
  cd $tls_dir
  echo ' |'

  #===================================================================================
  # Begin Version Controlled Tools Pull
  #-----------------------------------------------------------------------------------
  echo '[*] Beginning Tools Pull'
  for tool in $tls_nms
  do
    if [ -d $tool ]
    then
      echo " |-[!] $tool Installed. Skipping..."
    else
      case $tool in
        [aA][rR][tT][iI][lL][lL][eE][rR][yY])
          echo ' |-[+] Artillery Started (SVN)'
          $scr_com svn co http://svn.trustedsec.com/artillery $tool
          ;;
        [bB][eE][eE][fF])
          echo ' |-[+] BeEF Started (Git)'
          $scr_com git clone https://github.com/beefproject/beef.git $tool
          ;;
        [dD][nN][sS][eE][nN][uU][mM])
          echo ' |-[+] DNSEnum Started (SVN)'
          $scr_com svn co http://dnsenum.googlecode.com/svn/trunk $tool
          ;;
        [dD][nN][sS][rR][eE][cC][oO][nN])
          echo ' |-[+] DNSRecom Started (Git)'
          $scr_com git clone https://github.com/darkoperator/dnsrecon.git $tool
          ;;
        [mM][eE][tT][aA][sS][pP][lL][oO][iI][tT]2)
          echo ' |-[+] Metasploit2 Started (SVN)'
          $scr_com svn co https://www.metasploit.com/svn/framework2/trunk $tool
          ;;
        [mM][eE][tT][aA][sS][pP][lL][oO][iI][tT]4)
          echo ' |-[+] Metasploit4 Started (Git)'
          $scr_com git clone git://github.com/rapid7/metasploit-framework.git $tool
          ;;
        [pP][uU][sS][hH][pP][iI][nN])
          echo ' |-[+] PushPin Started (Git)'
          $scr_com git clone https://bitbucket.org/LaNMaSteR53/pushpin.git $tool
          ;;
        [sS][eE][tT])
          echo ' |-[+] SET Started (SVN)'
          $scr_com svn co http://svn.trustedsec.com/social_engineering_toolkit $tool
          ;;
        [sS][qQ][lL][mM][aA][pP])
          echo ' |-[+] SQLMap Started (Git)'
          $scr_com git clone https://github.com/sqlmapproject/sqlmap.git $tool
          ;;
        [sS][qQ][lL][nN][iI][nN][jJ][aA])
          echo ' |-[+] SQLNinja Started (SVN)'
          $scr_com svn co https://sqlninja.svn.sourceforge.net/svnroot/sqlninja $tool
          ;;
        [sS][sS][lL][yY][zZ][eE])
          echo ' |-[+] SSLyze Started (Git)'
          $scr_com git clone https://github.com/iSECPartners/sslyze.git $tool
          ;;
        [wW]3[aA][fF])
          echo ' |-[+] W3af Started (SVN)'
          $scr_com svn co https://w3af.svn.sourceforge.net/svnroot/w3af/trunk $tool
          ;;
        [wW][pP][sS][cC][aA][nN])
          echo ' |-[+] WPScan Started (Git)'
          $scr_com git clone https://github.com/wpscanteam/wpscan.git $tool
          ;;
        *)
          echo " |-[!] $tool Unsupported. Skipping..."
          ;;
      esac
    fi
  done
  func_jobmon
  #===================================================================================
  # Begin Manually Updated Tools Pull
  #-----------------------------------------------------------------------------------
  echo '[*] Beginning Manual Tools Pull'
  for tool in $man_tls
  do
    if [ -d ${tool}-* ]
    then
      echo " |-[!] $tool Installed. Skipping..."
    else
      case $tool in
        [bB][uU][rR][pP])
          echo ' |-[+] Downloading Burp 1.5 Tool'
          burp_dir="${tool}-1.5"
          mkdir $burp_dir && cd $burp_dir
          wget -q http://www.portswigger.net/burp/burpsuite_free_v1.5.jar
          cd $tls_dir
          ;;
        [fF][iI][eE][rR][cC][eE])
          echo ' |-[+] Downloading Fierce 0.9.9 Tool'
          fierce_dir="${tool}-0.9.9"
          mkdir $fierce_dir && cd $fierce_dir
          wget -q http://ha.ckers.org/fierce/fierce.pl
          wget -q http://ha.ckers.org/fierce/hosts.txt
          cd $tls_dir
          ;;
        *)
          echo " |-[!] $tool Unsupported. Skipping..."
          ;;
      esac
    fi
  done
  echo ' |'
  func_fin
}
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

######################################################################################
# Update Function
#*************************************************************************************
func_update(){
  #===================================================================================
  # Begin Version Controlled Sources Update
  #-----------------------------------------------------------------------------------
  echo '[*] Updating Sources'
  cd $src_dir
  for source in $src_nms
  do
    if [ -d $source ]; then
      echo " |-[+] $source Update Started"
      cd $source
      case $source in
        [aA][rR][aA][cC][hH][nN][iI])
          $scr_com git pull
          ;;
        [kK][iI][sS][mM][eE][tT])
          $scr_com git pull
          ;;
        *)
          $scr_com svn update
          ;;
      esac
      cd $src_dir
    fi
  done
  func_jobmon
  #===================================================================================
  # Begin Version Controlled Tools Update
  #-----------------------------------------------------------------------------------
  echo '[*] Updating Tools'
  cd $tls_dir
  for tool in $tls_nms
  do
    if [ -d "$tool" ]; then
      echo " |-[+] $tool Update Started"
      cd $tool
      case $tool in
        [bB][eE][eE][fF])
          $scr_com git pull
          ;;
        [dD][nN][sS][rR][eE][cC][oO][nN])
          $scr_com git pull
          ;;
        [mM][eE][tT][aA][sS][pP][lL][oO][iI][tT]4)
          $scr_com git pull
          ;;
        [pP][uU][sS][hH][pP][iI][nN])
          $scr_com git pull
          ;;
        [sS][qQ][lL][mM][aA][pP])
          $scr_com git pull
          ;;
        [sS][sS][lL][yY][zZ][eE])
          $scr_com git pull
          ;;
        [wW][pP][sS][cC][aA][nN])
          $scr_com git pull
          ;;
        *)
          $scr_com svn update
          ;;
      esac
      cd $tls_dir
    fi
  done
  func_jobmon
  func_fin
}
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

######################################################################################
# Check Script Requirements
#*************************************************************************************
for req in $req_utl
do
  if [ ! -f `which $req` ]
  then
    func_title
    echo "[!] Missing Requirement: $req"
    echo ' |'
    echo "[!] PenKit Requirements: $req_utl"
    echo
    exit 1
  fi
done
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

######################################################################################
# Function Statement
#*************************************************************************************
func_title
case $1 in
  #===================================================================================
  # Print Configuration To STDOUT
  #-----------------------------------------------------------------------------------
  -c|--[cC][oO][nN][fF][iI][gG])
    echo '[*] Printing Configuration'
    echo ' |'
    echo ' |-[*] Directory Configuration'
    echo " |  |-[:] Sources Directory.: $src_dir"
    echo " |  |-[:] Tools Directory...: $tls_dir"
    echo ' |'
    echo ' |-[*] Sources Enabled'
    cmb_src="$src_nms $man_src"
    for src in $cmb_src
    do
      echo " |  |-[:] $src"
    done | sort
    echo ' |'
    echo ' |-[*] Tools Enabled'
    cmb_tls="$tls_nms $man_tls"
    for tls in $cmb_tls
    do
      echo " |  |-[:] $tls"
    done | sort
    if [ "$scr_com" == '' ]
    then
      echo ' |'
      echo ' |-[*] Miscellaneous'
      echo ' |  |-[:] Debugging: Enabled'
    else
      echo ' |'
      echo ' |-[*] Miscellaneous'
      echo ' |  |-[:] Debugging: Disabled'
    fi
    echo ' |'
    func_fin
    ;;
  #===================================================================================
  # Install All Dependencis
  #-----------------------------------------------------------------------------------
  -d|--[dD][eE][pP][sS])
    func_dependencies
    ;;
  #===================================================================================
  # Export Configuration
  #-----------------------------------------------------------------------------------
  -e|--[eE][xX][pP][oO][rR][tT])
    conf=penkit.conf
    echo '#=====================================================================================' > $conf
    echo "# PenKit Configuration | Exported On: `date +%m.%d.%Y`" >> $conf
    echo '#=====================================================================================' >> $conf
    echo '[*] Exporting Configuration'
    cat ${0}|head -n74|tail -n23 >> $conf
    func_fin
    ;;
  #===================================================================================
  # Install Sources & Tools
  #-----------------------------------------------------------------------------------
  -i|--[iI][nN][sS][tT][aA][lL][lL])
    if [ "${src_dir}" = '/PATH/TO/SOURCES/DIRECTORY' ]
    then
      echo "[Error]: You must edit 'src_dir' configuration variable in script."
      echo
      exit 1
    elif [ "${tls_dir}" = '/PATH/TO/TOOLS/DIRECTORY' ]
    then
      echo "[Error]: You must edit 'tls_dir' configuration variable in script."
      echo
      exit 1
    fi
    func_install
    ;;
  #===================================================================================
  # Install Version Controlled Sources & Tools
  #-----------------------------------------------------------------------------------
  -s|--[sS][tT][aA][tT][sS])
    echo '[*] PenKit Script Statistics'
    echo " |-[~] Lines of Code With Comments....: `cat $0|wc -l`"
    echo " |-[~] Lines of Code Without Comments.: `cat $0|awk '!/^#|^  #/'|wc -l`"
    echo " |-[~] Number of Functions............: `cat $0|grep -i '^func_.*(){'|wc -l`"
    echo " |-[~] Number of If Statements........: `cat $0|grep -i 'if \['|wc -l`"
    echo " |-[~] Number of Case Statements......: `cat $0|grep -i 'case.*in'|wc -l`"
    echo " |-[~] Number of For Loops............: `cat $0|grep -i 'for .*in'|wc -l`"
    echo " |-[~] Number of Variables............: `cat $0|grep -i '[a-z_]='|awk '!/echo/'|sort -bu|wc -l`"
    func_fin
    ;;
  #===================================================================================
  # Update Version Controlled Sources & Tools
  #-----------------------------------------------------------------------------------
  -u|--[uU][pP][dD][aA][tT][eE])
    func_update
    ;;
  #===================================================================================
  # Print Version
  #-----------------------------------------------------------------------------------
  -v|--[vV][eE][rR][sS][iI][oO][nN])
    func_title
    ;;
  #===================================================================================
  # Help Menu
  #-----------------------------------------------------------------------------------
  *)
    if [ "$scr_com" == '' ]
    then
       echo ' [Info]....: Debugging Enabled'
    fi
    echo ' [Usage]...: ./PenKit.sh [OPTION]'
    echo ' [Options].:'
    echo '             -c | --config  = Print Configuration'
    echo '             -d | --deps    = Install All Dependencies'
    echo '             -e | --export  = Export Configuration'
    echo '             -i | --install = Install Sources & Tools'
    echo '             -s | --stats   = Print Script Statistics'
    echo '             -u | --update  = Update Installed Sources & Tools'
    echo '             -v | --version = Print Version'
    echo
esac
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
