PenKit 0.6.1
============

Description
-----------
PenKit is a bash script to build cutomizable penetration testing systems. Specifically, it allows security professionals to build their own customized BackTrack-like systems using only the tools they want to include. PenKit can also store all tools conveniently in one directory and update them in paralell using their respective source code management configurations (Subversion, Git, etc.) cutting out the middle man for updates and allowing scriptable automatic updates via cron jobs or similar tasks.

**SCM Supported Source Code**

* AirCrack-NG
* Arachni
* Kismet
* Nmap
* Reaver
* Zed Attack Proxy (ZAP)

**SCM Supported Tools**

* Artillery
* Browser Exploitation Framework (BeEF)
* DNSEnum
* DNSRecon
* Metasploit2
* Metasploit4
* PushPin
* Social Engineering Toolkit (SET)
* SQLMap
* SQLNinja
* W3af
* WPScan

**Non-SCM Supported Source Code**

* Crunch
* Hydra

**Non-SCM Supported Tools**

* Burp
* Fierce

Configuration
-------------
Currently, PenKit's configuration is done through the top portion of the script, starting at line 48. By default, all supported source code and tools are enabled. To remove a tool or source code, simply remove it from the variable.

**Configurable Options:**
* Sources Storage Directory  = src_dir=/PATH/TO/SOURCES/DIRECTORY
* Tools Storage Directory    = tls_dir=/PATH/TO/TOOLS/DIRECTORY
* Enabled SCM Sources        = src_nms='AirCrack-NG Arachni Kismet Nmap Reaver ZAP'
* Enabled Non-SCM Sources    = man_src='Crunch Hydra'
* Enabled SCM Tools          = tls_nms='Artillery BeEF DNSEnum DNSRecon Metasploit2 Metasploit4 PushPin SET SQLMap SQLNinja SSLyze W3af WPScan'
* Enabled Non-SCM Tools      = man_tls='Burp Fierce'
* Enable Debugging (Line 81) = Comment Out "scr_com='screen -d -m -S PenKit'" (Note: Will disable parallel updating)


Usage
-----
**Supported Switches:**

* -c | --config  = Print Configuration
* -d | --deps    = Install All Dependencies
* -e | --export  = Export Configuration
* -i | --install = Install Sources & Tools
* -s | --stats   = Print Script Statistics
* -u | --update  = Update Installed Sources & Tools
* -v | --version = Print Version
