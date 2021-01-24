#!/bin/bash - 
#===============================================================================
#
#          FILE: initial.sh
# 
#         USAGE: ./initial.sh 
# 
#   DESCRIPTION: 
# 
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: Amit Agarwal (aka), 
#  ORGANIZATION: Individual
#       CREATED: 01/01/2021 13:14
#      REVISION:  ---
#===============================================================================

set -o nounset                              # Treat unset variables as an error

## AutoRecon
#$autorecon $IP -o autorecon

#cd $ODIR/autorecon/$IP/scans
#for i in *txt; do echo "=============$i===================" ; cat $i; echo '-----------------------------'; echo '-----------------------------'; done |xclip -i -selection clipboard
# echo "Results have been copied to clipboard, you can paste it now"

cd $ODIR/
mkdir nmap
alias nmap='nmap -vv --reason'
echo "Scanning IP address :: $IP $HOSTNAME"
nmap $IP -oA nmap/initial 
nmap -sC -sV -A $IP -oA nmap/initial-a
nmap -p- $IP -oA nmap/all-ports
nmap -sU --top-ports 50 $IP -oA nmap/all-ports
nmap -p 139 --script="banner,(nbstat or smb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --script-args="unsafe=1" $IP -oA "nmap/smb-scripts.txt"


