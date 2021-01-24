#!/bin/bash - 
#===============================================================================
#
#          FILE: smb.sh
# 
#         USAGE: ./smb.sh 
# 
#   DESCRIPTION: 
# 
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: Amit Agarwal (aka), 
#  ORGANIZATION: Individual
#       CREATED: 01/01/2021 18:38
#      REVISION:  ---
#===============================================================================

set -o nounset                              # Treat unset variables as an error
enum4linux -a -M -l -d $IP 2>&1 | tee "$ODIR/enum4linux.txt"
smbmap -H $IP 2>&1 | tee -a "$ODIR/smbmap.txt"
smbmap -u null -p "" -H $IP -P 139 2>&1 | tee -a "$ODIR/smbmap-null.txt"
smbmap -H $IP -P 139 -R 2>&1 | tee -a "$ODIR/smbmap-recursive.txt"
smbmap -u null -p "" -H $IP -P 139 -R 2>&1 | tee -a "$ODIR/smbmap-null-recursive.txt"
smbmap -H $IP -P 139 -x "ipconfig /all" 2>&1 | tee -a "$ODIR/smpmap-command.txt"
smbmap -u null -p "" -H $IP -P 139 -x "ipconfig /all" 2>&1 | tee -a "$ODIR/smpmap-command.txt"
crackmapexec smb $IP
