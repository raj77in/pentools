#!/bin/bash - 
#===============================================================================
#
#          FILE: lin.sh
# 
#         USAGE: ./lin.sh 
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
set -x

## Copy the enumeration scripts
#cd $PT_TEMP
mkdir -p www/lin
cd www/lin

wget "https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh"
wget "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"
wget "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"
wget "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh"

wget "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32"
wget "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32s"
wget "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64"
wget "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64s"



echo "Files available on webserver"
find . -type f
echo "Local IP is :: $LIP"
python3 -m http.server 80
