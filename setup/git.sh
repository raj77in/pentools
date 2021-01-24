#!/bin/bash - 
#===============================================================================
#
#          FILE: git.sh
# 
#         USAGE: ./git.sh 
# 
#   DESCRIPTION: 
# 
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: Amit Agarwal (aka), 
#  ORGANIZATION: Individual
#       CREATED: 01/01/2021 14:02
#      REVISION:  ---
#===============================================================================

set -o nounset                              # Treat unset variables as an error

mcd() {
    mkdir -p "$1"
    cd "$1"
}
alias gc='git clone '

mcd $TDIR/pspy-v1.2.0/
wget "https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32"
wget "https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64"                                
wget "https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32s"                               
wget "https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64s" 

## Linux Tools
mcd $GDIR/tools/
gc https://github.com/Tib3rius/AutoRecon
mcd Linux
gc https://github.com/diego-treitos/linux-smart-enumeration
gc https://github.com/rebootuser/LinEnum
mcd $GDIR/tools/PrivEsc
gc https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite

## Windows Tools
mcd $GDIR/tools/Windows
cd tools/Windows
git clone https://github.com/Neohapsis/creddump7.git


