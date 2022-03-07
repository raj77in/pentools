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

## Copy the enumeration scripts
cd $PT_TEMP
mkdir -p www/lin
cd www/lin

cp $PT_GDIR/Linux/linux-smart-enumeration/lse.sh .
cp $PT_GDIR/Linux/LinEnum/LineEnum.sh .
cp $PT_GDIR/PrivEsc/privilege-escalation-awesome-scripts-suite/linPEAS/linpeas.sh .

## Get pspy
cp $PT_TDIR/pspy-v1.2.0/pspy32 .
cp $PT_TDIR/pspy-v1.2.0/pspy64 .
cp $PT_TDIR/pspy-v1.2.0/pspy32s .
cp $PT_TDIR/pspy-v1.2.0/pspy64s .

cd $PT_TEMP
echo "Files available on webserver"
find . -type f
echo "Local IP is :: $LIP"
python3 -m http.server 80
