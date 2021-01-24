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
mkdir -p www/lin
cd www/lin

cp $GDIR/Linux/linux-smart-enumeration/lse.sh .
cp $GDIR/Linux/LinEnum/LineEnum.sh .
cp $GDIR/PrivEsc/privilege-escalation-awesome-scripts-suite/linPEAS/linpeas.sh .

## Get pspy
cp $TDIR/pspy-v1.2.0/pspy32 .
cp $TDIR/pspy-v1.2.0/pspy64 .
cp $TDIR/pspy-v1.2.0/pspy32s .
cp $TDIR/pspy-v1.2.0/pspy64s .

cd ..
echo "Local IP is :: $LIP"
python3 -m http.server 80
