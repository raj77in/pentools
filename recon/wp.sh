#!/bin/bash - 
#===============================================================================
#
#          FILE: wp.sh
# 
#         USAGE: ./wp.sh 
# 
#   DESCRIPTION: 
# 
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: Amit Agarwal (aka), 
#  ORGANIZATION: Individual
#       CREATED: 01/01/2021 18:31
#      REVISION:  ---
#===============================================================================

set -o nounset                              # Treat unset variables as an error

read -p "Enter the wordpress URL :" wpurl
wpscan --url $wpurl --no-update --disable-tls-checks -e vp,vt,tt,cb,dbe,u,m --plugins-detection aggressive --plugins-version-detection aggressive -f cli-no-color 2>&1 | tee "$ODIR/wpscan.txt"
wpscan --url $wpurl --no-update --disable-tls-checks 2>&1 | tee "$ODIR/wpscan-users.txt"

