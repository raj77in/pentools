#!/bin/bash - 
#===============================================================================
#
#          FILE: ssl.sh
# 
#         USAGE: ./ssl.sh 
# 
#   DESCRIPTION: 
# 
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: Amit Agarwal (aka), 
#  ORGANIZATION: Individual
#       CREATED: 01/01/2021 18:54
#      REVISION:  ---
#===============================================================================

set -o nounset                              # Treat unset variables as an error
sslscan --show-certificate --no-colour $url 2>&1 tee -a "$ODIR/sslscan.txt"

