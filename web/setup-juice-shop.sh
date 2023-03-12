#!/bin/bash - 
#===============================================================================
#
#          FILE: setup-juice-shop.sh
# 
#         USAGE: ./setup-juice-shop.sh 
# 
#   DESCRIPTION: 
# 
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: Amit Agarwal (aka), 
#  ORGANIZATION: Individual
#       CREATED: 10/30/2022 11:34
#      REVISION:  ---
#===============================================================================

set -o nounset                              # Treat unset variables as an error
docker pull bkimminich/juice-shop
docker run --rm -p 3000:3000 bkimminich/juice-shop

