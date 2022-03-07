#!/bin/bash -
#===============================================================================
#
#          FILE: pwn-templ.sh
#
#         USAGE: ./pwn-templ.sh
#
#   DESCRIPTION:
#
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: Amit Agarwal (aka),
#  ORGANIZATION: Individual
#       CREATED: 11/10/18 12:00:10
#      REVISION:  ---
#===============================================================================

set -o nounset                                  # Treat unset variables as an error

virtualenv pwntools  -p $(which python)
source pwntools/bin/activate
pip install pwntools

if [[ -f pwn.py ]]
then
    echo "File pwn.py already exists"
    exit 2
fi

# $1 - binary
# $2 - host
# $3 - port
python template $1 --host $2 --port $3 > pwn.py