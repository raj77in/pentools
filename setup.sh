#!/bin/bash - 
#===============================================================================
#
#          FILE: setup.sh
# 
#         USAGE: ./setup.sh 
# 
#   DESCRIPTION: 
# 
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: Amit Agarwal (aka), 
#  ORGANIZATION: Individual
#       CREATED: 01/01/2021 13:13
#      REVISION:  ---
#===============================================================================

[[ -z $IP ]] && echo "IP is not set", exit 3
[[ -z $HOSTNAME ]] && echo "HOSTNAME is not set", exit 3
export BASE="/root/tools"
export ODIR="/root/amitag/CTF/hackthebox/scans/$HOSTNAME/"
mkdir -p $ODIR
cd $ODIR

export TUN=${TUN:-tun0}
export GDIR=${GDIR:-/root/amitag/git/tools/}
export TDIR=${TDIR:-/root/amitag/tools/}
export IP=${IP:-10.10.10.10}
export LPORT=${LPORT:-8001}
export LIP=$(ip -o -4 --brief a \
             show dev  $TUN |awk '{print $3}'|sed 's;/.*;;')


export autorecon="$GDIR/AutoRecon/src/autorecon/autorecon.py"
export gobuster="$GDIR/Scanning/ffuf"
export nmap="/usr/bin/nmap"

function help() {
    echo "Not enough arguments."
    echo "Run with <folder> <script>"
    dirs=$(find -type f|sed 's/^..//'|grep '\/'|awk -F'/' '{print $1}'|sort |uniq)
    echo "Folders : $(echo ${dirs}|tr '\n' ' ')"
    echo "All modules :: $(for i in $dirs; do \
          find $i -type f -name \*sh ; done | tr '\n' ' ') "

    exit 2
}

if [[ $# -lt 2 ]]
then
    help
fi


if [[ ! -e $BASE/$1/$2.sh ]]
then
    echo "check if file exists $BASE/$1/$2.sh"
    help
fi

if [[ $3 == run ]]
then
    bash $BASE/$1/$2.sh $*
else
    envsubst < $BASE/$1/$2.sh
fi
