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

[[ -z $PT_IP ]] && echo "PT_IP is not set", exit 3
[[ -z $HOSTNAME ]] && echo "HOSTNAME is not set", exit 3
export BASE="$HOME/tools"
export PT_ODIR="${PT_ODIR:-~/scans/$HOSTNAME/}"
mkdir -p $PT_ODIR
cd $PT_ODIR

export PT_TUN=${PT_TUN:-tun0}
export PT_GDIR=${PT_GDIR:-~/tools/git}
export PT_TDIR=${PT_TDIR:-/tools/downloaded_tools}
export PT_IP=${PT_IP:-10.10.10.10}
export PT_LPORT=${PT_LPORT:-8001}
export LIP=$(ip -o -4 --brief a \
             show dev  $PT_TUN |awk '{print $3}'|sed 's;/.*;;')
export PT_TEMP=$(mktemp -d /tmp/PT-XXXXXX)

## Some common tools
export autorecon="$PT_GDIR/autorecon.py"
export gobuster="$PT_GDIR/Scanning/ffuf"
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


if [[ ! -e "$BASE/$1/$2.sh" ]]
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
