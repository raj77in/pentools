#!/bin/bash
#
# Read the creds.txt file in current
# folder to get the creds and connect method
#

# rdp='xfreerdp /dynamic-resolution +clipboard /cert-ignore +auto-reconnect /auto-reconnect-max-retries:3 /v:$IP /u:$USER /p:$PASS /t:$IP /rfx +fonts '
rdp='xfreerdp /dynamic-resolution +clipboard /cert-ignore +auto-reconnect /auto-reconnect-max-retries:3 /v:$IP /u:$USER /p:$PASS /t:$IP /rfx +fonts '
rdph='xfreerdp /dynamic-resolution +clipboard /cert-ignore +auto-reconnect /auto-reconnect-max-retries:3 /v:$IP /u:$USER /pth:$PASS /t:$IP /rfx +fonts '
ssh='sshpass -p $PASS ssh -l $USER $IP'
winrm='evil-winrm -u $USER -i $IP -p $PASS'
winrmh='evil-winrm -u $USER -i $IP -H $PASS'
smb='impacket-smbexec "$USER:$PASS@$IP"'
ps='impacket-psexec "$USER:$PASS@$IP"'

w=( $(grep $1 creds.txt | sed 's/|/ /g') )
export IP=${w[1]}
export USER=${w[2]}
export PASS=${w[3]}
echo ${!w[0]} |envsubst
if [[ $2 == p* || $3 == p* ]]
then
  eval proxychains4 ${!w[0]}
  exit
fi

if [[ $2 != "" ]]
then
w=( $(grep $1 creds.txt|grep $2 | sed 's/|/ /g') )
  export IP=${w[1]}
  export USER=${w[2]}
  export PASS=${w[3]}
  echo ${!w[0]} |envsubst
  eval ${!w[0]}
else
  eval ${!w[0]}
fi
