#!/bin/bash - 
#===============================================================================
#
#          FILE: lin.sh
# 
#         USAGE: ./lin.sh 
# 
#   DESCRIPTION: 
# 
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: Amit Agarwal (aka), 
#  ORGANIZATION: Individual
#       CREATED: 06/28/2022 13:14
#      REVISION:  ---
#===============================================================================

set -o nounset                              # Treat unset variables as an error

## Copy the enumeration scripts
#cd $PT_TEMP
mkdir -p www/win
cd www/win

declare -A tarurls
declare -A zipurls
declare -A others
tarurls=(
    [GhostPack]="https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/archive/refs/heads/master.tar.gz"
    [powersploit]="https://github.com/PowerShellMafia/PowerSploit/archive/refs/tags/v3.0.0.tar.gz"
    [peas]="https://github.com/carlospolop/PEASS-ng/archive/refs/heads/master.tar.gz"
)

zipurls=(
    [mimikatz]='https://github.com/gentilkiwi/mimikatz/releases/latest/download//mimikatz_trunk.zip'
    [sysinternals]="https://download.sysinternals.com/files/SysinternalsSuite.zip"
    [sharphound]="https://github.com/BloodHoundAD/SharpHound/releases/download/v1.0.4/SharpHound-v1.0.4.zip"
)
others=(
    [AmsiBypass.md]="https://raw.githubusercontent.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell/master/README.md"
    [sysinternals.pdf]="https://docs.microsoft.com/en-us/sysinternals/opbuildpdf/toc.pdf?branch=live"
    [winpeas.exe]="https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe"
    [winpeas_ofs.exe]="https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe"
    [winpeas64_ofs.exe]="https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64_ofs.exe"
    [linpeas.sh]="https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"
    [AmsiTrigger64.exe]="https://github.com/RythmStick/AMSITrigger/releases/latest/download/AmsiTrigger_x64.exe"
    [Invoke-AmsiBypass.ps1]="https://raw.githubusercontent.com/samratashok/nishang/master/Bypass/Invoke-AmsiBypass.ps1"
)


for zip in "${!tarurls[@]}"
do
    wget -nv -nc -c "${tarurls[$zip]}" -O "${zip}.tar.gz"
    tar xf "${zip}.tar.gz"
    rm -f "${zip}.tar.gz"
done

for zip in "${!zipurls[@]}"
do
    wget -nv -nc -c "${zipurls[$zip]}" -O "${zip}.zip"
    (mkdir ${zip}; cd ${zip}; unzip "../${zip}.zip"; cd -)
    rm -f "${zip}.zip"
done

for file in "${!others[@]}"
do
    wget -nv -nc -c "${others[$file]}" -O "${file}"
done

echo "Files available on webserver"
find . -type f
echo "Local IP is :: $LIP"
python3 -m http.server 80
