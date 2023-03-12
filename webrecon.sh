#!/bin/bash
# Original Idea from :
# https://github.com/TCM-Course-Resources/Practical-Ethical-Hacking-Resources/blob/master/bash/webrecon.sh

if [[ $# -le 0 ]]
then
	echo "Usage : $0 <Domain>"
	exit 1
fi
url=$1

## Color codes
red="\e[0;91m"
blue="\e[0;94m"
expand_bg="\e[K"
blue_bg="\e[0;104m${expand_bg}"
red_bg="\e[0;101m${expand_bg}"
green_bg="\e[0;102m${expand_bg}"
green="\e[0;92m"
white="\e[0;97m"
bold="\e[1m"
uline="\e[4m"
reset="\e[0m"



if [ ! -d "$url" ];then
    mkdir $url
fi

for i in recon/eyewitness recon/scans recon/httprobe recon/potential_takeovers recon/wayback recon/wayback/params recon/wayback/extensions
do
	dir=$url/$i
	[[ ! -d $dir ]] && mkdir -p $dir
done

function header()
{
    echo "## ================================================== ##"
    echo -e "[${green}+${reset}] Starting $blue$1$reset to $blue'$2'$reset ..."
    echo "## ================================================== ##"
}

header assetfinder  "Harvest subdomains"
assetfinder $url | grep $url >> $url/recon/final.txt
 
#header amass "Double checking"
#amass enum -d $url >> $url/recon/f.txt
#sort -u $url/recon/f.txt >> $url/recon/final.txt
#rm $url/recon/f.txt
 
header httprobe "Check alive domains"
cat $url/recon/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443'  >> $url/recon/httprobe/a.txt
sort -u $url/recon/httprobe/a.txt > $url/recon/httprobe/alive.txt
rm $url/recon/httprobe/a.txt
 
echo "[+] Checking for possible subdomain takeover..."
 
header subjack "Possible Domain TakeOver" 
subjack -w $url/recon/final.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 -o $url/recon/potential_takeovers/potential_takeovers.txt
 
# header nmap "Port Scan"
# nmap -iL $url/recon/httprobe/alive.txt -T4 -oA $url/recon/scans/scanned.txt
 
# header waybackurls "Wayback data"
# cat $url/recon/final.txt | waybackurls >> $url/recon/wayback/wayback_output.txt
# sort -u $url/recon/wayback/wayback_output.txt
 
# header params "Scraping params"
# cat $url/recon/wayback/wayback_output.txt | grep '?*=' | cut -d '=' -f 1 | sort -u >> $url/recon/wayback/params/wayback_params.txt
# for line in $(cat $url/recon/wayback/params/wayback_params.txt);do echo $line'=';done
#
# header Scraping "Pulling and compiling js/php/aspx/jsp/json files"
# for line in $(cat $url/recon/wayback/wayback_output.txt);do
    # ext="${line##*.}"
    # echo $line >> $url/recon/wayback/extensions/$ext.txt
# done
#
# for f in $url/recon/wayback/extensions/*
# do
    # sort -u $url/recon/wayback/extensions/$ext.txt >$url/recon/wayback/extensions/temp.txt
    # mv $url/recon/wayback/extensions/temp.txt $url/recon/wayback/extensions/$ext.txt
# done
#
#echo "[+] Running eyewitness against all compiled domains..."
#python3 EyeWitness/EyeWitness.py --web -f $url/recon/httprobe/alive.txt -d $url/recon/eyewitness --resolve

