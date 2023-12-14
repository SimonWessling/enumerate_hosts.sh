#!/bin/bash

## Setup

if [[ -z "${TARGET}" ]]; then
	echo 'Error: $TARGET not defined.'
	exit -1
else
	echo "Using \$TARGET $TARGET."
fi

# run project setup
mkdir -p ~/$TARGET/amass
this_dir="$(dirname "${BASH_SOURCE}")"
python $this_dir/setup_project.py -d ~/$TARGET

if [ $? -ne 0 ];
then
	echo "Aborted."
	exit -1
fi

## query crt.sh
curl --silent "https://crt.sh/?q=%25.$TARGET&output=json" | jq '.[].name_value' \
| sed 's/\"//g' | sed 's/\*\.//g'| sed 's/\\n/\n/g' | sort -u \
> ~/$TARGET/crt.sh/subdomains_crt.sh.txt

## Amass
~/amass_v3.19.2/amass enum -v -d ~/$TARGET -o ~/$TARGET/amass/amass.txt -config ~/$TARGET/amass/config.ini -dir ~/$TARGET/amass -active -p 443,80,8080,8008 -nf ~/$TARGET/crt.sh/subdomains_crt.sh.txt

# query amass db for results. Only works with older versions??
~/amass_v3.19.2/amass db -names -dir ~/$TARGET/amass > ~/$TARGET/amass/subdomains_amass.txt

## Hosthunter
~/HostHunter/hosthunter.py -o ~/$TARGET/HostHunter/hosthunter.txt -f TXT ~/$TARGET/ips.txt

## create final subdomain list
cat $TARGET/HostHunter/hosthunter.txt ~/$TARGET/amass/subdomains_amass.txt ~/$TARGET/crt.sh/subdomains_crt.sh.txt | sort -u > ~/$TARGET/domains.txt

## filter out the domains that are not in scope (in the given CIDR ranges)
cat ~/$TARGET/domains.txt \
| while read domain; do
ip=$(echo "$domain" | dnsx -silent -a -resp-only);
python $this_dir/filter_IP_in_CIDR.py --debug --f_discard ~/$TARGET/out_of_scope_IPs.txt --cidr_file ~/$TARGET/cidr.txt "$ip" "$domain";
done

## whois for the out-of-scope domains - maybe the customer missed some?
cat ~/$TARGET/out_of_scope_IPs.txt | sort -u | while read ip; do echo $ip | xargs whois | head -n 20; done;