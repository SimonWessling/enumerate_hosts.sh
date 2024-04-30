#!/bin/bash

AMASS_TIMOUT=5
AMASS_ACTIVE='-active -p 443,80,8080,8008,8443' # attempts zone transfer and certificate grab on these ports. Active probing!
AMASS=~/tools/amass_v3.22.1/amass
WORDLISTS=~/tools/wordlists
DO_HOSTHUNTER=true
PROBE_ALIVE=true
MAX_IPS=255

COLOR_GREEN='\e[92m'
COLOR_BLUE_BOLD='\e[1;34m'
COLOR_RED='\e[31m'
COLOR_ORANGE='\e[93m'
COLOR_END='\e[0m'

if [[ -z "${TARGET}" ]]; then
	echo 'Error: $TARGET not defined.'
	exit -1
else
	echo "Using \$TARGET $TARGET."
fi

if [[ $TARGET == www.* ]]
then
	echo -e "${COLOR_ORANGE}Warning: TARGET ${TARGET} starts with \"www.\"$COLOR_END"
fi

if [[ $TARGET == *.*.* ]]
then
	echo -e "${COLOR_ORANGE}Warning: TARGET ${TARGET} is already a subomdomain$COLOR_END"
fi

# run project setup
SCRIPT="$(realpath "$0")"
SCRIPTPATH="$(dirname "$SCRIPT")"

#if [ $# -gt 0 ]; then
#	printf "Using CIDR range(s) $@"; printf "\n"
#fi
printf "Setting up project\n"
python $SCRIPTPATH/setup_project.py ~/$TARGET #"$@"

if [ $? -ne 0 ]; then
	exit -1
	echo "Aborted."
fi

# TODO check if this is an iterative run

# TODO check canonical hostname for TARGET

# TODO attempt zone transfer https://github.com/rbsec/dnscan and disable zone transfer for amass
# dnscan.py -d "$TARGET" -z

## whois for the out-of-scope domains - maybe the customer missed some?
#printf "${COLOR_BLUE_BOLD} %s${COLOR_END}\n" "############### Whois"
#cat ~/$TARGET/discovered_out_of_scope_IPs.txt | sort -u | while read ip; do echo $ip | xargs whois | head -n 20; done;
#TODO get IP ranges from whois inetnum or route
#TODO urlscan.io for CIDR range

## bruteforce with dictionary
printf "${COLOR_BLUE_BOLD}%s${COLOR_END}\n" "############### Bruteforcing subdomains"

touch ~/$TARGET/dnsx-bruteforce/from_best-dns-wordlist.txt
# best-dns-wordlist seems to be sorted by frequency/likelihood -> only brute the first 50 000 candidates
for i in 00 01 02 03 04; do
	printf "Bruteforcing $WORDLISTS/best-dns-wordlist/best-dns-wordlist-10.000-$i (%d/50000)\n" $((($i+1)*10000))
	printf "${COLOR_GREEN}"
	wordlist="$WORDLISTS/best-dns-wordlist/best-dns-wordlist-10.000-$i"
	if [ ! -f "$wordlist" ]; then
		printf "${COLOR_RED}%s${COLOR_END}\n" "Wordlist not found: $wordlist. Did you run setup.sh?" # dnsx doesn't throw an error if file is not found, need to check explicitly
		exit -1
	fi
	dnsx -silent -resolver 8.8.8.8,8.8.4.4 -retry 3 -a -d "$TARGET" -w "$wordlist" | tee -a ~/$TARGET/dnsx-bruteforce/from_best-dns-wordlist.txt
	printf "${COLOR_END}"
done

## query crt.sh
printf "${COLOR_BLUE_BOLD}%s${COLOR_END}\n" "############### Query crt.sh"
curl "https://crt.sh/?q=%25.$TARGET&output=json" | jq '.[].name_value' \
| sed 's/\"//g' | sed 's/\*\.//g'| sed 's/\\n/\n/g' | sort -u \
> ~/$TARGET/crt.sh/subdomains_crt.sh.txt
printf "${COLOR_GREEN}"
cat ~/$TARGET/crt.sh/subdomains_crt.sh.txt | head -n 50
printf "${COLOR_END}"

# create input file for amass
# TODO add known IPs if provided
cat ~/$TARGET/crt.sh/subdomains_crt.sh.txt ~/$TARGET/dnsx-bruteforce/from_best-dns-wordlist.txt | sort -u > ~/$TARGET/amass/input.txt
echo "$TARGET" >> ~/$TARGET/amass/input.txt

## Amass
printf "${COLOR_BLUE_BOLD}%s${COLOR_END}\n" "############### Run Amass (Limit $AMASS_TIMOUT minutes)"
$AMASS enum -v -timeout $AMASS_TIMOUT -d $TARGET -o ~/$TARGET/amass/amass.txt -config ~/$TARGET/amass/config.ini -dir ~/$TARGET/amass $AMASS_ACTIVE -nf ~/$TARGET/amass/input.txt

# query amass db for results. Only works with older versions??
printf ''
$AMASS db -names -dir ~/$TARGET/amass | tee ~/$TARGET/amass/subdomains_amass.txt

## Hosthunter
printf "${COLOR_BLUE_BOLD}%s${COLOR_END}\n" "############### Run Hosthunter"
if [ "$DO_HOSTHUNTER" = true ]; then
	# if too many hosts, run Hosthunter only the first $MAX_IPS IPs
	num_in_scope_IPs=$(wc -l ~/$TARGET/in-scope_ips.txt | cut -d' ' -f1)
	if (( $num_in_scope_IPs > $MAX_IPS )); then
		printf "$num_in_scope_IPs in scope, running hosthunter for the first $MAX_IPS\n"
		head -n $MAX_IPS ~/$TARGET/in-scope_ips.txt > ~/$TARGET/hosthunter_scanned_IPs.txt
		hosthunter_input=~/$TARGET/hosthunter_scanned_IPs.txt
	else
		hosthunter_input=~/$TARGET/in-scope_ips.txt
	fi
	
	cd ~/$TARGET/HostHunter/ # need to set cwd because hosthunter -o only accepts files, not paths
	hosthunter -o hosthunter.txt -f TXT ~/$TARGET/in-scope_ips.txt
	printf "${COLOR_END}"
	
else
	printf "Skipping HostHunter (DO_HOSTHUNTER = $DO_HOSTHUNTER)\n\n"
	touch ~/TARGET/HostHunter/hosthunter.txt # create empty file for next steps
fi

## create final subdomain list
cat ~/$TARGET/HostHunter/hosthunter.txt ~/$TARGET/amass/subdomains_amass.txt ~/$TARGET/crt.sh/subdomains_crt.sh.txt | sort -u > ~/$TARGET/domains.txt

## filter out the domains that are not in scope (in the given CIDR ranges)
printf "${COLOR_BLUE_BOLD}%s${COLOR_END}\n" "############### Filter domains that are not in scope"
cat ~/$TARGET/domains.txt \
| while read domain; do
ip=$(echo "$domain" | dnsx -silent -resolver 8.8.8.8,8.8.4.4 -a -resp-only);
python $SCRIPTPATH/filter_IP_in_CIDR.py --debug --f_keep ~/$TARGET/discovered_in_scope.csv --f_discard ~/$TARGET/discovered_out_of_scope_IPs.csv --cidr_file ~/$TARGET/cidr.txt "$ip" "$domain";
done

# version sort for correct IP sorting
sort -V -o ~/$TARGET/discovered_out_of_scope_IPs.csv > ~/$TARGET/discovered_out_of_scope_IPs.csv
sort -V -o ~/$TARGET/discovered_in_scope.csv ~/$TARGET/discovered_in_scope.csv

## alive HTTP(S) and screenshots
printf "${COLOR_BLUE_BOLD}%s${COLOR_END}\n" "############### Probe alive HTTP(S)"
if [ "$PROBE_ALIVE" = true ]; then
	mkdir ~/TARGET/screenshots
	httpx-toolkit -list ~/$TARGET/domains.txt -silent -probe -o ~/$TARGET/alive_hosts.txt # -screenshot -srd ~/${TARGET}/screenshots
else
	printf "Not probing alive hosts (PROBE_ALIVE = $PROBE_ALIVE)\n\n"
	touch ~/$TARGET/alive_hosts.txt # create empty file for next steps
fi

# TODO
#cat alive_hosts.txt | waybackurls

