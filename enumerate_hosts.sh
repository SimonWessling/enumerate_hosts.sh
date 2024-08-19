#!/bin/bash

AMASS_TIMOUT=15
AMASS_ACTIVE='-active -p 443,80,8080,8008,8443' # attempts zone transfer and certificate grab on these ports. Active probing!
AMASS=~/tools/amass_v3.22.1/amass
WORDLISTS=~/tools/wordlists
DO_HOSTHUNTER=false
MAX_HOSTHUNTER_IPS=32
DNSX_NUM_RETRIES=3
DNS_NUM_BRUTE=5 # in steps of 10 000
PROBE_ALIVE=true

COLOR_GREEN='\e[92m'
COLOR_BLUE_BOLD='\e[1;34m'
COLOR_RED='\e[31m'
COLOR_ORANGE='\e[93m'
COLOR_END='\e[0m'

if [ $# -gt 0 ]; then
	TARGET=$1
	if [ $# -gt 1 ] && [[ "$2" == "--fast" ]] ; then
		printf "${COLOR_ORANGE}%s$COLOR_END" "Quick scan, results may be incomplete.\n"
		AMASS_TIMOUT=5
		DO_HOSTHUNTER=false
		DNS_NUM_BRUTE=3
		DNSX_NUM_RETRIES=1
fi
elif [[ -v "${TARGET}" ]]; then
	echo "Using env \$TARGET $TARGET."
else
	echo "Error: Target not defined. Specify it via environment variable \$TARGET or use:"
	echo "$0 domain.com"
	exit -1
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

num_cidrs=$(grep -c "" ~/$TARGET/in-scope_ips.txt)
if [[ $num_cidrs -eq 1 ]] && [[ $(grep "*" ~/$TARGET/in-scope_ips.txt) ]]; then
	is_wildcard_scope=true
	DO_HOSTHUNTER=false
	printf "${COLOR_ORANGE}%s${COLOR_END}\n" 'Using wildcard scope ("*")'
fi

timestamp="$(date +%F_%H:%M:%S)"
collection_file=~/$TARGET/domains.txt # append-only file to collect domains discovered across iterative script runs
unresolvable_domains_file=~/$TARGET/${timestamp}_unresolvable.txt
current_run_final_file=~/$TARGET/${timestamp}_domains.txt # output of domains discovered during the current run

# check if this is an iterative run -> keep final list of domains from last run
if [ -f $collection_file ]; then
	is_iterative_run=true
fi
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

touch ~/$TARGET/dnsx-bruteforce/${timestamp}_from_best-dns-wordlist.txt
# best-dns-wordlist seems to be sorted by frequency/likelihood -> only brute the first 50 000 candidates
for (( i=0; i<$DNS_NUM_BRUTE; i+=1 )); do
	printf "Bruteforcing $WORDLISTS/best-dns-wordlist/best-dns-wordlist-10.000-%02d (%d/%d)\n" $i $((($i+1)*10000)) $(($DNS_NUM_BRUTE*10000))
	printf "${COLOR_GREEN}"
	wordlist=$(printf "$WORDLISTS/best-dns-wordlist/best-dns-wordlist-10.000-%02d" $i)
	if [ ! -f "$wordlist" ]; then
			printf "${COLOR_RED}%s${COLOR_END}\n" "Wordlist not found: $wordlist. Did you run setup.sh?" # dnsx doesn't throw an error if file is not found, need to check explicitly
			exit -1
	fi
	dnsx -duc -silent -resolver 1.1.1.1 -retry $DNSX_NUM_RETRIES -a -d "$TARGET" -w "$wordlist" | tee -a ~/$TARGET/dnsx-bruteforce/${timestamp}_from_best-dns-wordlist.txt
	printf "${COLOR_END}"
done

## query crt.sh
printf "${COLOR_BLUE_BOLD}%s${COLOR_END}\n" "############### Query crt.sh"
curl "https://crt.sh/?q=%25.$TARGET&output=json" | jq '.[].name_value' \
| sed 's/\"//g' | sed 's/\*\.//g'| sed 's/\\n/\n/g' | sort -u \
> ~/$TARGET/crt.sh/${timestamp}_subdomains_crt.sh.txt
printf "${COLOR_GREEN}"
cat ~/$TARGET/crt.sh/${timestamp}_subdomains_crt.sh.txt | head -n 50
printf "${COLOR_END}"

# create input file for amass
# TODO add known IPs if provided
cat ~/$TARGET/crt.sh/${timestamp}_subdomains_crt.sh.txt ~/$TARGET/dnsx-bruteforce/${timestamp}_from_best-dns-wordlist.txt | sort -u > ~/$TARGET/amass/${timestamp}_input.txt
echo "$TARGET" >> ~/$TARGET/amass/${timestamp}_input.txt

## Amass
printf "${COLOR_BLUE_BOLD}%s${COLOR_END}\n" "############### Run Amass (Limit $AMASS_TIMOUT minutes)"
$AMASS enum -v -timeout $AMASS_TIMOUT -d $TARGET -o ~/$TARGET/amass/${timestamp}_amass.txt -config ~/$TARGET/amass/config.ini -dir ~/$TARGET/amass $AMASS_ACTIVE -nf ~/$TARGET/amass/${timestamp}_input.txt

# query amass db for results. Only works with older versions??
printf ''
$AMASS db -names -dir ~/$TARGET/amass | tee ~/$TARGET/amass/${timestamp}_subdomains_amass.txt

## Hosthunter
printf "${COLOR_BLUE_BOLD}%s${COLOR_END}\n" "############### Run Hosthunter"
if [ "$DO_HOSTHUNTER" = true ]; then
	cd ~/$TARGET/HostHunter/ # need to set cwd because hosthunter -o only accepts files, not paths
	num_in_scope_IPs=$(grep -c "" ~/$TARGET/in-scope_ips.txt)
	if (( $num_in_scope_IPs > $MAX_HOSTHUNTER_IPS )); then
		# if too many hosts, run Hosthunter only for a random sample of $MAX_HOSTHUNTER_IPS IPs and log analysed IPs
		printf "$num_in_scope_IPs IPs in scope, running hosthunter for a random sample of $MAX_HOSTHUNTER_IPS IPs\n"
		shuf -n $MAX_HOSTHUNTER_IPS ~/$TARGET/in-scope_ips.txt > ~/$TARGET/${timestamp}_hosthunter_analysed_IPs.txt
		hosthunter_input=~/$TARGET/${timestamp}_hosthunter_analysed_IPs.txt
		echo $hosthunter_input
	else
		hosthunter_input=~/$TARGET/in-scope_ips.txt
	fi
	
	hosthunter -o ${timestamp}_hosthunter.txt -f TXT $hosthunter_input
	# add to analysed IPs
	cat ~/$TARGET/${timestamp}_hosthunter_analysed_IPs.txt ~/$TARGET/hosthunter_all_analysed_IPs.txt | sort -u -V -o ~/$TARGET/hosthunter_all_analysed_IPs.txt 
	printf "${COLOR_END}"
	
else
	if $is_wildcard_scope; then
		printf "Cannot run HostHunter with wildcard scope\n"
	fi
	printf "Skipping HostHunter (DO_HOSTHUNTER = $DO_HOSTHUNTER)\n\n"
	touch ~/$TARGET/HostHunter/${timestamp}_hosthunter.txt # create empty file for next steps
fi

## create final subdomain list
cat ~/$TARGET/HostHunter/${timestamp}_hosthunter.txt ~/$TARGET/amass/${timestamp}_subdomains_amass.txt ~/$TARGET/crt.sh/${timestamp}_subdomains_crt.sh.txt | sort -u > $current_run_final_file

## filter out the domains that are not in scope (in the given CIDR ranges)
printf "${COLOR_BLUE_BOLD}%s${COLOR_END}\n" "############### Filter domains that are not in scope"
cat $current_run_final_file | while read domain; do
	ip=$(echo "$domain" | dnsx -duc -resolver 1.1.1.1 -silent -a -resp-only);
	if [[ ! $ip ]]; then
		echo "$domain" >> $unresolvable_domains_file
	fi
	((++num_domains_total))
	python $SCRIPTPATH/filter_IP_in_CIDR.py --f_keep ~/$TARGET/${timestamp}_discovered_in_scope.csv --f_discard ~/$TARGET/${timestamp}_discovered_out_of_scope.csv --cidr_file ~/$TARGET/cidr.txt "$ip" "$domain";
done
# if all domains were in scope/out of scope, one of the files does not exist -> create it
if [ ! -f ~/$TARGET/${timestamp}_discovered_in_scope.csv ]; then
	touch -f ~/$TARGET/${timestamp}_discovered_in_scope.csv
elif [ ! -f ~/$TARGET/${timestamp}_discovered_out_of_scope.csv ]; then
	touch -f ~/$TARGET/${timestamp}_discovered_out_of_scope.csv
fi

## collect all
if [ ! -f $collection_file ]; then
	touch $collection_file
fi
cat $collection_file $current_run_final_file | sort -u -o $collection_file
	
# version sort for correct IP sorting
#TODO combine from other runs
sort -V -o ~/$TARGET/${timestamp}_discovered_out_of_scope.csv ~/$TARGET/${timestamp}_discovered_out_of_scope.csv
sort -V -o ~/$TARGET/${timestamp}_discovered_in_scope.csv ~/$TARGET/${timestamp}_discovered_in_scope.csv

## alive HTTP(S) and screenshots
printf "${COLOR_BLUE_BOLD}%s${COLOR_END}\n" "############### Probe alive HTTP(S)"
if [ "$PROBE_ALIVE" = true ]; then
	grep -oP '^.*?(?=,|$)' ~/$TARGET/${timestamp}_discovered_in_scope.csv | tr -d '"' | httpx-toolkit -silent -probe -nf -ip -o ~/$TARGET/${timestamp}_alive_hosts.csv  2>&1 1>/dev/null
	# grep 'SUCCESS' ~/zf.com/2024-05-10_16:23:53_alive_hosts.csv | awk '{print $3,$1}' | tr -d '[]' | tr ' ' ',' | srot -uV
	# TODO screenshots
else
	printf "Not probing alive hosts (PROBE_ALIVE = $PROBE_ALIVE)\n\n"
	touch ~/$TARGET/${timestamp}_alive_webhosts.txt # create empty file for next steps
fi

# TODO
#cat alive_hosts.txt | waybackurls

## print some stats
printf "${COLOR_BLUE_BOLD}%s${COLOR_END}\n" "############### Done."
num_domains_unresolvable=$(grep -c "" $unresolvable_domains_file)
num_domains_total=$(grep -c "" $collection_file)
proportion_domains_unresolvable=$(bc -l <<< "($num_domains_unresolvable / $num_domains_total)*100") # turns out bash can't do float arithmetic...
printf "${COLOR_RED}%d${COLOR_END} domains could not be resolved (${COLOR_RED}~%2.f${COLOR_END} unresolvable)\n" $num_domains_unresolvable
printf "Collected ${COLOR_GREEN}%d resolvable domains${COLOR_END} in this run (%s).\n" $num_domains_total $current_run_final_file
printf "A total of ${COLOR_GREEN}%d domains in total${COLOR_END} were discovered across the runs so far (%s)\n" $num_domains_total $collection_file