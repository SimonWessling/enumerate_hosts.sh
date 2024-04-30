#!/bin/bash
TOOLS=~/tools
WORDLISTS="${TOOLS}/wordlists"

set -e
sudo apt install jq hosthunter dnsx httpx-toolkit
#git clone https://github.com/SpiderLabs/HostHunter.git
if [ ! -f ${TOOLS}/amass_v3.22.1/amass ]; then
	printf "Installing amass\n"
	curl -L -o ~/Downloads/amass_linux_amd64.zip https://github.com/owasp-amass/amass/releases/download/v3.22.1/amass_linux_amd64.zip
	mkdir -p ${TOOLS}/amass_v3.22.1
	unzip -d ${TOOLS}/amass_v3.22.1 ~/Downloads/amass_linux_amd64.zip
	mv ${TOOLS}/amass_v3.22.1/amass_linux_amd64/* ${TOOLS}/amass_v3.22.1/
	rmdir ${TOOLS}/amass_v3.22.1/amass_linux_amd64
	rm ~/Downloads/amass_linux_amd64.zip
else
	printf "${TOOLS}/amass_v3.22.1 exists\n"
fi
if [ ! -f ${WORDLISTS}/best-dns-wordlist/best-dns-wordlist.txt ]; then
	printf "Creating directory for best-dns wordlist at $WORDLISTS/best-dns-wordlist\n"
	mkdir -p ${WORDLISTS}/best-dns-wordlist
	printf "Getting best-dns wordlist and splitting (to $WORDLISTS/best-dns-wordlist/)\n"
	curl -o ${WORDLISTS}/best-dns-wordlist/best-dns-wordlist.txt https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt
	split -d -l 2000 ${WORDLISTS}/best-dns-wordlist/best-dns-wordlist.txt "${WORDLISTS}/best-dns-wordlist/best-dns-wordlist-10.000-"  # dnsx can't handle large files
else
	printf "best-dns-wordlist exists\n"
fi
