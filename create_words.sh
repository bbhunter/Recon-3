#!/bin/bash

# script that generate all wordlist useful for recon process and removes unnecessary data.

domain=$1
name=$(echo $domain | cut -d "." -f1)
SECONDS=0

rm -r wordlists
mkdir -p wordlists

echo -e "\e[32m[*] Fetching DNS bruteforce wordlists ... \e[0m"
cd wordlists
git clone -q https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056
wget https://github.com/assetnote/commonspeak2-wordlists/blob/master/subdomains/subdomains.txt > /dev/null 2>&1 &
cat 86a06c5dc309d08580a018c66354a056/all.txt subdomains.txt | sort -u | uniq > /root/Desktop/Recon/massdns/lists/brutesub.txt
cp /root/Desktop/Recon/massdns/lists/brutesub.txt /root/Desktop/Recon/wordlists/
rm -rf 86a06c5dc309d08580a018c66354a056 subdomains.txt

echo -e "\e[32m[*] Fetching content discovery wordlists ... \e[0m"
git clone -q https://gist.github.com/jhaddix/b80ea67d85c13206125806f0828f4d10
mv /root/Desktop/Recon/wordlists/b80ea67d85c13206125806f0828f4d10/content_discovery_all.txt /root/Desktop/Recon/wordlists/
rm -r /root/Desktop/Recon/wordlists/b80ea67d85c13206125806f0828f4d10

echo -e "\e[32m[*] Fetching providers data for ST ... \e[0m"
cp /root/go/src/github.com/anshumanbh/tko-subs/providers-data.csv /root/Desktop/Recon/wordlists

echo -e "\e[32m[*] Fetching DNS resolver lists ... \e[0m"
git clone -q https://github.com/Abss0x7tbh/bass.git
cd bass #&& pip3 install -r requirements.txt
python3 bass.py -d $1 -o $1_bass.txt >/dev/null
mv $1_bass.txt /root/Desktop/Recon/wordlists/ && cd ..
rm -rf bass

git clone -q https://github.com/vortexau/dnsvalidator
cd dnsvalidator
python3 setup.py install > /dev/null 2>&1 &
dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 20 -o resolvers.txt #>/dev/null
mv resolvers.txt /root/Desktop/Recon/wordlists/ && cd ..
rm -rf dnsvalidator

cat $1_bass.txt resolvers.txt > /root/Desktop/Recon/massdns/lists/validated.txt

duration=$SECONDS
echo -e "\e[31m[*] $(($duration / 60)) minutes and $(($duration % 60)) seconds elapsed.\e[0m"
