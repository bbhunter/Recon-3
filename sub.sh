#!/bin/bash
# usage ./enum.sh netflix.com
# bash <(sed -n '5,$p' enum.sh)
# All tools need to be launched from Desktop

domain=$1
name=$(echo $domain | cut -d "." -f1)
SECONDS=0


# Check if a folder already exist
if [ -d "data/$1" ]; then
  echo "$(tput setaf 1)
========================================================================
          WARNING:/$1 EXISTS! CONTINUE AND OVERWRITE?
========================================================================
$(tput sgr0)"
read -p "Proceed? (Y/N) "
  if [[ ! $REPLY =~ ^[Yy]$ ]]
      then [[ "$0" = "$BASH_SOURCE" ]] &&
      echo "exit process" && exit 1 || return 1 # handle exits from shell or function but don't exit interactive shell
  fi
	rm -rf data/$1 && mkdir data/$1
else
	echo "[+] Creating a new folder for $1"
	mkdir data/$1
fi

echo -e "\e[32m[*] Findomain enum on $1 \e[0m"
time ./findomain-linux -t $domain -i -o && mv $domain.txt data/$domain/ #> /dev/null 2>&1 &
mv data/$domain/$domain.txt data/$domain/findomain.txt
cat data/$domain/findomain.txt | cut -d "," -f1 | sort -u > data/$domain/domains.txt
cat data/$domain/findomain.txt | cut -d "," -f2 | sort -u > data/$domain/findomain_ip.txt

echo -e "\e[32m[*] Amass passive enum on $1 \e[0m"
time ./amass enum --passive -d $1 -do data/$domain/amass.txt

echo -e "\e[32m[*] Massdns bruteforce on $1 \e[0m"
time ./massdns/scripts/subbrute.py massdns/lists/brutesub.txt $1 | ./massdns/bin/massdns -r massdns/lists/validated.txt -t A -o S -w data/$1/$1_mdns.txt # > /dev/null 2>&1 &
#time ./massdns/scripts/subbrute.py massdns/lists/allsmall.txt $1 | ./massdns/bin/massdns -r massdns/lists/validated.txt -t A -o S -w data/$1/$1_mdns.txt  > /dev/null 2>&1 &
#./massdns/scripts/subbrute.py massdns/lists/allsmall.txt $1 | ./massdns/bin/massdns -r massdns/lists/validated.txt -t A -o S -w data/$1/$1_mdns.txt #> /dev/null 2>&1 &
cat data/$1/$1_mdns.txt | sed 's/\s.*$//' > data/$1/massdns.txt && rm data/$1/$1_mdns.txt
cat data/$1/domains.txt data/$1/massdns.txt data/$1/amass.txt > data/$1/hosts.txt && rm data/$1/domains.txt

echo -e "\e[32m[*] Generating permutation... \e[0m"
goaltdns -l data/$1/hosts.txt -o data/$1/altdns.txt -w /root/go/src/github.com/subfinder/goaltdns/words.txt

echo -e "\e[32m[*] Massdns bruteforce on $1 based on permutation \e[0m"
./massdns/scripts/subbrute.py data/$1/altdns.txt $1 | ./massdns/bin/massdns -r massdns/lists/validated.txt -t A -o S -w data/$1/$1_mdns.txt #> /dev/null 2>&1 &
cat data/$1/$1_mdns.txt | sed 's/\s.*$//' > data/$1/massdns_permutation.txt && rm data/$1/$1_mdns.txt
cat data/$1/massdns_permutation.txt >> data/$1/hosts.txt

echo -e "\e[32m[*] Resolving...\e[0m"
./massdns/bin/massdns -r massdns/lists/validated.txt -t A -o S data/$1/hosts.txt -w data/$1/livehosts.txt #> /dev/null 2>&1 &
sed 's/A.*//' data/$1/livehosts.txt | sed 's/CN.*//' | sed 's/\..$//' | sort -u > data/$1/subdomains.txt
rm data/$1/livehosts.txt
cat subdomains.txt | httprobe > https.txt

echo -e "\e[32m[*] Cleaning up ...\e[0m"
#remove altdns and other files than subdomains.txt
# maybe store in another folder

duration=$SECONDS
echo -e "\e[31m[*] $(($duration / 60)) minutes and $(($duration % 60)) seconds elapsed.\e[0m"
