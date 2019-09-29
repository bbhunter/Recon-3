#!/bin/bash
# usage ./enum.sh netflix.com
# bash <(sed -n '5,$p' enum.sh)
# All tools need to be launched from Desktop

domain=$1
name=$(echo $domain | cut -d "." -f1)
SECONDS=0

# TO DO
  # no need to put $1 in output files cause are in folder with the same name
  # add a shortcut for path as /root/Desktop/Recon
      # add also paths for wordlist and data folders

# run massdns
# service detection and folder creation
# vulnchecker from nmap

echo -e "\e[32m[*] Converting host name to ip addresses... \e[0m"
cat data/$1/alive.txt | while read domain; do
    IP=$(dig +short "$domain"|grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"|head -1)
    echo "$IP"
done < data/$1/alive.txt > data/$1/tmp.txt
cat data/$1/tmp.txt | sed '/^\s*$/d' | uniq | awk '!seen[$0]++' > data/$1/ip.txt && rm data/$1/tmp.txt

#check for entire ips route e.g
#netflix.com.		60	IN	A	54.171.27.14
#netflix.com.		60	IN	A	52.208.135.54
#netflix.com.		60	IN	A	52.31.145.183
#netflix.com.		60	IN	A	52.209.79.186
#netflix.com.		60	IN	A	54.76.161.146
#netflix.com.		60	IN	A	52.30.128.237
#netflix.com.		60	IN	A	54.229.249.97
#netflix.com.		60	IN	A	52.209.224.161

echo -e "\e[32m[*] Checking the entire route ... \e[0m"
cat data/$1/alive.txt | while read domain; do
    IPs=$(dig $domain | grep "$domain\." | awk '{print $5}')
    echo "We found the following IP addresses $IPs associated to the $domain domain"
    echo "$IPs"
done < data/$1/alive.txt > data/$1/tmp2.txt

echo -e "\e[32m[*] Adding extra ip's to expand scope ... \e[0m"
cat data/$1/tmp2.txt | sed '/^\s*$/d' | uniq | awk '!seen[$0]++' | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" >> data/$1/ip.txt && data/$1/rm tmp2.txt

#implement EDGE EXPANSION MIRRORING
#explore the rest of the ranges and It also identified new potentially related domains based on the reverse lookups of this network space
#scan a list of in-scope hosts/networks and any subdomains that resolve to any of the in-scope IPs
#nmap $1 -n -sP | grep report | awk '{print $5}'
#./livehosts.sh 192.168.1.1/24
#nmap -sP 104.200.23.*

echo -e "\e[32m[*] Implement edge expansion based on ASN ... \e[0m"
# code is not clear, do loop can be togheter and to many files are written
# file need asn and alive_from_asn

./amass intel -org $name -o data/$1/$1_asn.txt

cat data/$1/findomain_ip.txt | while read findomain_ip; do
    echo -e "\e[31m[*] Extract ASN from already found ip ... \e[0m"
    whois -h whois.cymru.com $findomain_ip | awk '{print $1}' | tail -1 >> data/$1/$1_asn.txt
done

cat data/$1/$1_asn.txt | cut -d "," -f1 | while read asn; do
    echo -e "\e[31m[*] Extract IP from ASN ... \e[0m"
    whois -h whois.radb.net -- '-i origin $asn' | grep -Eo "([0-9.]+){4}/[0-9]+" > data/$1/$1_asn_ip.txt
done

cat data/$1/$1_asn_ip.txt | while read ip; do
    echo -e "\e[31m[*] Ping ASN ranges to found hosts alive ... \e[0m"
    nmap -T5 -sP $ip | grep -Eo "([0-9.]+){4}/[0-9]+" > data/$1/$1_alive_from_asn.txt
done

cat $1_alive_from_asn.txt data/$1/findomain_ip.txt > data/$1/ip.txt


duration=$SECONDS
echo -e "\e[31m[*] $(($duration / 60)) minutes and $(($duration % 60)) seconds elapsed.\e[0m"

exit

# Retrieves all IP addresses associated to the given domain
echo -e "\e[32m[*] Running Masscan... \e[0m"
#miss route and programs ...
masscan -p1-65535 -iL ip.txt --max-rate 10000 -oG output.txt
cat output.txt | sed '/^#/ d' > masscan_output.txt #&& rm output.txt


cat masscan_output.txt | awk '{print $2}' > p1.txt
cat masscan_output.txt | awk '{print $5}' | grep -Eo '[0-9]{1,4}' > p2.txt

#https://stackoverflow.com/questions/18602234/sed-to-remove-everything-after-in-file-using-command
awk '
#    NR==FNR {a[NR]=$0; next}
#    {
#        split(a[FNR],b,".");
#        printf "%s\t%s_%s_%s\n", a[FNR], $1, $2, b[1]
#    }
#' p1.txt p2.txt > p3.txt
cat p3.txt | sed 's/[_].*$//' > ipport.txt
rm p1.txt p2.txt p3.txt

#Splitting masscan output to have as results a file with host: tab ports:
#https://stackoverflow.com/questions/24028505/how-to-clean-up-masscan-output-og
echo -e "\e[32m[*] Preparing data for nmap service detection... \e[0m"
sort -u -o masscan_output.txt masscan_output.txt
awk -F' +|/' '
  !/\s*#/ {    # ignore comment lines
      # Add the port on the current line to the associative array
      # element for the IP address on the current line.
    ips[$2] = ips[$2] (ips[$2] == "" ? $4 : ", " $4)
  }
  END {
      # Enumerate all IPs and the ports for each.
      # Since the IPs will be listed in no specific order, the output
      # is piped as a _single_ line to "sort" in order to sort by IP address,
      # and then expanded into 2 lines via "tr".
    for (ip in ips) {
      printf "Host: %s@Ports: %s@\n", ip, ips[ip] | \
        "sort -t. -n -k 1.6,1 -k 2,2 -k 3,3 -k 4,4 | tr @ \"\n\""
    }
  }
  ' masscan_output.txt > p.txt
cat p.txt | sed 's/[[:blank:]]//g' | sed '/^\s*$/d' | awk 'ORS=NR%2?" ":"\n"' | sed 's/\<Host\>//g' | sed 's/\<Ports\>//g' | sed s/://g > ipport.txt && rm p.txt

# need to change ip if firewall like akamai is detected
echo -e "\e[32m[*] Running Nmap service detection for open ports... \e[0m"
mkdir results
cat ipport.txt | while read line; do
    duration=$SECONDS
    IP=$(echo "$line" | awk '{print $1}')
    PORT=$(echo "$line" | awk '{print $2}')
    mkdir ./results/"$IP"
    nmap -sV -sT -Pn -n -T3 -p $PORT -oA ./results/"$IP"/"$IP"_tcp $IP > /dev/null 2>&1;
    #Blind UDP nmap scan of common ports, as masscan does not support UDP
    #nmap -sV --version-intensity 7 -sU -O --min-rate 15000 --max-rate 25000 --min-hostgroup 200  --max-retries=2 -Pn -n -T4 -p 53,161,500 -oA ./results/"$IP"/"$IP"_udp $IP > /dev/null 2>&1;
    echo -e "\e[31m[*] $(($duration / 60)) minutes and $(($duration % 60)) seconds elapsed. Scanned: "$IP".\e[0m"
done < ipport.txt


duration=$SECONDS
echo -e "\e[31m[*] $(($duration / 60)) minutes and $(($duration % 60)) seconds elapsed.\e[0m"
