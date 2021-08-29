#!/bin/bash

apt install python3-pip -y

# Installing Sublist3r
git clone https://github.com/aboul3la/Sublist3r.git
python3 -m pip install -r Sublist3r/requirements.txt
sed -i "s/query(host/resolve(host/g" ./Sublist3r/sublist3r.py
sed -i "s/csrf_regex.findall(resp)[0]/csrf_regex.search(resp).group(0)/g"

# Installing Altdns
apt install altdns -y

# Installing Assetfinder
wget https://github.com/tomnomnom/assetfinder/releases/download/v0.1.0/assetfinder-linux-amd64-0.1.0.tgz
tar -xvf assetfinder-linux-amd64-0.1.0.tgz 
rm -rf assetfinder-linux-amd64-0.1.0.tgz

# Installing Findomain
wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux
chmod +x findomain-linux 
# METHOD 2:
#apt install cargo
#git clone https://github.com/Edu4rdSHL/findomain.git
#cd findomain
#cargo build --release
#sudo cp target/release/findomain ../findomain-linux
#cd .. && rm -rf findomain

# Installing Subfinder
wget https://github.com/projectdiscovery/subfinder/releases/download/v2.4.5/subfinder_2.4.5_linux_amd64.tar.gz
tar -xvf subfinder_2.4.5_linux_amd64.tar.gz > /dev/null
rm -rf subfinder_2.4.5_linux_amd64.tar.gz README.md LICENSE.md
sed -i "s/query(host/resolve(host/g" Sublist3r/sublist3r.py

# Installing Github-subdomain
wget https://raw.githubusercontent.com/gwen001/github-search/master/github-subdomains.py
python3 -m pip install colored
python3 -m pip install tldextract

# Installing Amass
wget https://github.com/OWASP/Amass/releases/download/v3.10.5/amass_linux_amd64.zip
unzip amass_linux_amd64.zip && rm -rf amass_linux_amd64.zip
mv amass_linux_amd64 amass

# Adding Golang Environmental Variables
apt install golang 
export GOPATH=$HOME/go 
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin

# Installing Httprobe
git clone https://github.com/tomnomnom/httprobe.git
cd httprobe 
go build
mv httprobe /usr/bin
cd .. 
rm -rf httprobe
#METHOD 2 : go get -u github.com/tomnomnom/httprobe 

# Installing Aquatone
apt install chromium -y
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip 
rm -rf aquatone_linux_amd64_1.7.0.zip

# Installing Rustscan
wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb
dpkg -i rustscan_2.0.1_amd64.deb 
rm -rf rustscan_2.0.1_amd64.deb

# Installing Subscraper
git clone https://github.com/m8r0wn/subscraper
python3 -m pip install bs4
python3 -m pip install -r subscraper/requirements.txt

rm -rf LICENSE.txt README.txt
