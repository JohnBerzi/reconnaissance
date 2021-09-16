from colorama import Fore, Style
import datetime
import os
import sys
import getopt


date = datetime.datetime.now()
date = date.strftime('%d-%m-%y')

############## Help Output ###############
def usage():
    print("Recon Automation")
    print("Usage: recon.py <options> <domain>")
    print("")
    print("Options:")
    print("-a or --all         -----> For All Options.")
    print("-s or --subdomains  -----> For Subdomain Enumeration")
    print("-x or --screenshots -----> For Screenshot")
    print("-c or --subdomain-takeover -------> For Subdomain Takeover")
    print("-d or --date -----> For A Specific Date (Ex: -d 25-01-19)")
    sys.exit()

############# Subdomain Enumeration Functions ##############

#def sublisterScan(domain,date):
#    print(f'{Fore.CYAN}[-] Starting Sublist3r{Style.RESET_ALL}')
#    os.system(f'python3 ./Sublist3r/sublist3r.py -d {domain} -o {domain}/{date}/subdomain.txt >/dev/null')
#    print(f'{Fore.GREEN}[+] Finished Sublist3r{Style.RESET_ALL}')

def assetfinderScan(domain,date):
    print(f'{Fore.CYAN}[-] Starting assetfinder{Style.RESET_ALL}')
    os.system(f'./assetfinder {domain} >> {domain}/{date}/subdomain.txt')
    print(f'{Fore.GREEN}[+] Finished assetfinder{Style.RESET_ALL}')

########## Takes Too Much Time ############
#def altdnsScan(domain,date):
#    print(f'{Fore.CYAN}[-] Starting altdns{Style.RESET_ALL}')
#    if len(open(f'{domain}/{date}/subdomain.txt').readlines()) > 50:
#        os.system(f'head -n 50 {domain}/{date}/subdomain.txt > 50subdomains.txt')
#        os.system(f'altdns -i 50subdomains.txt -o data -w words.txt -r -s res.txt > /dev/null')
#        os.system('rm -rf 50subdomains.txt')
#    else:
#        os.system(f'altdns -i {domain}/{date}/subdomain.txt -o data -w words.txt -r -s res.txt > /dev/null')
#    os.system(f"cat ./res.txt | cut -d':' -f1 >> {domain}/{date}/subdomain.txt")
#    os.system(f'rm -rf ./data ./res.txt')
#    print(f'{Fore.GREEN}[+] Finished altdns{Style.RESET_ALL}')

def findomainScan(domain,date):
    print(f'{Fore.CYAN}[-] Starting findomain{Style.RESET_ALL}')
    os.system(f'./findomain-linux -t {domain} -o > /dev/null')
    os.system(f'cat {domain}.txt >> {domain}/{date}/subdomain.txt && rm -rf {domain}.txt')
    print(f'{Fore.GREEN}[+] Finished findomain{Style.RESET_ALL}')

def subfinderScan(domain,date):
    print(f'{Fore.CYAN}[-] Starting subfinder{Style.RESET_ALL}')
    os.system(f'./subfinder -d {domain} -o output.txt -silent > /dev/null')
    os.system(f'cat output.txt >> {domain}/{date}/subdomain.txt && rm -rf output.txt')
    print(f'{Fore.GREEN}[+] Finished subfinder{Style.RESET_ALL}')

def subscraperScan(domain,date):
    print(f'{Fore.CYAN}[-] Starting subscraper{Style.RESET_ALL}')
    os.system(f'python3 subscraper/subscraper.py {domain} -o subscraper/subscraper_report.txt > /dev/null')
    os.system(f'cat subscraper/subscraper_report.txt >> {domain}/{date}/subdomain.txt')
    print(f'{Fore.GREEN}[+] Finished subscraper{Style.RESET_ALL}')

def githubSubScan(domain,date):
    print(f'{Fore.CYAN}[-] Starting github-subdomains.py{Style.RESET_ALL}')
    os.system(f'python3 github-subdomains.py -t "41c6c6d9a046c0b1329dfbaa478f14204cef84b7" -d {domain} >> {domain}/{date}/subdomain.txt')
    print(f'{Fore.GREEN}[+] Finished github-subdomains.py{Style.RESET_ALL}') 

def amassScan(domain,date):
    print(f'{Fore.CYAN}[-] Starting amass{Style.RESET_ALL}')
    os.system(f'./amass/amass enum -norecursive -noalts -brute -d {domain} -o hosts > /dev/null 2>&1')
    os.system(f'cat hosts >> {domain}/{date}/subdomain.txt && rm -rf hosts')
    print(f'{Fore.GREEN}[+] Finished amass{Style.RESET_ALL}')
    os.system(f'sort -u {domain}/{date}/subdomain.txt | grep ".{domain}"> {domain}/{date}/subdomains.txt && rm -rf {domain}/{date}/subdomain.txt')

    ############## End Subdomain Enumeration Functions ###################



def subdomainEnumeration(domain,date):
    os.system(f'mkdir {domain}/{date}')
    print(f'{Fore.YELLOW}* Subdomain Enumeration:{Style.RESET_ALL}')
    try:
        ## Enumerating With All The Tools
        #sublisterScan(domain,date)
        assetfinderScan(domain,date)
        #altdnsScan(domain,date)
        findomainScan(domain,date)
        subfinderScan(domain,date)
        subscraperScan(domain,date)
        githubSubScan(domain,date)
        amassScan(domain,date)
    except:
        ## Exiting The Program After Any Error
        print(f'{Fore.RED}[-] Error with running Subdomain Enumration{Style.RESET_ALL}')
        sys.exit()
    
    
    

def screenshotsEnumeration(domain,date):
    ## Scanning alive hosts on port 80 and 443 using httprobe
    print(f'{Fore.YELLOW}* Scanning port 80 and 443 for all subdomains{Style.RESET_ALL}')
    os.system(f'cat {domain}/{date}/subdomains.txt | httprobe > {domain}/{date}/resolved.txt')
    print(f'{Fore.YELLOW}* Screenshotting all live hosts{Style.RESET_ALL}')
    os.system(f'mkdir {domain}/{date}/screenshots')
    ## Screenshoting All The Subdomains Found With Aquatone
    os.system(f'cat {domain}/{date}/resolved.txt | ./aquatone -out {domain}/{date}/screenshots > /dev/null')

# Port Scanning All Ports For All subdomains found
def portScanning(domain,date):
    print(f'{Fore.YELLOW}* Port scanning all subdomains{Style.RESET_ALL}')
    os.system(f'mkdir -p {domain}/{date}/portscan')
    os.system(f'for i in $(cat {domain}/{date}/subdomains.txt); do echo $i;dig "$i" +short | grep -oP "([0-9]{{1,3}}\.){{3}}[0-9]{{1,3}}";echo "=============";  done > {domain}/{date}/portscan/reverse-ip.txt')
    os.system(f'for i in $(cat {domain}/{date}/subdomains.txt); do dig "$i" +short | grep -oP "([0-9]{{1,3}}\.){{3}}[0-9]{{1,3}}" ; done > {domain}/{date}/portscan/ips.txt')
    os.system(f'cat {domain}/{date}/portscan/ips.txt | sort -u > {domain}/{date}/portscan/uniq-ips.txt && rm -rf {domain}/{date}/portscan/ips.txt')
    os.system(f'rustscan -a {domain}/{date}/subdomains.txt -r1-65535 -g >> {domain}/{date}/portscan/uniq-ips.txt')
    print(f'{Fore.GREEN}[+] Finished port scanning{Style.RESET_ALL}')

## Checking For Subdomain Takeover On ALL The Subdomains 
def subdomainTakeover(domain,date):
    print(f'{Fore.YELLOW}* Checking For Subdomain Takeover{Style.RESET_ALL}')
    os.system(f'python3 subscraper/subscraper.py --takeover {domain}/{date}/subdomains.txt > x.txt')
    os.system(f'cat x.txt | sed 1,9d > {domain}/{date}/subdomain-takeover.txt && rm -rf x.txt')
    print(f'{Fore.GREEN}[+] Finished Checking For Subdomain Takeover{Style.RESET_ALL}')

def main():
    global date
    subdomainsEnum = False
    screenshotsEnum = False
    portScan = False
    subdomainTake = False

    ## Making The Main Directory With Domain Name
    if sys.argv[-1] == '-h' or sys.argv[-1] == '--help':
        pass
    else:
        os.system(f'mkdir -p ./{sys.argv[-1]}')
    
    opts , args = getopt.getopt(sys.argv[1:],"hasxpcd:", ["help","all","subdomains","screenshots","portscan","subdomain-takeover","date="])
    for o,a in opts :
        if o in ('-d', '--date'):
            date = a
            print("This is date: " + a)
        if o in ('-h', '--help'):
            usage() 
        elif o in ('-a', '--all'):
            subdomainsEnum = True
            screenshotsEnum = True
            portScan = True
            subdomainTake = True
        elif o in ('-s','--subdomains'):
            subdomainsEnum = True
        elif o in ('-x','--screenshots'):
            screenshotsEnum = True
        elif o in ('-p', '--portscan'):
            portScan = True
        elif o in ('-c', '--subdomain-takeover'):
            subdomainTake = True

    if subdomainsEnum:
        subdomainEnumeration(sys.argv[-1],date)
    if screenshotsEnum:
        try:
            screenshotsEnumeration(sys.argv[-1],date)
        except:
            print(f'{Fore.RED}[-] Error with Screenshots function{Style.RESET_ALL}')
    if subdomainTake:
        try:
            subdomainTakeover(sys.argv[-1],date)
        except Exception as e:
            print(f'{Fore.RED}[-] Error with Subdomain Takeover function{Style.RESET_ALL}')
            print(f'Error: {e}')
    if portScan:
        try:
            portScanning(sys.argv[-1],date)
        except:
            print(f'{Fore.RED}[-] Error with Port Scanning function{Style.RESET_ALL}')
main()









