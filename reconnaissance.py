#!/usr/bin/env python3

import argparse
import os
import subprocess
import sys
from pathlib import Path

def run_command(command):
    try:
        subprocess.run(command,shell=True)
    except subprocess.CalledProcessError:
        print(f"[!] Command failed: {command}")

def main():
    parser = argparse.ArgumentParser(description="Recon automation tool")

    parser.add_argument("domain", help="Target domain")
    parser.add_argument("-s", "--subfinder", action="store_true", help="Run Subfinder")
    parser.add_argument("-f", "--findomain", action="store_true", help="Run Findomain")
    parser.add_argument("-a", "--assetfinder", action="store_true", help="Run Assetfinder")
 #   parser.add_argument("-m", "--amass", action="store_true", help="Run Amass (passive)")
    parser.add_argument("-x", "--httprobe", action="store_true", help="Run httprobe")
    parser.add_argument("-q", "--aquatone", action="store_true", help="Run Aquatone")
    parser.add_argument("-r", "--rustscan", action="store_true", help="Run RustScan")
    parser.add_argument("-S", "--smap", action="store_true", help="Run Smap (full port scan)")
    parser.add_argument("-u", "--ffuf", action="store_true", help="Run ffuf")
    parser.add_argument("-b", "--waybackurls", action="store_true", help="Run waybackurls")
    parser.add_argument("-A", "--all", action="store_true", help="Run all tools")
    parser.add_argument("--passive", action="store_true", help="Run only passive tools")
    parser.add_argument("-w", "--wordlist", help="Wordlist for ffuf (necessary with -u or -A)")

    args = parser.parse_args()

    # Set all tools if -A or --all is used
    if args.all:
        args.subfinder = args.findomain = args.assetfinder = args.httprobe = True
        args.aquatone = args.rustscan = args.smap = args.ffuf = args.waybackurls = True
#	args.amass = True

    # Passive mode (subset of tools)
    if args.passive:
        args.subfinder = args.findomain = args.assetfinder = args.httprobe = True
        args.aquatone = args.waybackurls = args.smap = True
        args.rustscan = args.ffuf = False
#	args.amass = True

    if args.ffuf and not args.wordlist:
        print("[!] -w/--wordlist is required when using -u/--ffuf")
        sys.exit(1)

    output_dir = Path(f"{args.domain}")
    output_dir.mkdir(exist_ok=True)

    print(f"[*] Starting recon for {args.domain}...")

    if args.assetfinder:
        print("[*] Running Assetfinder...")
        run_command(f"assetfinder --subs-only {args.domain} > {output_dir}/assetfinder.txt")

    if args.subfinder:
        print("[*] Running Subfinder...")
        run_command(f"subfinder -silent -d {args.domain} > {output_dir}/subfinder.txt")

    if args.findomain:
        print("[*] Running Findomain...")
        run_command(f"findomain -t {args.domain} -q > {output_dir}/'findomain.txt'")
# BROKEN FOR NOW!!
 #   if args.amass:
 #       print("[*] Running Amass (passive)...")
 #       run_command(f"amass enum -passive -d {args.domain} -o {output_dir / 'amass.txt'}", None, error_log)

    if any([args.subfinder, args.findomain, args.assetfinder]):
        print("[*] Merging results...")
        combined = output_dir / "all_subdomains.txt"
        sub_files = list(output_dir.glob("*.txt"))
        subdomains = set()
        for file in sub_files:
            with file.open() as f:
                for line in f:
                    subdomains.add(line.strip())
        with combined.open("w") as f:
            f.write("\n".join(sorted(subdomains)))

    live_file = output_dir / "live_subdomains.txt"
    if args.httprobe:
        print("[*] Probing live subdomains with httprobe...")
        run_command(f"cat {output_dir / 'all_subdomains.txt'} | sort -u | httprobe > {live_file}")

    if args.aquatone:
        print("[*] Running Aquatone...")
        aquatone_dir = output_dir / "aquatone_report"
        run_command(f"mkdir -p {aquatone_dir}")
        run_command(f"cat {live_file} | aquatone -out {aquatone_dir}")
        print(f"[+] Aquatone report saved at {aquatone_dir}/aquatone_report.html")

    if args.waybackurls:
        print("[*] Running waybackurls...")
        wayback_out = output_dir / "waybackurls_results"
        wayback_out.mkdir(exist_ok=True)
        with open(live_file) as f:
            for url in f:
                url = url.strip()
                domain = url.replace("https://", "").replace("http://", "").strip("/")
                out_file = wayback_out / f"{domain}.txt"
                paths_file = wayback_out / f"{domain}_paths.txt"
                print(f"[*] Fetching wayback URLs for {url}")
                run_command(f"echo {url} | waybackurls > {out_file}")
                with open(out_file) as inf, open(paths_file, "w") as outf:
                    paths = {line.split(domain)[-1] for line in inf if domain in line}
                    outf.write("\n".join(sorted(paths)))

    if args.rustscan:
        print("[*] Running RustScan...")
        rustscan_dir = output_dir / "rustscan_results"
        rustscan_dir.mkdir(exist_ok=True)
        with open(live_file) as f:
            for url in f:
                target = url.strip()
                out_file = rustscan_dir / f"{target.replace('https://', '').replace('http://', '').strip('/')}.txt"
                run_command(f"rustscan -a {target} --ulimit 5000 -- -sS -Pn -n -T4 -oN {out_file}")

    if args.smap:
        print("[*] Running Smap...")
        smap_dir = output_dir / "smap_results"
        smap_dir.mkdir(exist_ok=True)
        input_file = output_dir/'all_subdomains.txt'
        output_file = output_dir / "smap_results" / "smap_results.txt"
        run_command(f"smap -iL {input_file} -oN {output_file}")


    if args.ffuf:
        print("[*] Starting ffuf directory fuzzing...")
        ffuf_dir = output_dir / "ffuf_results"
        ffuf_dir.mkdir(exist_ok=True)
        with open(live_file) as f:
            for url in f:
                url = url.strip()
                host = url.replace("https://", "").replace("http://", "").strip("/")
                print(f"[*] Fuzzing {url}")
                run_command(f"ffuf -w {args.wordlist} -u {url}/FUZZ -o {ffuf_dir / f'{host}.json'} -of json -t 50 -mc all")



    total_subs = sum(1 for _ in open(output_dir / "all_subdomains.txt")) if (output_dir / "all_subdomains.txt").exists() else 0
    live_subs = sum(1 for _ in open(live_file)) if live_file.exists() else 0

    print("\n=======, ffuf_dir, error_log============= Recon Summary ====================")
    print(f"Total Unique Subdomains : {total_subs}")
    print(f"Live Subdomains         : {live_subs}")
    print(f"Output Directory        : {output_dir}/")
    if args.waybackurls:
        print(f"Waybackurls Output      : {output_dir}/waybackurls_results/")
    if args.aquatone:
        print(f"Aquatone Report         : {output_dir}/aquatone_report/aquatone_report.html")
    print("========================================================")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[!] Script interrupted.")
        sys.exit(1)
