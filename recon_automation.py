import os
import nmap
import whois
import sublist3r
import requests
import json
from subprocess import Popen, PIPE
import shodan
from censys.search import CensysHosts
from censys.common.exceptions import CensysException
from virus_total_apis import PublicApi as VirusTotalPublicApi

# API keys
SHODAN_API_KEY = 'your_shodan_api_key'
VIRUSTOTAL_API_KEY = 'your_virustotal_api_key'
CENSYS_API_ID = 'your_censys_api_id'
CENSYS_API_SECRET = 'your_censys_api_secret'

# Function to perform WHOIS Lookup
def whois_lookup(domain):
    print(f"[*] Performing WHOIS lookup for {domain}")
    try:
        whois_info = whois.whois(domain)
        return whois_info
    except Exception as e:
        return f"WHOIS lookup failed: {str(e)}"

# Function to perform DNS enumeration using Sublist3r
def subdomain_enumeration(domain):
    print(f"[*] Enumerating subdomains for {domain}")
    subdomains = sublist3r.main(domain, 40, None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
    return subdomains

# Function to perform Nmap scan
def nmap_scan(target):
    print(f"[*] Scanning target {target} with Nmap")
    nm = nmap.PortScanner()
    nm.scan(target, '1-65535', '-sV -O')  # Scanning all ports with version detection and OS detection
    return nm[target] if target in nm.all_hosts() else None

# Function to detect web technologies using WhatWeb
def detect_web_technologies(domain):
    print(f"[*] Detecting web technologies for {domain}")
    try:
        response = Popen(['whatweb', domain], stdout=PIPE, stderr=PIPE)
        output, error = response.communicate()
        if output:
            return output.decode('utf-8').strip()
        if error:
            return error.decode('utf-8').strip()
    except Exception as e:
        return f"Web technology detection failed: {str(e)}"

# Function to perform OSINT using TheHarvester (using subprocess to call theHarvester)
def osint_gathering(domain):
    print(f"[*] Gathering OSINT data for {domain} using theHarvester")
    try:
        response = Popen(['theHarvester', '-d', domain, '-b', 'all'], stdout=PIPE, stderr=PIPE)
        output, error = response.communicate()
        if output:
            return output.decode('utf-8').strip()
        if error:
            return error.decode('utf-8').strip()
    except Exception as e:
        return f"OSINT gathering failed: {str(e)}"

# Shodan IoT Device Reconnaissance
def shodan_scan(target):
    print(f"[*] Scanning for IoT devices with Shodan for {target}")
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(target)
        return json.dumps(host, indent=4)
    except Exception as e:
        return f"Shodan scan failed: {str(e)}"

# VirusTotal domain analysis
def virustotal_scan(domain):
    print(f"[*] Performing VirusTotal domain analysis for {domain}")
    try:
        vt = VirusTotalPublicApi(VIRUSTOTAL_API_KEY)
        response = vt.get_domain_report(domain)
        return json.dumps(response['results'], indent=4)
    except Exception as e:
        return f"VirusTotal scan failed: {str(e)}"

# Censys for discovering services and certificates
def censys_scan(target):
    print(f"[*] Performing Censys scan for {target}")
    try:
        c = CensysHosts(api_id=CENSYS_API_ID, api_secret=CENSYS_API_SECRET)
        search_results = c.search(target)
        return json.dumps(search_results, indent=4)
    except CensysException as e:
        return f"Censys scan failed: {str(e)}"

# Function to save the results to a file
def save_results(filename, content):
    print(f"[*] Saving results to {filename}")
    with open(filename, 'w') as f:
        f.write(content)

# Main reconnaissance function
def perform_recon(domain):
    results = ""

    # 1. WHOIS Lookup
    whois_info = whois_lookup(domain)
    results += f"\n### WHOIS Information ###\n{whois_info}\n"

    # 2. Subdomain Enumeration
    subdomains = subdomain_enumeration(domain)
    results += f"\n### Subdomain Enumeration ###\n" + "\n".join(subdomains) + "\n"

    # 3. Nmap Port Scanning
    nmap_results = nmap_scan(domain)
    if nmap_results:
        results += "\n### Nmap Scan Results ###\n"
        for protocol in nmap_results.all_protocols():
            results += f"\nProtocol: {protocol}\n"
            ports = nmap_results[protocol].keys()
            for port in ports:
                state = nmap_results[protocol][port]['state']
                service = nmap_results[protocol][port]['name']
                results += f"Port {port}/{protocol} is {state} (Service: {service})\n"

    # 4. Web Technologies Detection
    web_tech = detect_web_technologies(domain)
    results += f"\n### Web Technologies ###\n{web_tech}\n"

    # 5. OSINT Gathering
    osint_results = osint_gathering(domain)
    results += f"\n### OSINT Results ###\n{osint_results}\n"

    # 6. Shodan IoT Device Reconnaissance
    shodan_results = shodan_scan(domain)
    results += f"\n### Shodan IoT Device Scan ###\n{shodan_results}\n"

    # 7. VirusTotal Domain Analysis
    vt_results = virustotal_scan(domain)
    results += f"\n### VirusTotal Scan ###\n{vt_results}\n"

    # 8. Censys for Services and Certificates
    censys_results = censys_scan(domain)
    results += f"\n### Censys Scan ###\n{censys_results}\n"

    # Save to file
    save_results(f"{domain}_recon_results.txt", results)
    print(f"[*] Reconnaissance complete. Results saved to {domain}_recon_results.txt")

# Run the script
if __name__ == "__main__":
    target_domain = input("Enter the target domain or IP: ")
    perform_recon(target_domain)
