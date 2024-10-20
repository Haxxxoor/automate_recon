import os
import nmap
import whois
import sublist3r
import requests
import json
from subprocess import Popen, PIPE

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

# Function to perform OSINT using TheHarvester (using the subprocess to call theHarvester)
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

    # Save to file
    save_results(f"{domain}_recon_results.txt", results)
    print(f"[*] Reconnaissance complete. Results saved to {domain}_recon_results.txt")

# Run the script
if __name__ == "__main__":
    target_domain = input("Enter the target domain: ")
    perform_recon(target_domain)
