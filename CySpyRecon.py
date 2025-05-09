import requests
import dns.resolver
import socket
from urllib.parse import urlparse
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def clean_domain_input(user_input):
    parsed = urlparse(user_input if '://' in user_input else 'http://' + user_input)
    domain = parsed.netloc or parsed.path
    return domain.replace("www.", "").strip().lower()

def resolve_domain_to_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        print(f"[!] Could not resolve IP: {e}")
        return None

def check_multiple_ips(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        ttl = result.rrset.ttl
        ips = [ip.address for ip in result]

        print(f"\n{Fore.YELLOW}[+] Resolved IPs: {', '.join(ips)}")
        print(f"{Fore.YELLOW}[+] TTL (Time To Live): {ttl} seconds")

        if len(ips) > 1:
            print(f"{Fore.YELLOW}[~] Multiple IPs detected — possible DNS-based load balancing")
        if ttl < 60:
            print(f"{Fore.YELLOW}[~] TTL is very low — possible geo-based load balancing")

        return len(ips) > 1 or ttl < 60

    except Exception as e:
        print(f"[!] DNS Error: {e}")
        return False

def check_headers(domain):
    try:
        url = f"http://{domain}"
        res = requests.get(url, timeout=5)
        print(f"\n{Fore.CYAN}[+] Response Headers:")
        for k, v in res.headers.items():
            print(f"    {Fore.CYAN}{k}: {v}")

        header_keys = [k.lower() for k in res.headers.keys()]
        common_lb_headers = ['x-forwarded-for', 'x-amzn-trace-id', 'via', 'x-cache', 'cf-ray', 'server']
        if any(h in header_keys for h in common_lb_headers):
            print(f"{Fore.YELLOW}[~] Load balancer-related headers found")
            return True
    except Exception as e:
        print(f"[!] Request Error: {e}")
    return False

def check_waf(domain):
    try:
        url = f"http://{domain}"
        res = requests.get(url, timeout=5)
        headers = res.headers

        waf_signatures = {
            "Cloudflare": ["cf-ray", "server: cloudflare"],
            "AWS WAF": ["x-amzn-requestid", "x-amzn-trace-id"],
            "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
            "Akamai": ["akamai-x-cache", "akamai-cache-status"],
            "Imperva (Incapsula)": ["x-iinfo", "visid_incap", "incap_ses"],
            "F5 BIG-IP": ["x-wa-info", "bigipserver"]
        }

        detected = []
        header_string = "\n".join([f"{k.lower()}: {v.lower()}" for k, v in headers.items()])

        for waf, patterns in waf_signatures.items():
            if any(p.lower() in header_string for p in patterns):
                detected.append(waf)

        if detected:
            print(f"\n{Fore.YELLOW}[~] Detected possible WAF: {', '.join(detected)}")
            return True
        else:
            print(f"\n{Fore.RED}[~] No obvious WAF detected")
            return False

    except Exception as e:
        print(f"[!] WAF Detection Error: {e}")
        return False

def geoip_lookup(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = response.json()
        print(f"\n{Fore.GREEN}[+] GeoIP Information:")
        print(f"    IP: {data.get('ip')}")
        print(f"    City: {data.get('city')}")
        print(f"    Region: {data.get('region')}")
        print(f"    Country: {data.get('country')}")
        print(f"    Org: {data.get('org')}")
        print(f"    Location: {data.get('loc')}")
        return True
    except Exception as e:
        print(f"[!] GeoIP lookup failed: {e}")
        return False

def tech_stack_detection(domain):
    try:
        url = f"http://{domain}"
        res = requests.get(url, timeout=5)
        headers = res.headers

        print(f"\n{Fore.GREEN}[+] Technology Stack Detection:")
        server = headers.get("Server", "Unknown")
        powered_by = headers.get("X-Powered-By", "Unknown")

        print(f"    Server: {server}")
        print(f"    X-Powered-By: {powered_by}")

        if powered_by.lower().startswith("php") or "php" in powered_by.lower():
            print(f"    → Likely using PHP-based backend")
        elif "asp.net" in powered_by.lower():
            print(f"    → Likely using ASP.NET backend")
        elif "express" in powered_by.lower():
            print(f"    → Likely using Node.js Express framework")

        return True
    except Exception as e:
        print(f"[!] Tech stack detection failed: {e}")
        return False

def main():
    print(Fore.GREEN + "====== Load Balancer, WAF, GeoIP & Tech Stack Detector ======")
    user_input = input("Enter website URL or domain (e.g., https://www.example.com): ").strip()
    domain = clean_domain_input(user_input)

    print(f"\n{Fore.CYAN}[~] Scanning domain: {domain}")

    ip = resolve_domain_to_ip(domain)
    if ip:
        geoip_lookup(ip)

    print(f"\n{Fore.CYAN}[~] Checking for multiple IPs and TTL...")
    multiple_ips_or_low_ttl = check_multiple_ips(domain)

    print(f"\n{Fore.CYAN}[~] Checking HTTP headers...")
    header_result = check_headers(domain)

    print(f"\n{Fore.CYAN}[~] Checking for WAF presence...")
    waf_detected = check_waf(domain)

    print(f"\n{Fore.CYAN}[~] Detecting technology stack...")
    tech_stack_detection(domain)

    print(Fore.GREEN + "\n====== Final Verdict ======")
    print(f"{Fore.GREEN}[✔] Load Balancer Status: ", end="")
    if multiple_ips_or_low_ttl or header_result:
        print(Fore.GREEN + "Likely in use ✅")
    else:
        print(Fore.RED + "No clear signs ❌")

    print(f"{Fore.GREEN}[✔] WAF Status: ", end="")
    if waf_detected:
        print(Fore.GREEN + "WAF is present 🔒")
    else:
        print(Fore.RED + "No WAF detected ❌")

    print(f"{Fore.GREEN}[✔] Technology Stack: ", end="")
    tech_stack_detection(domain)

    print(f"{Fore.GREEN}[✔] GeoIP Info: ", end="")
    geoip_lookup(ip)

    print(f"{Fore.YELLOW}[✔] Multiple IPs / TTL: ", end="")
    check_multiple_ips(domain)

if __name__ == "__main__":
    main()
