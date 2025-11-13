import json
import sys
import time
import globals
from colorama import Fore, Style

def print_report(start_time, end_time):
    duration = end_time - start_time
    success_rate = (globals.results['success'] / (globals.results['success'] + globals.results['fail'])) * 100 if (globals.results['success'] + globals.results['fail']) > 0 else 0
    print(f"\n{Fore.CYAN}====== {Style.BRIGHT}Layer 7 Stress Test Report{Style.RESET_ALL} ======\n")
    print(f"{Fore.YELLOW}Duration:{Style.RESET_ALL} {time.strftime('%H:%M:%S', time.gmtime(duration))}")
    print(f"{Fore.YELLOW}Total Requests:{Style.RESET_ALL} {globals.results['success'] + globals.results['fail']}")
    print(f"{Fore.YELLOW}Success Rate:{Style.RESET_ALL} {success_rate:.2f}%")
    print(f"{Fore.YELLOW}Success:{Style.RESET_ALL} {globals.results['success']}")
    print(f"{Fore.YELLOW}Fail:{Style.RESET_ALL} {globals.results['fail']}")
    print(f"{Fore.YELLOW}Packets Sent:{Style.RESET_ALL} {globals.results['packets_sent']}")
    print(f"{Fore.YELLOW}Bytes Sent:{Style.RESET_ALL} {globals.results['bytes_sent']} bytes")
    print(f"{Fore.YELLOW}Details:{Style.RESET_ALL}")
    for url, details in globals.results['details'].items():
        print(f"  {Fore.GREEN}{url}{Style.RESET_ALL}: {Fore.YELLOW}{details['status_code']}{Style.RESET_ALL} ({Fore.YELLOW}{details['response_time']:.2f}{Style.RESET_ALL} ms)")
    print("===============================================\n")

def print_dns_check_report():
    print(f"\n{Fore.CYAN}====== {Style.BRIGHT}DNS Check Report{Style.RESET_ALL} ======\n")
    for ip, details in globals.resolved_ip_details.items():
        print(f"{Fore.YELLOW}{ip}{Style.RESET_ALL}: {Fore.GREEN}{details.get('country', 'N/A')}{Style.RESET_ALL}, {Fore.GREEN}{details.get('city', 'N/A')}{Style.RESET_ALL}, {Fore.GREEN}{details.get('isp', 'N/A')}{Style.RESET_ALL}, {Fore.GREEN}{details.get('as', 'N/A')}{Style.RESET_ALL}, {Fore.GREEN}{details.get('ptr', 'N/A')}{Style.RESET_ALL}")
    print("===============================================\n")

def print_analysis_report(hostname, findings):
    print(f"\n{Fore.CYAN}====== {Style.BRIGHT}Analysis Report for {hostname}{Style.RESET_ALL} ======\n")
    print(f"{Fore.YELLOW}CNAME:{Style.RESET_ALL} {Fore.GREEN}{findings.get('cname', 'N/A')}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}A Records:{Style.RESET_ALL} {Fore.GREEN}{', '.join(findings['a_records'])}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}NS Records:{Style.RESET_ALL} {Fore.GREEN}{', '.join(findings['ns_records'])}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}CDN Provider:{Style.RESET_ALL} {Fore.GREEN}{findings['cdn_provider']}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Detection Reason:{Style.RESET_ALL} {Fore.GREEN}{findings['detection_reason']}{Style.RESET_ALL}")
    print("===============================================\n")

def export_dns_report(output_file):
    with open(output_file, 'w') as f:
        json.dump(globals.resolved_ip_details, f, indent=4)
    print(f"{Fore.GREEN}DNS report exported to {output_file}{Style.RESET_ALL}\n")

def print_origin_report(hostname):
    print(f"\n{Fore.CYAN}====== {Style.BRIGHT}Origin Server Report for {hostname}{Style.RESET_ALL} ======\n")
    if globals.origin_results['cdn_ips']:
        print(f"{Fore.YELLOW}CDN IPs:{Style.RESET_ALL} {Fore.GREEN}{', '.join(globals.origin_results['cdn_ips'])}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}CDN IPs:{Style.RESET_ALL} {Fore.GREEN}N/A{Style.RESET_ALL}")
    if globals.origin_results['methods']:
        print(f"{Fore.YELLOW}Methods Tried:{Style.RESET_ALL} {Fore.GREEN}{', '.join(globals.origin_results['methods'].keys())}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}Methods Tried:{Style.RESET_ALL} {Fore.GREEN}N/A{Style.RESET_ALL}")
    print("===============================================\n")

def print_flood_report(start_time, end_time):
    duration = end_time - start_time
    print(f"\n{Fore.CYAN}====== {Style.BRIGHT}Layer 3/4 Flood Attack Report{Style.RESET_ALL} ======\n")
    print(f"{Fore.YELLOW}Duration:{Style.RESET_ALL} {time.strftime('%H:%M:%S', time.gmtime(duration))}")
    print(f"{Fore.YELLOW}Packets Sent:{Style.RESET_ALL} {globals.results['packets_sent']}")
    print(f"{Fore.YELLOW}Bytes Sent:{Style.RESET_ALL} {globals.results['bytes_sent']} bytes")
    print("===============================================\n")
