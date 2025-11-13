import requests
import random
import asyncio
import aiohttp
import json
import ssl
import re
import sys
import socket
import time
from urllib.parse import urlparse
import globals

try:
    import dns.resolver
    import dns.reversename
    from bs4 import BeautifulSoup
except ImportError:
    print("Error: Required libraries are missing. Please run:")
    print("pip install dnspython beautifulsoup4 lxml")
    sys.exit(1)

CDN_SIGNATURES = {
    'Cloudflare': {
        'headers': {'server': ['cloudflare'], 'specific': ['__cfduid', 'cf-ray', 'cf-cache-status']},
        'cnames': ['cloudflare.net'], 'ns': ['cloudflare.com'], 'asns': ['AS13335']
    },
    'ArvanCloud': {
        'headers': {'server': ['ArvanCloud'], 'specific': ['x-ar-cache', 'ar-ray']},
        'cnames': ['arvancloud.com', 'arvancdn.com'], 'ns': ['arvancloud.ir'], 'asns': ['AS205104', 'AS58224']
    },
    'Amazon Web Services (AWS)': {
        'headers': {'server': ['awselb', 's3', 'CloudFront']},
        'cnames': ['amazonaws.com', 'cloudfront.net'], 'ns': ['awsdns'], 'asns': ['AS16509', 'AS14618']
    },
    'Google Cloud': {
        'headers': {'server': ['gws', 'gse'], 'specific': ['via']},
        'cnames': [], 'ns': ['google.com'], 'asns': ['AS15169', 'AS396982']
    },
    'Akamai': {
        'headers': {'specific': ['x-akamai-transformed', 'x-cache']},
        'cnames': ['akamai.net', 'akamaiedge.net'], 'ns': ['akam.net', 'akamai.net'], 'asns': ['AS20940', 'AS16625']
    },
    'Fastly': {
        'headers': {'specific': ['x-served-by', 'x-cache']},
        'cnames': [], 'ns': [], 'asns': ['AS54113']
    },
    'KeyCDN': {
        'headers': {'server': ['keycdn-engine'], 'specific': ['x-pull']},
        'cnames': ['keycdn.com'], 'ns': [], 'asns': ['AS51065']
    },
    'StackPath (MaxCDN)': {
        'headers': {'server': ['NetDNA-cache']},
        'cnames': ['stackpathcdn.com', 'netdna-cdn.com'], 'ns': [], 'asns': ['AS21828']
    },
    'BunnyCDN': {
        'headers': {'server': ['BunnyCDN']},
        'cnames': ['b-cdn.net'], 'ns': [], 'asns': ['AS204733']
    },
    'CDN77': {
        'headers': {'server': ['CDN77']},
        'cnames': ['cdn77.org', 'cdn77.net'], 'ns': [], 'asns': ['AS60068']
    },
    'Imperva (Incapsula)': {
        'headers': {'specific': ['x-iinfo', 'x-cdn']},
        'cnames': [], 'ns': [], 'asns': ['AS19551']
    },
    'CacheFly': {
        'headers': {}, 'cnames': ['cachefly.net'], 'ns': [], 'asns': ['AS30081']
    },
    'Microsoft Azure CDN': {
        'headers': {'server': ['Microsoft-IIS'], 'specific': ['x-cdn']},
        'cnames': ['azureedge.net'], 'ns': [], 'asns': ['AS8075']
    },
    'Edgecast (Verizon Media)': {
        'headers': {'server': ['ECS']},
        'cnames': ['edgecastcdn.net'], 'ns': [], 'asns': ['AS15133']
    },
    'Limelight Networks': {
        'headers': {'server': ['LLNW']},
        'cnames': ['llnwd.net'], 'ns': [], 'asns': ['AS22822']
    },
    'OVH CDN': {
        'headers': {'specific': ['x-cache']},
        'cnames': ['ovh.com'], 'ns': [], 'asns': ['AS16276']
    },
    'Leaseweb CDN': {
        'headers': {}, 'cnames': ['lswcdn.net'], 'ns': [], 'asns': ['AS60781']
    },
    'Gcore': {
        'headers': {'server': ['G-Core']},
        'cnames': [], 'ns': ['gcore.com'], 'asns': ['AS199524']
    },
    'BelugaCDN': {
        'headers': {'server': ['BelugaCDN']},
        'cnames': [], 'ns': [], 'asns': ['AS200074']
    },
    'CDNify': {
        'headers': {'server': ['CDNify']},
        'cnames': ['cdnify.io'], 'ns': [], 'asns': ['AS202422']
    },
    'CDNsun': {
        'headers': {'server': ['CDNsun']},
        'cnames': ['cdnsun.net'], 'ns': [], 'asns': ['AS202781']
    },
    'CDNlion': {
        'headers': {'server': ['CDNlion']},
        'cnames': ['cdnlion.com'], 'ns': [], 'asns': []
    },
    'Tata Communications CDN': {
        'headers': {'server': ['Tata Communications']},
        'cnames': [], 'ns': [], 'asns': ['AS6453']
    },
    'Wangsu Science & Technology (ChinaNetCenter)': {
        'headers': {'server': ['WS-CDN', 'ChinaNetCenter']},
        'cnames': ['wscloudcdn.com'], 'ns': [], 'asns': ['AS45167']
    },
    'ChinaCache': {
        'headers': {'server': ['ChinaCache']},
        'cnames': ['ccgslb.com.cn'], 'ns': [], 'asns': ['AS4837']
    },
    'Lumen (CenturyLink)': {
        'headers': {}, 'cnames': ['lumen.com'], 'ns': [], 'asns': ['AS209', 'AS3356']
    },
    'Medianova': {
        'headers': {'server': ['Medianova']},
        'cnames': [], 'ns': [], 'asns': ['AS47332']
    },
    'CDNetworks': {
        'headers': {'server': ['CDNetworks']},
        'cnames': ['cdngslb.com'], 'ns': [], 'asns': ['AS36674']
    },
    'Quantil': {
        'headers': {'server': ['QUANTIL']},
        'cnames': ['quantil.com'], 'ns': [], 'asns': ['AS40065']
    },
    'Tencent Cloud CDN': {
        'headers': {'server': ['Tengine']},
        'cnames': ['dnsv1.com', 'qcloudcdn.com'], 'ns': [], 'asns': ['AS132203', 'AS45090']
    },
    'Alibaba Cloud CDN': {
        'headers': {'server': ['Tengine'], 'specific': ['x-cache', 'via']},
        'cnames': ['alikunlun.com', 'alibabacloudcdn.com'], 'ns': [], 'asns': ['AS37963', 'AS45102']
    },
    'DigiCDN (Custom)': {
        'headers': {'server': ['DigiCDN Edge']},
        'cnames': [], 'ns': [], 'asns': ['AS206456']
    }
}

def dns_worker(hostname, repetitions_per_thread):
    resolver = dns.resolver.Resolver()
    for _ in range(repetitions_per_thread):
        for record_type in ['A', 'AAAA']:
            try:
                answers = resolver.resolve(hostname, record_type)
                for rdata in answers:
                    ip_address = rdata.to_text()
                    with globals.results_lock:
                        if ip_address not in globals.resolved_ip_details:
                            globals.resolved_ip_details[ip_address] = {'status': 'pending'}

                    if globals.resolved_ip_details[ip_address].get('status') == 'pending':
                        try:
                            ip_info_response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=query,country,city,isp,as")
                            if ip_info_response.status_code == 200:
                                ip_data = ip_info_response.json()
                                ip_data['type'] = 'IPv6' if record_type == 'AAAA' else 'IPv4'
                                try:
                                    rev_name = dns.reversename.from_address(ip_address)
                                    ptr_answer = resolver.resolve(rev_name, "PTR")
                                    ip_data['ptr'] = ptr_answer[0].to_text().rstrip('.')
                                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, Exception):
                                    ip_data['ptr'] = 'Not found'
                                with globals.results_lock:
                                    globals.resolved_ip_details[ip_address] = ip_data
                            else:
                                with globals.results_lock:
                                    globals.resolved_ip_details[ip_address] = {'status': 'failed'}
                        except requests.RequestException:
                            with globals.results_lock:
                                globals.resolved_ip_details[ip_address] = {'status': 'failed'}
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                continue

def analyze_target(hostname):
    findings = {
        'cname': None, 'a_records': [], 'ns_records': [], 'headers': None, 'ip_info': None,
        'cdn_provider': 'Unknown', 'detection_reason': 'No direct evidence found.'
    }
    try:
        resolver = dns.resolver.Resolver()
        findings['a_records'] = sorted([r.to_text() for r in resolver.resolve(hostname, 'A')])
        domain_parts = hostname.split('.')
        root_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) > 1 else hostname
        findings['ns_records'] = sorted([r.to_text().rstrip('.') for r in resolver.resolve(root_domain, 'NS')])
        try:
            cname_answers = resolver.resolve(hostname, 'CNAME')
            findings['cname'] = cname_answers[0].target.to_text().rstrip('.')
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN): pass
        for provider, sigs in CDN_SIGNATURES.items():
            if any(c in findings['cname'] for c in sigs['cnames'] if findings['cname']):
                findings['cdn_provider'], findings['detection_reason'] = provider, f"CNAME record points to '{findings['cname']}'"
