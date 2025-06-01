import json
import re
import subprocess
from urllib import request
from prettytable import PrettyTable

ip_regex = re.compile(r'\d{1,3}(?:\.\d{1,3}){3}')
not_resolve_node = 'traceroute: unknown host'
tracing_route = 'traceroute to'
timeout_pattern = re.compile(r'^\s*\*\s+\*\s+\*')


def get_console_tracer(hostname):
    return subprocess.Popen(
        ['tracert', '-d', hostname],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    ).stdout.readline

def get_ip_info(ip):
    with request.urlopen(f'https://ipinfo.io/{ip}/json') as resp:
        return json.loads(resp.read())


def get_list_ip(address):
    reader = get_console_tracer(address)
    hops = []

    while True:
        line = reader()
        if not line:
            break
        text = line.decode('cp866', errors='ignore').strip()

        if text.lower().startswith('tracert to') or text.lower().startswith('иcпользование'):
            continue

        if timeout_pattern.match(text):
            print(text)
            continue

        match = ip_regex.search(text)
        if match:
            ip = match.group(0)
            hops.append(ip)
            print(f"{len(hops):2d}  {text}  → {ip}")

    return hops


def get_table(list_ip):
    table = PrettyTable(['№', 'IP', 'ASN', 'Provider', 'Country'])

    for idx, ip in enumerate(list_ip, 1):
        info = get_ip_info(ip)
        org = info.get('org', '*')
        parts = org.split()

        asn = parts[0] if parts else '*'
        provider = ' '.join(parts[1:]) or '*'
        country = info.get('country', '*')

        table.add_row([idx, ip, asn, provider, country])

    return table


def main():
    target = input('Введите доменное имя или IP: ').strip()
    hops = get_list_ip(target)
    print()
    print(get_table(hops))

if __name__ == '__main__':
    main()