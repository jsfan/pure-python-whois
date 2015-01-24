"""
This script can generate the whois_lookup_data.py file's contents from
the files included in Marco d'Itri's whois client's source code

http://www.linux.it/~md/software/
"""

import ipaddress
import re

known_files = [
    ('as32_del_list', 'asn'),
    ('as_del_list', 'asn'),
    ('ip6_del_list', 'ipv6'),
    ('ip_del_list', 'ipv4'),
    ('tld_serv_list', 'domain'),
    ('new_gtlds_list', 'domain'),
    ('nic_handles_list', 'handle'),
    ('servers_charset_list', 'charset')
]

asn = []
ipv6 = []
ipv4 = []
tlds = []
handles = []
charsets = {}
ipv4_catchall = None
for f, t in known_files:
    with open(f, 'r') as input_file:
        for l in input_file:
            if re.match(r'^\s*#', l) or re.match(r'^\s*$', l):
                continue
            clean_l = re.sub(r'(#.*)?\r*\n*$', '', l)
            clean_l = re.sub(r'\s+', '\t', clean_l)
            details = re.split(r'\s+', clean_l)
            if t == 'asn':
                if '.' not in details[2]:
                    details[2] = 'whois.{name}.net'.format(name=details[2])
                asn.append(tuple(details))
            elif t == 'ipv6':
                block = ipaddress.ip_network(details[0])
                start = int(block.network_address)
                end = int(block.broadcast_address)
                if '.' in details[1]:
                    server = details[1]
                else:
                    server = 'whois.{name}.net'.format(name=details[1])
                    if details[1] in ['teredo', '6to4']:
                        server = details[1].upper()
                ipv6.append((start, end, server))
            elif t == 'ipv4':
                block = ipaddress.ip_network(details[0])
                start = int(block.network_address)
                end = int(block.broadcast_address)
                if '.' in details[1] or re.match(r'[A-Z]+', details[1]):
                    server = details[1]
                else:
                    server = 'whois.%s.net' % details[1]
                if len(ipv4) > 0 and start == 0:
                    ipv4_catchall = (start, end, server)
                else:
                    ipv4.append((start, end, server))
            elif t == 'domain':
                tld = details[0]
                if len(details) < 2:
                    details.append('whois.' + details[0])
                    tld = '.' + details[0]
                if len(details) > 2:
                    whois = details[2]
                    dtype = details[1]
                elif details[1] == 'ARPA':
                    whois = None
                    dtype = details[1]
                else:
                    whois = details[1]
                    dtype = None
                tlds.append((tld, whois, dtype))
            elif t == 'handle':
                handles.append(tuple(details))
            elif t == 'charset':
                if len(details) < 3:
                    details.append(None)
                charsets[details[0]] = tuple(details[1:])
if ipv4_catchall:
    ipv4.append(ipv4_catchall)
print('ASN = {d}'.format(d=re.sub(r',\s+(\()', r',\n\t\1', asn.__str__())))
print('IPV6 = {d}'.format(d=re.sub(r',\s+(\()', r',\n\t\1', ipv6.__str__())))
print('IPV4 = {d}'.format(d=re.sub(r',\s+(\()', r',\n\t\1', ipv4.__str__())))
print('TLDS = [')
for tld in tlds:
    print('\t{d},'.format(d=tld.__str__()))
print(']')
print('NIC = {d}'.format(d=re.sub(r',\s+(\()', r',\n\t\1', handles.__str__())))
print('FLAGS = {d}'.format(d=re.sub(r',\s+(\'[^\']+\':\s)', r',\n\t\1', charsets.__str__())))