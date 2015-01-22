import socket
import sys
import re
import chardet

import ppwhois.whois_data as data
from ppwhois.exceptions import *

IDSTRING = 'ppwhois-0.1.4'
RCVBUF = 2048


class Whois(object):
    """
    WHOIS lookup for IP addresses and domains

    Transliteration of Linux whois client by Marco d'Itri

    Option mapping:
        h/host => host: '<host>'
        p/port => PORT: <port>
        H => hide_disclaimers
        l => one_level_less
        L => all_levels_less
        m => one_level_more
        M => all_levels_more
        c => smallest_mnt_irt
        x => exact
        b => brief
        B => no_filter
        G => no_group
        d => no_reverse_dns
        i => inverse_attr: [attr, attr,...]
        T => only_type: [type, type,...]
        K => primary_only
        r => no_reverse_contact
        R => local_copy_only
        a => search_mirrors
        s => search_mirrors_source: [source, source,...]
        g => search_mirrors_range: (source, first, last)
        t => template: '<TYPE>'
        v => verbose_template: '<TYPE>'
        q => query_info: '<version|sources|types>'
    """

    def __init__(self):
        self.hide_disclaimer = False
        self.host = ''
        self.port = 0
        self.source_addr = None

    def lookup(self, query=None, source_addr=None, flags=None):
        self.host = ''
        self.port = 0
        fstring = ''
        ripeflags = {'search_mirrors': 'a',
                    'brief': 'b',
                    'no_filter': 'B',
                    'smallest_mnt_irt': 'c',
                    'no_reverse_dns': 'd',
                    'no_group': 'G',
                    'primary_only': 'K',
                    'one_level_less': 'l',
                    'all_levels_less': 'L',
                    'one_level_more': 'm',
                    'all_levels_more': 'M',
                    'no_reverse_contact': 'r',
                    'local_copy_only': 'R',
                    'exact': 'x',
                    'search_mirrors_range': 'g',
                    'inverse_attr': 'i',
                    'search_mirrors_source': 's',
                    'only_type': 'T',
                    'template' : 't',
                    'verbose_template': 'v',
                    'query_info': 'q'}

        nopar = False
        if flags:
            uargs = flags
        else:
            uargs = {}
        for f, v in ripeflags.items():
            pv = uargs.pop(f, None)
            if pv:
                if isinstance(pv, list) or isinstance(pv, tuple):
                    fstring += '-%s ' % v
                else:
                    if f == 'search_mirrors_range':
                        source = pv.pop(0)
                        pv[0] = source + ':' + pv[0]
                    fstring += '_%s %s' % (v, pv)
                    if f in ['template', 'verbose_template', 'query_info']:
                        nopar = True

        for f, v in uargs.items():
            if f == 'host': # host
                self.host = v
            elif f == 'hide_disclaimers': # hide disclaimer
                self.hide_disclaimer = True
            elif f == 'port': # port
                self.port = v

        if not query and not nopar:
            return False
        elif nopar:
            self.host = 'whois.ripe.net'

        query = self.normalise_domain(query)

        if not self.host:
            self.host = self.guess_server(query)

        if source_addr:
            self.source_addr = source_addr

        return self.handle_query(query, fstring)

    def normalise_domain(self, domain):
        domain.rstrip('. \t')
        dwords = domain.split(' ')
        last = dwords.pop()
        dwords.append(str(last.encode('idna').decode('ascii')))
        return ' '.join(dwords)

    def guess_server(self, query):
        if ':' in query:  # IPv6
            if query[:2].lower() == 'as':
                try:
                    asn = int(query[2:])
                    for asdata in data.ASN:
                        if asn >= asdata[0] and asn <= asdata[1]:
                            return asdata[2]
                    else:
                        return '\x05'
                except ValueError:
                    return ''

            query_parts = query.split(':')
            try:
                v6prefix = int(query_parts[0], 16)
            except ValueError:
                return '\x05' # unknown prefix

            v6net = (v6prefix << 16) + int(query_parts[1], 16)  # second u16

            for ip6net in data.IPV6:
                if (v6net & (int('FFFFFFFF', 16) << (32 - ip6net[1]))) == ip6net[0]:
                    return ip6net[2]
            return '\x06'  # unknown network

        if '@' in query:
            return '\x05'  # email address

        # no dot and no hyphen means it's a NSI NIC handle or ASN (?)
        if '.' not in query and not '-' in query:
            if query[:2].lower() == 'as':
                try:
                    asn = int(query[2:])
                    for asdata in data.ASN:
                        if asn >= asdata[0] and asn <= asdata[1]:
                            return asdata[2]
                    return '\x05'
                except ValueError:
                    pass
            if query[0] == '!':  # NSI NIC handle
                return 'whois.networksolutions.com'
            else:
                return '\x05'  # probably a unknown kind of NIC handle

        # smells like an IP?
        try:
            ip = socket.ntohl(int.from_bytes(socket.inet_pton(socket.AF_INET, query), sys.byteorder))
            for ip4r in data.IPV4:
                if (ip & ip4r[1]) == ip4r[0]:
                    return ip4r[2]
            return '\x05'
        except socket.error:
            pass

        # check the TLDs list
        for tld in data.TLDS:
            if query.endswith(tld[0]):
                return tld[1]

        # no dot but hyphen
        if '.' not in query:
            # search for strings at the start of the word */
            for nic in data.NIC:
                if query.startswith(nic[0]):
                    return nic[1]
            # it's probably a network name
            return ''

        # has dot and maybe a hyphen and it's not in tld_serv[], WTF is it?
        # either a TLD or a NIC handle we don't know about yet
        return '\x05'

    def handle_query(self, query, flags):
        first_result = {}
        notice = None
        modified = True
        while modified:
            modified = False
            code = int.from_bytes(self.host[0].encode('utf-8'), sys.byteorder)
            if code == 0:
                self.host = data.DEFAULTSERVER
            elif code == 1:
                return {'error': 'This TLD has no whois server, but you can access the whois database at %s' % self.host[2:]}
            elif code == 3:
                return {'error': 'This TLD has no whois server.'}
            elif code == 5:
                return {'error': 'No whois server is known for this kind of object.'}
            elif code == 6:
                return {'error': 'Unknown AS number or IP network. Please upgrade this package.'}
            elif code == 4:
                sockfd = self.openconn(self.host[1:])
                if not sockfd:
                    return sockfd
                self.host, first_result = self.query_crsnic(sockfd, query)
                sockfd.close()  # close socket from first connection
            elif code == 8:
                sockfd = self.openconn('whois.afilias-grs.info')
                if not sockfd:
                    return sockfd
                self.host, first_result = self.query_afilias(sockfd, query)
                sockfd.close()  # close socket from first connection
            elif code == 0x0A:
                p = self.convert_6to4(query)
                notice = 'Querying for the IPv4 endpoint %s of a 6to4 IPv6 address.' % p
                self.host = self.guess_server(p)
                modified = True
                query = p
            elif code == 0x0B:
                p = self.convert_teredo(query)
                notice = 'Querying for the IPv4 endpoint %s of a Teredo IPv6 address.' % p
                self.host = self.guess_server(p)
                modified = True
                query = p
            elif code == 0x0C:
                p = self.convert_inaddr(query)
                modified = True
                self.host = self.guess_server(p)

        if not self.host:
            try:
                _ = first_result['result']
                return first_result
            except KeyError:
                return {'error': 'No host found.'}

        query_string, warning = self.queryformat(self.host, flags, query)
        sockfd = self.openconn(self.host, self.port)
        if not sockfd:
            return sockfd

        server, result = self.do_query(sockfd, query_string)
        sockfd.close()  # close follow-up connection

        merged_result = {}
        for d in [first_result, result, {'warning': warning}, {'notice': notice}]:
            for k, v in d.items():
                if v:
                    if isinstance(v, list):
                        for l in v:
                            merged_result.setdefault(k, []).append(l)
                    else:
                        merged_result.setdefault(k, []).append(v)

        result = merged_result
        if server and not result['error']:
            _, further_result = self.handle_query(server, None, query, flags)
            merged_result = {}
            for d in [result, further_result]:
                for k, v in d.items():
                    if v:
                        if isinstance(v, list):
                            for l in v:
                                merged_result.setdefault(k, []).append(l)
                        else:
                            merged_result.setdefault(k, []).append(v)
            result = merged_result
        result['available'] = min(result['available'])
        return result

    def openconn(self, server, port=None):
        timeout = 10
        port = port if port else 'nicname'
        try:
            for srv in socket.getaddrinfo(server, port, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, socket.AI_ADDRCONFIG):
                af, socktype, proto, _, sa = srv
                try:
                    c = socket.socket(af, socktype, proto)
                except socket.error:
                    c = None
                    continue
                try:
                    if self.source_addr:
                        c.bind(self.source_addr)
                    c.settimeout(timeout)
                    c.connect(sa)
                except socket.error:
                    c.close()
                    c = None
                    continue
                break
        except socket.gaierror:
            return False

        return c

    def queryformat(self, server, flags, query):
        sflags = ''
        warning = None
        ripe = False
        if server in data.RIPE_SERVERS:
            sflags = '-V %s' + flags
            ripe = True
        if not ripe and flags:
            warning = 'Warning: RIPE flags used with a traditional server.'

        if server in data.FLAGS:
            flag = data.FLAGS[server][1]
            if flag:
                sflags += flag + ' '

        if ripe:
            pass
        elif ' ' in query or flags:
            pass
        elif server == 'whois.denic.de' and query.endswith('.de'):
            sflags += '-T dn,ace '
        elif server == 'whois.dk-hostmaster.dk' and query.endswith('.dk'):
            sflags += '--show-handles '

        # mangle and add the query string
        if not ripe and server == 'whois.nic.ad.jp' and query[:2].lower == "as":
            try:
                _ = int(query[2:])
                sflags += 'AS ' + query[:2]
            except ValueError:
                pass
        elif not ripe and server == 'whois.arin.net' and not ' ' in query:
            if query[:2].lower == "as":
                try:
                    _ = int(query[2:])
                    sflags += 'AS ' + query[:2]
                except ValueError:
                    pass
            else:
                is_ip = False
                try:
                    _ = socket.inet_pton(socket.AF_INET, query)
                    is_ip = True
                except socket.error:
                    if ':' in query:
                        is_ip = True
            if is_ip:
                sflags += 'n + ' + query
            else:
                sflags = query
        else:
            sflags = query

        # ask for English text
        if not ripe and (server == 'whois.nic.ad.jp' or server == 'whois.jprs.jp'):
            sflags += '/e'

        return [sflags, warning]

    def query_afilias(self, sock, query, prepend=''):
        return self.query_crsnic(sock, query)

    def query_crsnic(self, sock, query, prepend='='):
        _, result = self.do_query(sock, prepend + query)
        referral_server = None
        fresult = result.pop('result', None)
        if not fresult:
            return '', {'error': 'First query failed'}
        result['result'] = fresult
        found = False
        domlabel = re.compile(data.CRSDOMLABEL)
        whoislabel = re.compile(data.CRSWHOISLABEL)
        for l in result['result']:
            if not found and domlabel.search(l):
                found = True
            if found:
                wl = whoislabel.search(l)
                if wl:
                    referral_server = wl.group(1).strip()
                    break
        return referral_server, result

    def do_query(self, sock, query):
        hide = False
        referral_server = None

        try:
            sock.send(("%s\r\n" % query).encode('ascii'))
            sock.setblocking(True)
        except socket.error as e:
            raise ConnectionReset('Connection was reset  with error "%s" while sending data' % e)

        response = ''
        while True:
            try:
                rb = sock.recv(RCVBUF)
            except socket.error as e:
                raise TransferFailed('Transfer failed  with error "%s" while receiving data' % e)
            if not rb:
                break
            enc = chardet.detect(rb)['encoding']
            rb = rb.decode(enc)
            # 6bone-style referral:
            # % referto: whois -h whois.arin.net -p 43 as 1
            if not referral_server and '% referto:' in rb:
                # XXX we are ignoring the new query string
                rs = re.compile(data.REFERTO_FORMAT)
                ns, np = rs.group(1, 2)

            # ARIN referrals:
            # ReferralServer: rwhois://rwhois.fuse.net:4321/
            # ReferralServer: whois://whois.ripe.net
            if not referral_server and 'ReferralServer' in rb:
                rs = re.compile(data.REFERRAL_FORMAT)
                referral_server = rs.group(1)
            response += rb

        resp_lst = []
        expiry = None
        available = None
        blacklisted = None
        for l in response.split('\n'):
            hide = self.hide_line(hide, l)
            if not hide:
                resp_lst.append(l.rstrip())
            if not expiry:
                expiry = self.expiry(l)
            if not available or available < 0:
                available = self.is_available(l)
            if not blacklisted:
                blacklisted = self.is_blacklisted(l)

        if hide:
            return ('', 'Catastrophic error: disclaimer text has been changed.\n'
                    'Please upgrade this package.\n')
        sock.close()
        if not blacklisted:
            return referral_server, {'result': resp_lst, 'expiry': expiry, 'available': available}
        else:
            return referral_server, {'error': 'Blacklisted'}

    def hide_line(self, hide, line):
        if not self.hide_disclaimer:
            return 0
        hide = 0 if hide < 1 else 1
        if not hide:  # start hiding?
            for hs in data.HIDE_STR:
                if line == hs[0] or (line and line.startswith(hs[0])):
                    return 1
        else:  # done hiding?
            for hs in data.HIDE_STR:
                if line == hs[1] or (line and line.startswith(hs[1])):
                    return -1
        return 0

    def is_available(self, line):
        for av_marker in data.AVAILABLE:
            if re.search(av_marker, line, re.IGNORECASE):
                return 1
        return -1

    def is_blacklisted(self, line):
        for av_marker in data.BLACKLISTED:
            if re.search(av_marker, line, re.IGNORECASE):
                return True
        return False

    def expiry(self, line):
        for exp in data.EXPIRY:
            if re.search(exp, line, re.IGNORECASE):
                return re.sub(exp, '', line, flags=re.IGNORECASE)
        return False


    def convert_teredo(self, s):
        words = s.split(':')
        if words[0] != '2001' or int(words[1]) != 0:
            return '0.0.0.0'
        words = words[-2:]
        hip = hex(int(''.join(words[:2]), 16) ^ int('ffffffff', 16))
        hip = hip[2:]
        ip = []
        while hip:
            ip.append(str(int(hip[:2], 16)))
            hip = hip[2:]
        return '.'.join(ip)

    def convert_6to4(self, s):
        words = s.split(':')
        if words[0] != '2002':
            return '0.0.0.0'

        ip4_oct = []
        words.pop(0)
        for b in words[:2]:
            ip4_oct.append(str(int(b[:2], 16)))
            ip4_oct.append(str(int(b[2:], 16)))

        return '.'.join(ip4_oct)

    def convert_inaddr(self, s):
        if not s.endswith('.in-addr.arpa'):
            return '0.0.0.0'
        words = s.split('.')
        ip = words[:4]
        ip.reverse()
        return '.'.join(ip)

if __name__ == "__main__":
    print('This package can currently only be used as a library.')