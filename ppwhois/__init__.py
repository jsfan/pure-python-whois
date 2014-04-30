from ppwhois.whois import Whois


def whois(query=None, source_addr=None, flags=None):
    w = Whois()
    return w.lookup(query, source_addr, flags)