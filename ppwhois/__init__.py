from ppwhois.whois import Whois
from ppwhois.exceptions import ConnectionReset, TransferFailed


def whois(query=None, source_addr=None, **flags):
    w = Whois()
    return w.lookup(query, source_addr, flags)