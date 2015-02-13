"""
List was taken from Marco d'Itri's whois client
http://www.linux.it/~md/software/
"""

from .whois_lookup_data import *

DEFAULTSERVER = "whois.arin.net"

REFERTO_FORMAT = r"referto:\s+whois\s+-h\s+([^\s]*)(?:\s+-p\s([^\s]+))?(?:\s+(.*))?$"
REFERRAL_FORMAT = r"ReferralServer:\s+r?whois://([^/]+)#\s*$"

CRSDOMLABEL = "^\s*Domain\sName:\s*"
CRSWHOISLABEL = "^\s*Whois\sServer:\s*(.*)$"

RIPE_SERVERS = ["whois.ripe.net",
                "whois.apnic.net",
                "whois.afrinic.net",
                "rr.arin.net",        # does not accept the old syntax
                "whois.6bone.net",        # 3.0.0b1
                "whois.connect.com.au",    # 3.0.0b1
                "whois.nic.fr",
                "whois.telstra.net",
                "whois.restena.lu",
                "rr.level3.net",        # 3.0.0a13
                "whois.ripn.net",
                "whois.arnes.si",
                "www.registry.co.ug",
                "whois.nic.ir",
                "whois.nic.ck",
                "whois.ra.net",
                "whois.bgpmon.net"]

HIDE_STR = [("NOTICE AND TERMS OF USE: You", ""),  # NetSol
            ("TERMS OF USE: You are not", ""),  # crsnic
            ("The data in Register", ""),  # Register.Com
            ("The Data in the Tucows", "RECORD DOES NOT"),
            ("The information in this whois database", ""),  # DOTSTER
            ("This whois service currently only", "top-level domains."),  # NameSecure
            ("The Data in Gabia", "you agree to abide"),
            ("The data contained in GoDaddy.com", "is not the registrant"),
            ("Disclaimer: The Global Name Registry", "for any commercial"),
            ("Access to America Online", "time. By accessing"),  # AOL
            ("# Access and use restricted", ""),  # GANDI
            ("% The data in the WHOIS database of 1&1 Internet", ""),
            ("The data in this whois database is", ""),  # enom
            ("The Data in Moniker's WHOIS database", "of Moniker."),
            ("The Data in OnlineNIC", "    By starting this query"),
            ("Interdomain's WHOIS", "DOES NOT SIGNIFY"),
            ("The Data provided by Stargate Holdings", "(2) enable any"),
            ("; This data is provided by domaindiscount24.com", ""),
            ("%% NOTICE: Access to this information is provided", "%% By submitting"),  # bookmyname.com
            ("% NOTICE: Access to the domains information", "% this query"),  # CORE
            # gTLDs
            ("Access to .AERO WHOIS information", ""),
            ("DotAsia WHOIS LEGAL STATEMENT", "integrity of the database."),
            ("The .coop registry WHOIS", "VERIFICATION, NOR DO"),
            ("%% puntCAT Whois Server", "%% any time."),
            ("This Registry database contains ONLY .EDU", "type: help"),  # edu
            ("Access to INFO WHOIS information is provided", ""),  # Afilias
            ("mTLD WHOIS LEGAL STATEMENT", "integrity of the database."),  # .mobi
            ("Access to .ORG WHOIS information", ""),
            ("Access to RegistryPro's Whois", "All rights"),  # .pro
            ("Telnic, Ltd., the Registry Operator", "(b) harass any person;"),  # .tel
            ("Tralliance, Inc., the Registry", ""),  # .travel
            ("Access to .XXX ICM REGISTRY WHOIS", ""),  # .xxx
             # ccTLDs
            ("Access to CCTLD WHOIS information is provided", ""),  # Afilias
            ("Access to ASNIC", "by this policy."),  # as
            ("% The WHOIS service offered by DNS.be", "% protect the privacy"),  # be
            ("% The WHOIS service offered by EURid", "% of the database"),  # eu
            ("% WHOIS LEGAL STATEMENT AND TERMS & CONDITIONS", ""),  # sx
            ("NeuStar, Inc., the Registry", "OF THE AVAILABILITY")]  # us

AVAILABLE = [r'^(Domain|Key)\s+not\s+found\.*',
             r'^No\s+match',
             r'^%\s+no\s+matching\s+objects\s+found',
             r'^No\s+such\s+domain:\s+',
             r'^(((%*\s*)?Object|Domain)\s+)*NOT\s+FOUND',
             r'^(%*\s*)?This\s+query\+returned\+0\+objects\.',
             r'^We\s+do\s+not\s+have\s+an\s+entry\s+in\s+our\s+database\s+matching\s+your\s+query\.',
             r'^(%*\s*)?No\s+entries\s+found',
             r'^No\s+domain\s+records\s+were\s+found\s+to\s+match\s+',
             r'^No\s+(Data\s+)*Found',
             r'^(%*\s*)?[Nn]o\s[Mm]atch',
             r'^>>>\s+Domain\s+[^\s]+\s+is\s+available\s+for\s+registration',
             r'^(%*\s*)?No\s+entries\s+found',
             r'^\s*This\s+domain\s+name\s+has\s+not\s+been\s+registered.',
             r'^(%\s*)?nothing\s+found$',
             r'^(Domain\s+)*Status:\s+(No\s+Object\s+Found|Available|(Not\sregistered))',
             r'^Domain\s+[^\s]*\s+is\s+available\s+for\s+purchase',
             r'^Domain\s+[^\s]*\s+not\s+registe*red\.',
             r'^The\s+domain\s+has\s+not\s+been\s+registered\.',
             r'^>>>\s+Domain\s+[^\s]+\s+is\s+available\s+for\s+registration',
             r'^query_status:\s+220\s+Available',
             r'^(%\s*)?[Nn]ot\s[Rr]egistered',
             r'^.*is\sfree$',
             r'Status:\sfree']
EXPIRY = [r'^\s*((Domain|Registry)\s+)*Expir[ye]\s+Date:\s*',
          r'^\s*(Domain\s+)*Expiration\s+Date:\s*',
          r'^\s*((Domain|Record)\s+)*Expires(\sOn)*:*\s*',
          r'^\s*domain_datebilleduntil:\s+']
BLACKLISTED = [r'exceeded\s(the\s)?(query\s)?limit',
               r'limit\sexceeded',
               r'previous\srequest\sis\sbeing\sprocessed']