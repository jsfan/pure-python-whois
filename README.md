pure-python-whois
=================
The aim of this package is to provide a feature-complete pure Python implementation
for whois. While e.g. pywhois comes with a pure Python implementation, it only
uses this implementation as a fallback preferring the system implementation over the
pure Python one. Furthermore, the pure Python implementation is experimental and
rather limited in its features.

The pure-python-whois is a largely complete transliteration of Marco d'Itri's whois
client (written in C) which comes with most Linus distributions. While it is likely
to still have some maturity issues, it provides a large subset of the features
offered by the C client. Wherever practical, the Python implementation follows the C
implementation very closely even attempting to use the same variable names where
possible.

Please note that some functionality around IP addresses (in particular IPv6) probably
doesn't work on Windows. This will be addressed in future versions.

Pull requests welcome.
