#Cyber Clinic - Scan result parsers
#Parses nmap and nikto scan outputs into structured data

from .nmap_parser import NmapParser
from .nikto_parser import NiktoParser

__all__ = ['NmapParser', 'NiktoParser']
