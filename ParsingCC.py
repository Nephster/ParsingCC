import re
from pathlib import Path
from collections import namedtuple
import sys
import ipaddress
import requests


ASCII_BYTE = rb" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\t"
DOMAIN_NAME = r"[a-zA-Z0-9]+\.[a-z]{2,3}"
IP_ADDR = rb"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
#IP_ADDR_unicode = rb"((2\x005\x00[0-5]\x00|2\x00[0-4]\x00[0-9]\x00|[01]\x00?[0-9]\x00[0-9]\x00?\x00)\.\x00)((2\x005\x00[0-5]\x00|2\x00[0-4]\x00[0-9]\x00|[01]\x00?[0-9]\x00[0-9]\x00?)\.\x00)"
#IP_ADDR_unicode = ru"^((\u0032\u0035[\u0030-\u0035]|\u0032[\u0030-\u0034][\u0030-\u0039]|[\u0030\u0031]?[\u0030-\u0039][\u0030-\u0039]?)\u002e){3}(\u0032\u0035[\u0030-\u0035]|\u0032[\u0030-\u0034][\u0030-\u0039]|[\u0030\u0031]?[\u0030-\u0039][\u0030-\u0039]?)"
#IP_ADDR_unicode = rb"^((2\x005\x00[0-5]\x00|2\x00[0-4]\x00[0-9]\x00|[01]\x00?[0-9]\x00[0-9]\x00?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
#IP_ADDR_unicode = rb"((2\x005\x00[0-5]\x00|2\x00[0-4]\x00[0-9]\x00|[01]\x00?[0-9]\x00[0-9]\x00?)\.\x00){3}(2\x005\x00[0-5]\x00|2\x00[0-4]\x00[0-9]\x00|[01]\x00?[0-9]\x00[0-9]\x00?)"
IP_ADDR_unicode = rb"(([0-9]\x00[0-9]\x00|[0-9]\x00|2\x005\x00[0-5]\x00|2\x00[0-4]\x00[0-9]\x00|[01]\x00?[0-9]\x00[0-9]\x00?)\.\x00){3}((2\x005\x00[0-5]\x00|2\x00[0-4]\x00[0-9]\x00|[01]\x00?[0-9]\x00[0-9]\x00?|[0-9]\x00[0-9]\x00|[0-9]\x00))"
String = namedtuple("String", ["s", "offset"])
n = 6

def get_valid_top_domain():    
    page=requests.get("https://data.iana.org/TLD/tlds-alpha-by-domain.txt")
    if page == None:
        print("None response from server")
        return    

    listOfDomains = page.text.splitlines()
    listOfDomains.pop(0) # skipping the version and last upadate information from the server
    return listOfDomains

def validate_ip_address(address):
    try:
        ip = ipaddress.ip_address(address)
        #print("IP address {} is valid. The object returned is {}".format(address, ip))
        return 1
    except ValueError:
        #print("IP address {} is not valid".format(address))
        return 0

def ascii_ip_addr(buf, n):
    #reg = rb"([%s]{%d,})" % (ASCII_BYTE, n)
    ascii_re = re.compile(IP_ADDR)
    #IPre = re.compile(IP_ADDR)
    for match in ascii_re.finditer(buf):
        if validate_ip_address(match.group().decode("ascii")):
            yield String(match.group().decode("ascii"), match.start())

def unicode_ip_addr(buf, n):
    #reg = rb"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n)
    reg = IP_ADDR_unicode   
    uni_re = re.compile(reg)
    #IPre = re.compile(IP_ADDR)
    for match in uni_re.finditer(buf):
        try:
            if validate_ip_address(match.group().decode("utf-16")):
                yield String(match.group().decode("utf-16"), match.start())
        except UnicodeDecodeError:
            pass

def ascii_str(buf, n,listOfTopLevelDomains):
    reg = rb"([%s]{%d,})" % (ASCII_BYTE, n)
    domainName_re = re.compile(DOMAIN_NAME)
    ascii_re = re.compile(reg)
    for match in ascii_re.finditer(buf):
        if domainName_re.match(match.group().decode("ascii")):
            if domainName_re.match(match.group().decode("ascii")):
                topLevelDomain = match.group().decode("ascii").split('.')[-1]
                if topLevelDomain.upper() in listOfTopLevelDomains: 
                    yield String(match.group().decode("ascii"), match.start())

def unicode_str(buf, n,listOfTopLevelDomains):
    reg = rb"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n)
    domainName_re = re.compile(DOMAIN_NAME) 
    uni_re = re.compile(reg)
    for match in uni_re.finditer(buf):
        try:
            if domainName_re.match(match.group().decode("utf-16")):
                topLevelDomain = match.group().decode("utf-16").split('.')[-1]
                if topLevelDomain.upper() in listOfTopLevelDomains: 
                        yield String(match.group().decode("utf-16"), match.start())
        except UnicodeDecodeError:
            pass


def main():
    folder = sys.argv[1]
    listOfTopLevelDomains = get_valid_top_domain()

    for fn in Path(folder).glob("*.*"):
        with open(fn, 'rb') as f:
            b = f.read()
        #print(b)
        with open(folder + "\\"+"ips.txt","a") as w:
            for s in ascii_ip_addr(b, n):
                #print('0x{:x}: {:s}'.format(s.offset, s.s))
                w.write('0x{:x}: {:s}\n'.format(s.offset, s.s))
            for s in unicode_ip_addr(b,n):
                #print('0x{:x}: {:s}'.format(s.offset, s.s))
                w.write('0x{:x}: {:s}\n'.format(s.offset, s.s))
        with open(folder + "\\"+"domains.txt","a") as a:
            for s in ascii_str(b, n,listOfTopLevelDomains):
                #print('0x{:x}: {:s}'.format(s.offset, s.s))
                a.write('{} 0x{:x}: {:s}\n'.format(Path(fn).name,s.offset, s.s))
            for s in unicode_str(b,n,listOfTopLevelDomains):
                #print('0x{:x}: {:s}'.format(s.offset, s.s))
                a.write('{} 0x{:x}: {:s}\n'.format(Path(fn).name,s.offset, s.s))
                
if __name__ == '__main__':
    main()