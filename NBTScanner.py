
from __future__ import generator_stop
from itertools import zip_longest
import configparser
import subprocess
import ipaddress
import argparse
import sys
import re

# https://docs.python.org/3/library/itertools.html
def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)
        
def eprint(*args, **kwargs):
    '''
        Send print output to STDERR. Used to ease redirection to file.
    '''
    print(*args, **kwargs, file=sys.stderr)

def NBTScan(network, timeout, fmtstr):
    '''
        Use Windows NBTSTAT.EXE in IP address mode (-A) to scan
        all host addresses in CIDR range. Parse output with regular
        expressions and print IP Address, Host Name, and MAC
        Address with format string.
    '''
    macreg  = r'(([\da-f]{2}.){5}[\da-f]{2})'
    namereg = r'([\w\d]+).*?unique'
    ips = (a.exploded for a in ipaddress.IPv4Network(network).hosts())
    ips = grouper(ips, 254)
    procs = []
    eprint(f'Initializing NBT scan on network {network} . . .\n')
    print(fmtstr.format('IP Address', 'Host Name', 'MAC Address'))  # table header

    
    for hosts in ips:  # limit to 254 subprocesses
        for host in hosts:
            if host is None: continue
            procs.append(
                subprocess.Popen( ['nbtstat', '-A', host], 
                                  stdout=subprocess.PIPE
                )
            )

        for proc in procs:
            try:
                # get stdout bytes, decode to utf8, if timeout, next subp
                output = proc.communicate(timeout=timeout)[0].decode()
            except subprocess.TimeoutExpired:
                continue
                
            # parse output for hostname, mac strings
            hostip = proc.args[2]
            hostmac = re.search(macreg, output, re.IGNORECASE)
            hostname = re.search(namereg, output, re.IGNORECASE)
            if None in [hostmac, hostname]:
                continue  # host replied with error
            hostmac, hostname = hostname.group(1), hostmac.group(1)
            print(fmtstr.format(hostip, hostmac, hostname))
    
        procs.clear()

    eprint('\nScan complete')
        


def main():
    '''
        Main scan and saved state initialization logic.
    '''
    #initialize .ini file, or from .ini
    config = configparser.ConfigParser()
    configfilename = __file__.split('\\')[-1].split('.')[0] + '.ini'
    try:
        with open(configfilename) as f:
            config.read_file(f)
    except FileNotFoundError:
        config['network'] = {'network':'172.16.1.0/24', 'timeout':'0.01'}
        config['output']  = {'format_string':'{:<25}{:<25}{:<25}'}
        with open(configfilename ,'w') as f:
            config.write(f)                

    # initialize command line arguments
    parser = argparse.ArgumentParser(description='Use Windows NBT Protocol to find hosts on the network.')
    parser.add_argument('network', default=config['network']['network'], nargs='?', help='Target network in CIDR notation.')
    parser.add_argument('-t', '--timeout', default=config['network']['timeout'], type=float, help='Host response timeout delay.') 
    format_group = parser.add_mutually_exclusive_group()  # csv format overrides manual format
    format_group.add_argument('-f', '--format', default=config['output']['format_string'], help='Format output with Python format string.')
    format_group.add_argument('--csv', action='store_true', help='Format output with commas in CSV format.')
    
    parser = parser.parse_args()

    if '__' in parser.format:  # sanitize input
        raise ValueError('invalid format string')
        
    netmask = int(parser.network.split('/')[-1])
    if netmask < 22:
        eprint('You are about to scan', 2**(32-netmask), 'hosts.\nContinue? [y/{n}]:  ', end='')
        if not input().casefold().strip().startswith('y'):
            eprint('Scan cancelled')
            return
    
    if parser.csv:
        parser.format = '{},{},{}'
    NBTScan(parser.network, parser.timeout, parser.format)

if __name__=='__main__':
    main()
    eprint('Done')