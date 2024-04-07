#!/usr/bin/env python3
import argparse
from contextlib import contextmanager
import platform
import subprocess
# from yaml import load, Loader
# from provider import Provider


# MITMPROXY = "./mitmproxy-8.1.0/mitmproxy" # path to mitmproxy executable
MITMPROXY = "mitmproxy"
self_test = False     # Testing on your own machine. If set to false, then transparent mode will be used.

parser = argparse.ArgumentParser(description='Helper Script for Running mitmproxy')
domain_group = parser.add_mutually_exclusive_group()
domain_group.add_argument('-p', '--provider', metavar="PROVIDER", type=str, help='the vpn provider to test for')
domain_group.add_argument('-d', '--domain', metavar="DOMAIN", type=str, help='the vpn gateway domain')
parser.add_argument('-c', '--cert', metavar="CERT", type=str, help="the certificate to test")
parser.add_argument('-t', '--tcp', action='store_true', help="Capture All TCP traffic instead of HTTP only")
parser.add_argument('--dry-run', action='store_true', help="Only prints the command it should run")


def set_up():
    plat = platform.system()
    if plat == 'Darwin' and self_test:
        return [["networksetup", "-setwebproxystate", "wi-fi", "on"],
            ["networksetup", "-setsecurewebproxystate", "wi-fi", "on"]
        ]
    return []

def clean_up():
    plat = platform.system()
    if plat == 'Darwin' and self_test:
        return [["networksetup", "-setwebproxystate", "wi-fi", "off"],
            ["networksetup", "-setsecurewebproxystate", "wi-fi", "off"]
        ]
    return []

@contextmanager
def environment():
    for command in set_up():
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    yield
    for command in clean_up():
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
# def lookup(name):
#     with open("providers.yaml", "r") as f:
#         data = load(f.read(), Loader=Loader)
#     try:
#         entry = data[name]
#     except AttributeError:
#         raise ValueError("Lookup failed")

#     gateway = entry.get_gateway()
#     args = entry.get_args()
#     tcp = entry.get_tcp()
#     return gateway, args, tcp
        
        

def prepare_args(arg, extra):
    command = [ MITMPROXY, '--anticache', '--set', 'spoof-source-address',  '--ssl-insecure'] # ,  , , '-k' ,'--set', 'upstream-cert=False' , 
    if not self_test:
        command.extend(['--mode', 'transparent', '--showhost'])
    command.extend(['-s', 'downgrade_server.py'])
    domain = None
    domain, extra_args, tcp = arg.domain, [], False

    if arg.tcp or tcp:
        domain_prepend = '--tcp-hosts'
    else:
        domain_prepend = "--allow-hosts"

    if isinstance(domain, str):
        command.extend([domain_prepend, domain])
    elif isinstance(domain, list):
        for entry in domain:
            command.extend([domain_prepend, entry])

    if arg.cert is not None:
        command.extend(["--certs", arg.cert])
    if extra is not None:
        command.extend(extra)
    if extra_args:
        command.extend(extra_args)
    print(command)
    if arg.dry_run:
        print(" ".join(command))
        exit()
    return command
        


if __name__ == "__main__":
    args, extra = parser.parse_known_args()
    if extra == ["help"]:
        parser.print_help()
        exit()
    print(args, extra)
    proxy_command = prepare_args(args, extra)
    with environment():
        subprocess.run(proxy_command)
