#!/usr/bin/env python

import argparse
import sys
from datetime import datetime
import psutil
import os
import ipaddress
import netifaces
from scapy.all import *

description = '''
  arp_discover.py 2020 Patryk Hatka 
  https://ores.one
'''

parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawTextHelpFormatter)
requiredNamed = parser.add_argument_group('required arguments')
requiredNamed.add_argument('-i', '--interface', help='Target interface', required=True)

args = parser.parse_args()

net = psutil.net_if_addrs()
interfaces = net.keys()

if args.interface not in interfaces:
	print args.interface + ' not found in available interfaces:'
	print interfaces
	exit()

network = netifaces.ifaddresses(args.interface)[2][0]

ipn = ipaddress.ip_network(network['addr'] + '/' + network['netmask'], False)


start_time=datetime.now()
conf.verb= 0
ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = str(ipn)), timeout = 2, inter = 0.1)

print "MAC       -         IP"
for snd, rcv in ans:
	print rcv.sprintf(r"%Ether.src% - %ARP.psrc%")
stop_time = datetime.now()
total_time = stop_time - start_time
print "\n Scan finished"
print ("\n Total time: %s" %(total_time))