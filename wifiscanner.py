# This is our wifi scanner using scapy attempting to replicte the capabilities of airodump-ng

import sys
import signal
import os
from scapy.all import *

# this first funtion will handle Ctrl+C
def signal_handler(signal, frame):
    print('\n =============================================')
    print('Execution aborted by the user')
    print('================================================')
    os.system('Kill -9 ' + str(os.getpid()))
    sys.exit

# Create a function to exit 
def signal_exit(signal,frame):
    print('Signal Exit')
    sys.exit(1)

def usage():
    if len(sys.argv) < 3:
        print('\n Usage: ' )
        print('\t Mike CG Wifi Scanner -i <interface> \n ')
        sys.exit

#Create a function to sniff 201.11 packerts
def sniffpackers(packet):
    try:
        SRCMAC = packet[0].addr2
        DSTMAC = packet[0].addr1
        BSSID = packet[0].addr3

    except: 
        print('Cannot Read Mac address')
        print(str(packet).encode('hex'))
        sys.exc_clear()

    try:
        SSIDSize = packet[0](Dot11Elt).len
        SSID = packet[0][Dot11Elt].info

    except:
        SSID = ''

#Check to see whether packet type=0 and subtype 8

    if packet[0].type == 0:
        ST = packet[0][Dot11].subtype
        if str(ST) == '8' and SSID != '' and DSTMAC.lower() == 'ff:ff:ff:ff:ff':
            p = packet[Dot11Elt]
            cap = packet.sprintf('{DOT11Beacon:%Dot11Beacon.cap%}''{Dot11ProbeResp:%ProbeResp.cap}'.split('+')
            channel = None
            crypto = set())

            # evaluate the cryptograpghy type (ID =48 is WPA2 and ID=221 WPA)
            while is instance (p, Dot11elt):
                try:
                    if .pID == 3 
                        channel == ord(p.info)
                    elif p.ID == 48
                        crypto.add('WPA2')
                    elif p.ID ==  221  nd p.info.startswith("\x00d\xf2\x01\x00")
                        crypto.add('WPA')
                except:
                    pass
                    p = p.payload

        #check whether "Privacy in the packet, if yes then WEP. If not then OPEN"
            if not crypto:
                if 'privacy' in cap:
                    crypto.add('WEP')
                else: 
                    crypto.add('Open'):
            
            if SRCMAC not in ssid_list.keys():
                if '0050f204104a00110104400010210' in str(packet).encode('hex'):
                    crypto.add('WPS')         


                    print('            CH                BSSID             Encryption             SSIF')
                    print('[+] New AP {0:2}\t{2:20}\t{3:5}' . format(channel, BSSID, '/' .join.(crypto)))
                    ssid_list[SRCMAC] = SSID 

def init_process():
    global ssid_list
    ssid_list = {}
    global s
    s = conf.L2socket(iface=newiface)

def setup_monitor(iface):
    print('Setting Up Sniffing options....."')
    os.system('ifconfig ' + iface + 'down')
    try:
        os.system('iwconfig' + iface + 'mode monitor')
    except:
        print('Failed to set up interface in monitor')
        sys.exit(1)
    os.system('ifconfig' + iface + 'up')
    return iface 

# Define a function to track whether we have root privileges

def check_root()
    if not os.geteuid() == 0:
        print('You must be root to run this script effectively')
        exit(1)

#main code body
        
if name == '_main_':
    signal.signal(signal.SIGINT, signal_handler)
    usage()
    check_root()
    parameters = {sysargv[1]:sys.argv[2]}
    if 'mon' not in str(parameters['-i']):
        newiface = setup_monitor(parameters['-i'])
    else:
        newiface = str(parameters['-i'])
    init_process()
    print('Starting my Wifi Sniffer')
    print('Sniffing in interface' str(newiface) + '...\n')