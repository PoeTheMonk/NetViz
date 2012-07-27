"""
ARP / RARP module (version 1.0 rev 9/24/2011) for Python 2.7
Copyright (c) 2011 Andreas Urbanski.
Contact the me via e-mail: urbanski.andreas@gmail.com

This module is a collection of functions to send out ARP (or RARP) queries
and replies, resolve physical addresses associated with specific ips and
to convert mac and ip addresses to different representation formats. It
also allows you to send out raw ethernet frames of your preferred protocol
type. DESIGNED FOR USE ON WINDOWS.

NOTE: Some functions in this module use winpcap for windows. Please make
sure that wpcap.dll is present in your system to use them.

LICENSING:
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
"""

__all__ = ['showhelp', 'find_device', 'open_device', 'close_device', 'send_raw',
'multisend_raw', 'arp_resolve', 'arp_reply', 'rarp_reply','mac_straddr',
'ip_straddr', 'ARP_REQUEST', 'ARP_REPLY', 'RARP_REQUEST', 'RARP_REPLY',
'FRAME_SAMPLE']

""" Set this to True you wish to see warning messages """
__warnings__ = False

from ctypes import *
import socket
import struct
import time

FRAME_SAMPLE = """
Sample ARP frame
+-----------------+------------------------+
| Destination MAC | Source MAC             |
+-----------------+------------------------+
| \\x08\\x06 (arp)  | \\x00\\x01  (ethernet)   |
+-----------------+------------------------+
| \\x08\\x00 (internet protocol)             |
+------------------------------------------+
| \\x06\\x04 (hardware size & protocol size) |
+------------------------------------------+
| \\x00\\x02 (type: arp reply)               | 
+------------+-----------+-----------------+
| Source MAC | Source IP | Destination MAC |
+------------+---+-------+-----------------+
| Destination IP | ... Frame Length: 42 ...
+----------------+
"""

""" Frame header bytes """
ARP_REQUEST = "\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01"
ARP_REPLY = "\x08\x06\x00\x01\x08\x00\x06\x04\x00\x02"
RARP_REQUEST = "\x80\x35\x00\x01\x08\x00\x06\x04\x00\x03"
RARP_REPLY = "\x80\x35\x00\x01\x08\x00\x06\x04\x00\x04"
""" Defines """
ARP_LENGTH = 42
RARP_LENGTH = 42
DEFAULT = 0

""" Look for wpcap.dll """
try:
    wpcap = cdll.wpcap
except WindowsError:
    print "Error loading wpcap.dll! Ensure that winpcap is properly installed."
    
""" Loading Windows system libraries should not be a problem """
try:
    iphlpapi = windll.Iphlpapi
    ws2_32 = windll.ws2_32
except WindowsError:
    """ Should it still fail """
    print "Error loading windows system libraries!"

""" Import functions """
if wpcap:
    """ Looks up for devices """
    pcap_lookupdev = wpcap.pcap_lookupdev
    """ Opens a device instance """
    popen_live = wpcap.pcap_open_live
    """ Sends raw ethernet frames """
    pcap_sendpacket = wpcap.pcap_sendpacket
    """ Close and cleanup """
    pcap_close = wpcap.pcap_close

""" Find the first device available for use. If this fails
to retrieve the preferred network interface identifier,
disable all other interfaces and it should work."""
def find_device():
    errbuf = create_string_buffer(256)
    device = c_void_p
    
    device = pcap_lookupdev(errbuf)

    return device

""" Get the handle to a network device. """
def open_device(device=DEFAULT):
    errbuf = create_string_buffer(256)
    
    if device == DEFAULT:
        device=find_device()

    """ Get a handle to the ethernet device """
    eth = popen_live(device, 4096, 1, 1000, errbuf)

    return eth

""" Close the device handle """
def close_device(device):
    pcap_close(device)

""" Send a raw ethernet frame """
def send_raw(device, packet):
    if not pcap_sendpacket(device, packet, len(packet)):
        return len(packet)

""" Send a list of packets at the specified interval """
def multisend_raw(device, packets=[], interval=0):
    """ Bytes sent """
    sent = 0
    for p in packets:
        sent += len(p)
        send_raw(device, p)
        time.sleep(interval)
        
    """ Return the number of bytes sent"""
    return sent

""" Resolve the mac address associated with the
destination ip address"""
def arp_resolve(destination, strformat=True, source=None):
    
    mac_addr = (c_ulong*2)()
    addr_len = c_ulong(6)
    dest_ip = ws2_32.inet_addr(destination)
    
    if not source:
        src_ip = ws2_32.inet_addr(socket.gethostbyname(socket.gethostname()))
    else:
        src_ip = ws2_32.inet_addr(source)

    """
    Iphlpapi SendARP prototype
    DWORD SendARP(
      __in     IPAddr DestIP,
      __in     IPAddr SrcIP,
      __out    PULONG pMacAddr,
      __inout  PULONG PhyAddrLen
    );
    """
    error = iphlpapi.SendARP(dest_ip, src_ip, byref(mac_addr), byref(addr_len))

    if error:
        if __warnings__: print "Warning: SendARP failed! Error code:", error

    if strformat:
        return mac_straddr(mac_addr)
    else:
        return mac_addr

""" Send a (gratuitous) ARP reply """
def arp_reply(dest_ip, dest_mac, src_ip, src_mac):

    """ Test input formats """
    if dest_ip.find('.') != -1:
        dest_ip = ip_straddr(dest_ip)
    if src_ip.find('.') != -1:
        src_ip = ip_straddr(src_ip)

    """ Craft the arp packet """
    arp_packet = dest_mac+src_mac+ARP_REPLY+src_mac+src_ip+\
                 dest_mac+dest_ip
    
    if len(arp_packet) != ARP_LENGTH:
        return -1
    
    return send_raw(open_device(), arp_packet)

""" Include RARP for consistency :)"""
def rarp_reply(dest_ip, dest_mac, src_ip, src_mac):

    """ Test input formats """
    if dest_ip.find('.') != -1:
        dest_ip = ip_straddr(dest_ip)
    if src_ip.find('.') != -1:
        src_ip = ip_straddr(src_ip)

    """ Craft the rarp packet """
    rarp_packet = dest_mac+src_mac+RARP_REPLY+src_mac+src_ip+\
                 src_mac+src_ip
    
    if len(rarp_packet) != RARP_LENGTH:
        return -1
    return send_raw(open_device(), rarp_packet)

""" Convert c_ulong*2 to a hexadecimal string or a printable ascii
string delimited by the 3rd parameter"""
def mac_straddr(mac, printable=False, delimiter=None):
    """ Expect a list of length 2 returned by arp_query """
    if len(mac) != 2:
        return -1
    if printable:
        if delimiter:
            m = ""
            for c in mac_straddr(mac):
                m += "%02x" % ord(c) + delimiter
            return m.rstrip(delimiter)
        
        return repr(mac_straddr(mac)).strip("\'")
    
    return struct.pack("L", mac[0])+struct.pack("H", mac[1])

""" Convert address in an ip dotted decimal format to a hexadecimal
string """
def ip_straddr(ip, printable=False):
    ip_l = ip.split(".")
    if len(ip_l) != 4:
        return -1

    if printable:
        return repr(ip_straddr(ip)).strip("\'")
    
    return struct.pack(
        "BBBB",
        int(ip_l[0]),
        int(ip_l[1]),
        int(ip_l[2]),
        int(ip_l[3])
        )

def showhelp():
    helpmsg = """ARP MODULE HELP (Press ENTER for more or CTRL-C to break)

Constants:
    Graphical representation of an ARP frame
    FRAME_SAMPLE
    
    Headers for crafting ARP / RARP packets
    ARP_REQUEST, ARP_REPLY, RARP_REQUEST, RARP_REPLY

    Other
    ARP_LENGTH, RARP_LENGTH, DEFAULT

Functions:
    find_device() - Returns an identifier to the first available network
    interface.
    open_device(device=DEFAULT) - Returns a handle to an available network
    device.

    close_device() - Close the previously opened handle.

    send_raw(device, packet) - Send a raw ethernet frame. Returns
    the number of bytes sent.

    multisend_raw(device, packetlist=[], interval=0) - Send multiple packets
    across a network at the specified interval. Returns the number of bytes
    sent.

    arp_resolve(destination, strformat=True, source=None) - Returns the mac
    address associated with the ip specified by 'destination'. The destination
    ip is supplied in dotted decimal string format. strformat parameter
    specifies whether the return value is in a hexadecimal string format or
    in list format (c_ulong*2) which can further be formatted using
    the 'mac_straddr' function (see below). 'source' specifies the ip address
    of the sender, also supplied in dotted decimal string format.

    arp_reply(dest_ip, dest_mac, src_ip, src_mac) - Send gratuitous ARP
    replies. This can be used for ARP spoofing if the parameters are chosen
    correctly. dest_ip is the destination ip in either dotted decimal
    string format or hexadecimal string format (returned by 'ip_straddr').
    dest_mac is the destination mac address and must be in hexadecimal
    string format. If 'arp_resolve' is used with strformat=True the return
    value can be used directly. src_ip specifies the ip address of the
    sender and src_mac the mac address of the sender.

    rarp_reply(dest_ip, dest_mac, src_ip, src_mac) - Send gratuitous RARP
    replies. Operates similar to 'arp_reply'.

    mac_straddr(mac, printable=False, delimiter=None) - Convert a mac
    address in list format (c_ulong*2) to normal hexadecimal string
    format or printable format. Alternatively a delimiter can be specified
    for printable formats, e.g ':' for ff:ff:ff:ff:ff:ff.

    ip_straddr(ip, printable=False) - Convert an ip address in
    dotted decimal string format to hexadecimal string format. Alternatively
    this function can output a printable representation of the hex
    string format.
"""
    for line in helpmsg.split('\n'):
        print line,
        raw_input('')
    
    
    
if __name__ == "__main__":
    """ Test the module by sending an ARP query """
    ip = "192.168.1.1"
    result = arp_resolve(ip, 0)
    print ip, "is at", mac_straddr(result, 1, ":")


