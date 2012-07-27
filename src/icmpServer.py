
import socket, os, ping, threading
from struct import pack, unpack
#from uuid import getnode as get_mac #allows you to get your own MAC address

listening = False

def getICMPSock():
    ''' Gets raw socket (requires root) for sending ICMP pings '''
    icmp = socket.getprotobyname("icmp")
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    except socket.error, (errno, msg):
        if errno == 1:
            # Operation not permitted
            msg = msg + (
                " - Note that ICMP messages can only be sent from processes"
                " running as root."
            )
            raise socket.error(msg)
        raise # raise the original error
    return my_socket

def listen(sock = None):
    HOST = socket.gethostbyname(socket.gethostname())
    if (sock):
        s = sock
    else:
        s = getICMPSock()
    s.bind((HOST, 0))
    global listening
    listening = True
    while listening:
        frame, addr = s.recvfrom(8192)
        TYPE = None
        #ID = frame[24:26]
        #SEQ = frame[26:28]
        if (frame[20] == '\x00'): #Packet is response
            TYPE = 'Ping response'
        elif (frame[20] == '\x08'): #Packet is request
            TYPE = 'Ping request'
        if (TYPE != None):
            print TYPE, "recieved from", addr[0]

if __name__ == '__main__':
    errorText = ''
    #assert(False) #I put this in here to remind you to change the two lines after this
    starting = '192.168.1.1'.split('.')
    ending = '192.168.1.255'.split('.')
    ipList = []
    starting3 = int(starting[2])
    ending3 = int(ending[2])
    starting4 = int(starting[3])
    ending4 = int(ending[3])
    while starting3 <= ending3:
        while starting4 <= ending4:
            ip = starting[0] + '.' + starting[1] + '.'
            ip += str(starting3) + '.'+ str(starting4)
            ipList.append(ip)
            starting4 += 1
        starting4 = 0
        starting3 += 1
    s = getICMPSock()
    
    it = threading.Thread(target=ping.netVizPingArray, args=(getICMPSock(), ipList))
    it.start()
    listen(s)
