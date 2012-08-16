# Hello World. Here goes nothing.
# This is a Python script for my network visualizer program.
# Maybe it can go on the Technology Club website.
# (Copyright) 2012 by Mark Miller, Paul Ernst

# To-Do list
# button-press to sync
# delete tracked macs
# pretty-fy

#-----Import Modules-----#
import pygame, os, commands, time, threading, math, socket, select, ping
from struct import pack, unpack
if (os.name == 'nt'):
    import arp

#-----Definitions-----#

def winCommand(cmd):
    pipe = os.popen(cmd)
    ret = pipe.read()
    pipe.close()
    return ret    

def safeOpenMyCSV(filename):
    try:
        file = open(filename)
        file = file.read()
        file = file.split('\n')
        list = []
        for line in file:
            line = line.split(', ')
            list.append(line)
        return list
        file.close()
    except IOError as e:
        return(None)

def MACToObj(mac, listToSearch):
    'Returns the current unit object of a given MAC address, if possible.'
    a = None
    for element in listToSearch:
        if element.mac == mac:
            a = element
    return a

def netVizPingArray(my_socket, iplist, findingMac = False, findingDNS = False, ID = None):
    startTime = time.time()
    print "Pinger start"
    if not(bool(ID)):
        ID = os.getpid() & 0xFFFF
    for i in range(2):
        for ip in iplist:
            ping.netVizPing(my_socket, ip, ID)
            time.sleep(0.001)
    my_socket.close()
    print "Ping done, MAC next"
    pingTime = time.time()
    ipLen = range(len(iplist))
    macAnswer = range(len(iplist))
    if (findingMac):
        for i in ipLen:
            tmp = findmac(iplist[i])
            macAnswer[i] = tmp
            pingMACLock.acquire()
            pingMACStack.append([iplist[i], tmp])
            pingMACLock.release()
    print "MAC done, DNS next"
    macTime = time.time()
    if (findingDNS):
        for i in ipLen:
            if not(findingMac) or not(macAnswer[i].startswith('n') or macAnswer[i].startswith('(')): # assume that if no mac address, no dns)
                tmp = findDNS(iplist[i])
                pingDNSLock.acquire()
                pingDNSStack.append([iplist[i], tmp])
                pingDNSLock.release()
    print "DNS Done"
    dnsTime = time.time()
    print(pingTime - startTime, macTime - pingTime, dnsTime - macTime)
    print('Pinger exited')

def findDNS(ip):
    #if (os.name == 'nt'):
    try:
        result = socket.gethostbyaddr(ip)
    except:
        result = ("Not found", "", ip)
    return result[0]

def findmac(ip):
    'Returns the MAC address (str) given an IP.'
    if (os.name == 'nt'):
        result = arp.arp_resolve(ip, 0)
        result = arp.mac_straddr(result, 1, ":")
        if (result == '00:00:00:00:00:00'):
            #self.mac = 'no'
            return 'no'
        else:
            #self.mac = result
            return result
    result = commands.getoutput('arp ' + ip)
    result = result.split(' ')
    if len(result) > 2:
        result = result.pop(3) # if there is no MAC address, it will reply 'no'.
        #self.mac = result
        return result

def findOwnIP():
##    if (os.name == "nt"):
##        ipconfig = winCommand("ipconfig")
##        iploc = ipconfig.find("IP Address")
##        return ipconfig[iploc + 36:ipconfig.find("\r", iploc)]
##    return commands.getoutput('ifconfig en1 | grep inet | grep -v inet6 | cut -d" " -f2')
    return socket.gethostbyname(socket.gethostname())
    
def findNetworkBoundaries():
    if (os.name == 'nt'):
        ipconfig = winCommand("ipconfig")
        DGloc = ipconfig.find("Default Gateway")
        defaultGateway = ipconfig[DGloc + 36:ipconfig.find("\r", DGloc)]
        SMloc = ipconfig.find("Subnet Mask")
        SubnetMask = ipconfig[SMloc + 36:ipconfig.find("\r", SMloc)]
        mask = SubnetMask.split('.')
        dg = defaultGateway.split('.')
        intdg = [0, 0, 0, 0]
        for i in range(0, 4): #Convert strings into ints and find highest IP address
            intdg[i] = int(dg[i]) + (255 ^ int(mask[i]))
            intdg[i] = intdg[i] + ((255 - intdg[i]) & ((255 - intdg[i]) >> 31)) #intdg[i] = 255 or less
        endingIP = str(intdg[0]) + '.' + str(intdg[1]) + '.' + str(intdg[2]) + '.' + str(intdg[3])
        return (defaultGateway, endingIP)
    endingIP = commands.getoutput('ifconfig en1 | grep inet | grep -v inet6 | cut -d" " -f6')
    netmask = commands.getoutput('ifconfig en1 | grep inet | grep -v inet6 | cut -d" " -f4')
    intmask = int(netmask[2:], 16)
    endingIPArray = endingIP.split('.')
    ipTotal = 0
    for segment in endingIPArray:
        ipTotal *= 256
        ipTotal += int(segment)
    
    ipTotal &= intmask
    
    startingIP = ''
    for section in range(3, -1, -1):
        nnumber = ipTotal / (256**section)
        ipTotal -= nnumber * (256**section)
        startingIP += str(nnumber)
        if section != 0:
            startingIP += '.'
    
    return(startingIP, endingIP)

def rfp(a, b, c, d):
    return pygame.Rect(a, b, c-a, d-b)
    
def findMACOwner(owners, mac):
    owner = 'Not Found'
    if mac != 'no' and not(mac.startswith('(')):
        e = mac.split(':')
        f = e[0] + ':' + e[1] + ':' + e[2]
        try:
            owner = owners[f]
        except KeyError:
            owner = 'Not Found'
    return owner
    
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
    while icmpsRunning:
        startedSelect = time.time()
        whatReady = select.select([s], [], [], 5)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []: # Timeout
            #print("timeout")
            continue
        frame, addr = s.recvfrom(8192)
        TYPE = None
        #ID = frame[24:26]
        #SEQ = frame[26:28]
        if (frame[20] == '\x00'): #Packet is response
            TYPE = 'Ping response'
        elif (frame[20] == '\x08'): #Packet is request
            TYPE = 'Ping request'
        if (TYPE != None):
            pingIPLock.acquire()
            pingIPStack.append(addr[0])
            pingIPLock.release()
    s.close()
    print('ICMPS exited')

class Button:
    def __init__(self, name, x, y, guyArray,
                 text='',
                 textColor=(0, 0, 0),
                 textFont=None,
                 style='rectangle',
                 color=(255, 255, 255),
                 borderColor=(0,0,0),
                 borderSize=1,
                 height=None,
                 width=None,
                 rounding=None,
                 shadow='none',
                 mouseover='none',
                 image=None):
        self.buttonSurface = None
        self.x = x
        self.y = y
        self.name = name
        if guyArray != None:
            guyArray.append(self)
        if text != '' and textFont != None:
            textSurface = textFont.render(text, 1, textColor, color)
            if width == None:
                safeWidth = textSurface.get_width() + 1 + borderSize
            if height == None:
                safeHeight = textSurface.get_height() + 1 + borderSize
        if image != None:
            self.buttonSurface = pygame.Surface((width, height))
            self.height = height
            self.width = width
            self.buttonSurface.blit(image, (1, 1))
        elif style == 'rounded':
            if height == None:
                height = safeHeight + 2 * borderSize
                if rounding == None:
                    rounding = height / 2
                if height < rounding * 2:
                    height = rounding * 2
            if width == None:
                width = safeWidth + 2*borderSize + 2*rounding
            if rounding == None:
                rounding = height / 2
            buttonSurface = pygame.Surface((width, height))
            buttonSurface.fill(backgroundColor)
            pygame.draw.ellipse(buttonSurface, borderColor, rfp(0, 0, rounding*2, rounding*2))
            pygame.draw.ellipse(buttonSurface, borderColor, rfp(0, height-rounding*2, rounding*2, height))
            pygame.draw.ellipse(buttonSurface, borderColor, rfp(width-rounding*2, 0, width, rounding*2))
            pygame.draw.ellipse(buttonSurface, borderColor, rfp(width-rounding*2, height-rounding*2, width, height))
            buttonSurface.fill(borderColor, rfp(0, rounding, borderSize, height-rounding))
            buttonSurface.fill(borderColor, rfp(rounding, 0, width-rounding, borderSize))
            buttonSurface.fill(borderColor, rfp(width-borderSize, rounding, width, height-rounding))
            buttonSurface.fill(borderColor, rfp(rounding, height-borderSize, width-rounding, height))
            buttonSurface.fill(color, rfp(borderSize, rounding, width-borderSize, height-rounding))
            buttonSurface.fill(color, rfp(rounding, borderSize, width-rounding, rounding))
            buttonSurface.fill(color, rfp(rounding, height-rounding, width-rounding, height-borderSize))
            pygame.draw.ellipse(buttonSurface, color, pygame.Rect(borderSize, borderSize, (rounding-borderSize)*2, (rounding-borderSize)*2))
            pygame.draw.ellipse(buttonSurface, color, pygame.Rect(width+borderSize-rounding*2, borderSize, (rounding-borderSize)*2, (rounding-borderSize)*2))
            pygame.draw.ellipse(buttonSurface, color, pygame.Rect(borderSize, height+borderSize-rounding*2, (rounding-borderSize)*2, (rounding-borderSize)*2))
            pygame.draw.ellipse(buttonSurface, color, pygame.Rect(width+borderSize-rounding*2, height+borderSize-rounding*2, (rounding-borderSize)*2, (rounding-borderSize)*2))
            if textSurface != None:
                buttonSurface.blit(textSurface, (rounding, borderSize))
            self.buttonSurface = buttonSurface
            (self.width, self.height) = buttonSurface.get_size()
        else:
            if height == None:
                height = safeHeight + 2*borderSize
            if width == None:
                width = safeWidth + 2*borderSize
            buttonSurface = pygame.Surface((width, height))
            buttonSurface.fill(borderColor)
            buttonSurface.fill(color, rfp(borderSize, borderSize, width-borderSize, height-borderSize))
            buttonSurface.blit(textSurface, (borderSize + 1, borderSize + 1))
            self.buttonSurface = buttonSurface
            (self.width, self.height) = buttonSurface.get_size()
    
    def draw(self, screen):
        screen.blit(self.buttonSurface, (self.x, self.y))


class Text:
    def __init__(self, name, x, y, text, textFont, guyArray,
                 textColor=(0, 0, 0),
                 backgroundColor=(255, 255, 255)):
        self.x = x
        self.y = y
        self.name = name
        if guyArray != None:
            guyArray.append(self)
        self.textSurface = textFont.render(text, 1, textColor, backgroundColor)
        (self.width, self.height) = self.textSurface.get_size()
    def draw(self, screen):
        screen.blit(self.textSurface, (self.x, self.y))
    

class InputBox:
    def __init__(self, name, x, y, guyArray,
                 textColor=(0, 0, 0),
                 textFont=None,
                 style='rectangle',
                 color=(255, 255, 255),
                 borderColor=(0,0,0),
                 borderSize=1,
                 height=None,
                 width=None,
                 rounding=None,
                 shadow='none',
                 mouseover='none'):
        self.x = x
        self.y = y
        self.textFont = textFont
        self.textColor = textColor
        self.color = color
        self.name = name
        if guyArray != None:
            guyArray.append(self)
        safeSurf = textFont.render('255.255.255.255', 1, textColor, color)
        (safeWidth, safeHeight) = safeSurf.get_size()
        inputSurface = pygame.Surface((int(safeWidth + 2 * borderSize + 2),
                                      int(safeHeight + 2 * borderSize + 2)))
        (self.width, self.height) = inputSurface.get_size()
        inputSurface.fill(borderColor)
        inputSurface.fill(color, rfp(borderSize, borderSize,
                                     self.width-borderSize,
                                     self.height-borderSize))
        self.inputSurface = inputSurface
    def draw(self, screen, inputString):
        textFont = self.textFont
        inputSurface = self.inputSurface
        inputText = textFont.render(inputString, 1, self.textColor, self.color)
        inputSurfaceCopy = inputSurface.copy()
        inputSurfaceCopy.blit(inputText, (2, 2))
        screen.blit(inputSurfaceCopy, (self.x, self.y))


class Toggle:
    def __init__(self, name, x, y, guyArray,
                 text='',
                 textColor=(0, 0, 0),
                 textFont=None,
                 style='rectangle',
                 color=(255, 255, 255),
                 borderColor=(0,0,0),
                 borderSize=1,
                 height=None,
                 width=None,
                 rounding=None,
                 shadow='none',
                 mouseover='none',
                 toggled=False):
        self.buttonSurface = None
        self.x = x
        self.y = y
        self.name = name
        self.toggled = toggled
        if guyArray != None:
            guyArray.append(self)
        if text != '' and textFont != None:
            textSurface = textFont.render(text, 1, textColor, color)
            if width == None:
                safeWidth = textSurface.get_width() + 2
            if height == None:
                safeHeight = textSurface.get_height() + 2
        if style == 'rounded':
            if height == None:
                height = safeHeight + 2 * borderSize
                if rounding == None:
                    rounding = height / 2
                if height < rounding * 2:
                    height = rounding * 2
            if width == None:
                width = safeWidth + 2*borderSize + 2*rounding
            if rounding == None:
                rounding = height / 2
            buttonSurface = pygame.Surface((width, height))
            buttonSurface.fill(backgroundColor)
            pygame.draw.ellipse(buttonSurface, borderColor, rfp(0, 0, rounding*2, rounding*2))
            pygame.draw.ellipse(buttonSurface, borderColor, rfp(0, height-rounding*2, rounding*2, height))
            pygame.draw.ellipse(buttonSurface, borderColor, rfp(width-rounding*2, 0, width, rounding*2))
            pygame.draw.ellipse(buttonSurface, borderColor, rfp(width-rounding*2, height-rounding*2, width, height))
            buttonSurface.fill(borderColor, rfp(0, rounding, borderSize, height-rounding))
            buttonSurface.fill(borderColor, rfp(rounding, 0, width-rounding, borderSize))
            buttonSurface.fill(borderColor, rfp(width-borderSize, rounding, width, height-rounding))
            buttonSurface.fill(borderColor, rfp(rounding, height-borderSize, width-rounding, height))
            buttonSurface.fill(color, rfp(borderSize, rounding, width-borderSize, height-rounding))
            buttonSurface.fill(color, rfp(rounding, borderSize, width-rounding, rounding))
            buttonSurface.fill(color, rfp(rounding, height-rounding, width-rounding, height-borderSize))
            pygame.draw.ellipse(buttonSurface, color, pygame.Rect(borderSize, borderSize, (rounding-borderSize)*2, (rounding-borderSize)*2))
            pygame.draw.ellipse(buttonSurface, color, pygame.Rect(width+borderSize-rounding*2, borderSize, (rounding-borderSize)*2, (rounding-borderSize)*2))
            pygame.draw.ellipse(buttonSurface, color, pygame.Rect(borderSize, height+borderSize-rounding*2, (rounding-borderSize)*2, (rounding-borderSize)*2))
            pygame.draw.ellipse(buttonSurface, color, pygame.Rect(width+borderSize-rounding*2, height+borderSize-rounding*2, (rounding-borderSize)*2, (rounding-borderSize)*2))
            if textSurface != None:
                buttonSurface.blit(textSurface, (rounding, borderSize))
            self.buttonSurface = buttonSurface
            (self.width, self.height) = buttonSurface.get_size()
        else:
            if height == None:
                height = safeHeight + 2*borderSize
            if width == None:
                width = safeWidth + 2*borderSize
            buttonSurface = pygame.Surface((width, height))
            buttonSurface.fill(borderColor)
            buttonSurface.fill(color, rfp(borderSize, borderSize, width-borderSize, height-borderSize))
            buttonSurface.blit(textSurface, (borderSize + 1, borderSize + 1))
            self.buttonSurface = buttonSurface
            (self.width, self.height) = buttonSurface.get_size()
            toggleSurface = pygame.Surface((width, height))
            toggleSurface.fill(borderColor)
            toggleSurface.fill((153, 153, 153), rfp(borderSize, borderSize, width-borderSize, height-borderSize))
            toggleSurface.blit(textFont.render(text, 1, textColor, (153, 153, 153)), (borderSize + 1, borderSize + 1))
            self.toggleSurface = toggleSurface
    
    def draw(self, screen):
        if self.toggled:
            screen.blit(self.toggleSurface, (self.x, self.y))
        else:
            screen.blit(self.buttonSurface, (self.x, self.y))


class PictureToggle:
    def __init__(self, name, x, y, guyArray, height,
                 width, unpressed, pressed, toggled=False):
        self.name = name
        self.x = x
        self.y = y
        self.toggled = toggled
        self.height = height
        self.width = width
        self.pressed = pygame.Surface((width, height))
        self.unpressed = pygame.Surface((width, height))
        self.unpressed.blit(unpressed, (1, 1))
        self.pressed.blit(pressed, (1, 1))
        if guyArray != None:
            guyArray.append(self)
    
    def draw(self, screen):
        if self.toggled:
            screen.blit(self.pressed, (self.x, self.y))
        else:
            screen.blit(self.unpressed, (self.x, self.y))


class TrackedMAC:
    def __init__(self, MAC, name):
        self.MAC = MAC
        self.inRange = False
        self.online = False
        self.name = name
        self.ip = None


class MACTrackRunner:
    def __init__(self, trackMACList, font):
        self.trackMACList = trackMACList
        self.font = font
        #draw basic background
        background = pygame.Surface((344, 266))
        background.fill((255, 255, 255), rfp(1, 1, 330, 265))
        nameText = Text('nameText', 1, 1, 'Name', font, None)
        background.blit(nameText.textSurface, (2, 1))
        (width1, height1) = font.size('False')
        (width2, height2) = font.size('255.255.255.255')
        nameWidth = width1 + width2
        nameWidth = 331 - nameWidth - 6
        pingText = Text('pingText', 0, 0, 'Ping', font, None)
        background.blit(pingText.textSurface, (nameWidth + 3, 1))
        self.startPing = nameWidth
        nameWidth += width1 + 3
        self.startIP = nameWidth
        IPText = Text('IPText', 0, 0, 'IP', font, None)
        background.blit(IPText.textSurface, (nameWidth + 3, 1))
        background.fill((0, 0, 0), rfp(3, 17, 328, 18))
        background.fill((255, 255, 255), pygame.Rect(330, 1, 13, 16))
        self.background = background
        self.sliderHeight = None
        self.sliderPosition = 0
        
    def organize(self, criterion):
        if criterion == 'name':
            trackedNames = []
            for element in self.trackMACList:
                trackedNames.append(element.name)
            trackedNames.sort()
            sortTrackedMacs = []
            for name in trackedNames:
                continue_ = True
                for element in self.trackMACList:
                    if element.name == name and continue_:
                        continue_ = False
                        sortTrackedMacs.append(element)
            self.trackMACList = list(sortTrackedMacs)
        elif criterion == 'ping':
            pingTrues = []
            pingFalses = []
            for element in self.trackMACList:
                if element.online:
                    pingTrues.append(element)
                else:
                    pingFalses.append(element)
            pingTrues.extend(pingFalses)
            self.trackMACList = list(pingTrues)
        self.drawMACList()
        
    def drawMACList(self):
        font = self.font
        index = 0
        lineSize = font.get_linesize()
        MACsSurf = pygame.Surface((340, len(self.trackMACList) * lineSize))
        for element in self.trackMACList:
            nameSurf = font.render(element.name, 1, (0, 0, 0), (255, 255, 255))
            pingSurf = font.render(str(element.online), 1, (0, 0, 0), (255, 255, 255))
            IPSurf = font.render(element.ip, 1, (0, 0, 0), (255, 255, 255))
            
            rect = pygame.Rect(0, index * lineSize, 328, lineSize)
            MACsSurf.fill((255, 255, 255), rect)
            MACsSurf.blit(nameSurf, (0, index*lineSize))
            MACsSurf.blit(pingSurf, (self.startPing, index*lineSize))
            MACsSurf.blit(IPSurf, (self.startIP, index*lineSize))
            index += 1
        self.sliderHeight = 61009.0 / (MACsSurf.get_height() + 1)
        
        self.MACsSurf = MACsSurf
    def draw(self, screen):
        giveaway = self.background.copy()
        cutoffPoint = 247 * self.sliderPosition / self.sliderHeight
        giveaway.blit(self.MACsSurf, (2, 18), pygame.Rect(0, cutoffPoint, 328, 247))
        giveaway.fill((255, 255, 255), pygame.Rect(331, 18 + self.sliderPosition, 12, self.sliderHeight))
        giveaway.fill((0, 0, 0), pygame.Rect(330, 265, 14, 1))
        screen.blit(giveaway, (8, 248))


class Unit:
    def __init__(self, ip):
        self.ip = ip
        self.mac = '(Not Searched)'
        self.online = False
        #self.color = (0, 0, 0)
        self.ownIP = False
        self.username = ''
        self.dns = ''
        self.owner = 'Not Found'


class UnitManager:
    def __init__(self, startIP, endIP):
        startIP = startIP.split('.')
        startNum = [0, 0, 0, 0]
        endIP = endIP.split('.')
        endNum = [0, 0, 0, 0]
        dif = [0, 0, 0, 0]
        for i in range(4):
            startNum[i] = int(startIP[i])
            endNum[i] = int(endIP[i])
            dif[i] = endNum[i] - startNum[i] + 1
        tmp = list(startNum)
        self.unitList = range(dif[0] * dif[1] * dif[2] * dif[3])
        self.ipList = list(self.unitList)
        while(tmp[0] <= endNum[0]):
            while(tmp[1] <= endNum[1]):
                while(tmp[2] <= endNum[2]):
                    while(tmp[3] <= endNum[3]):
                        index = ((tmp[0] - startNum[0]) * dif[1] * dif[2] * dif[3] + (tmp[1] - startNum[1])
                            * dif[2] * dif[3] + (tmp[2] - startNum[2]) * dif[3] + tmp[3] - startNum[3])
                        self.unitList[index] = Unit(str(tmp[0]) + '.' + str(tmp[1]) + '.' + str(tmp[2]) + '.' + str(tmp[3]))
                        self.ipList[index] = str(tmp[0]) + '.' + str(tmp[1]) + '.' + str(tmp[2]) + '.' + str(tmp[3])
                        tmp[3] += 1
                    tmp[2] += 1
                    tmp[3] = startNum[3]
                tmp[1] += 1
                tmp[2] = startNum[2]
            tmp[0] += 1
            tmp[1] = startNum[1]
        self.startNum = startNum
        self.endNum = endNum
        self.dif = dif
        
    def getUnit(self, IP):
        tmpIP = IP.split('.')
        tmpNum = [0, 0, 0, 0]
        for i in range(4):
            tmpNum[i] = int(tmpIP[i])
            if not(0 <= tmpNum[i] - self.startNum[i] < self.dif[i]):
                return None
        return self.unitList[(tmpNum[0] - self.startNum[0]) * self.dif[1] * self.dif[2] * self.dif[3] + (tmpNum[1] - self.startNum[1])
            * self.dif[2] * self.dif[3] + (tmpNum[2] - self.startNum[2]) * self.dif[3] + tmpNum[3] - self.startNum[3]]

    def pingAll(self):
        pt = threading.Thread(target=netVizPingArray, name='Pinger', args=(getICMPSock(),
            list(self.ipList), searchMACToggle.toggled, searchDNSToggle.toggled))
        pt.setDaemon(True)
        print "pt.start()"
        pt.start()
        print "pt started"


#-----Settings / Options-----#
width = 960
height = 600
backgroundColor = (255, 255, 255)
fps = 15
mouse_x = 0
mouse_y = 0

#-----Global Important Stuff-----#
running = 1
icmpsRunning = 1
globalUnitManager = UnitManager(findOwnIP(), findOwnIP())
guyArray = []
displayIPStart = ''
displayIPEnd = ''
selectedBox = None
ownIP = ''
selectedIP = None
stepCount = 0
dialogStatus = 0
dialogArray = []
errorText = ''
sidebarSelected = False
pingIPStack = []
pingIPLock = threading.Lock()
pingMACStack = []
pingMACLock = threading.Lock()
pingDNSStack = []
pingDNSLock = threading.Lock()

#-----Pre-Game Setup-----#
screen = pygame.display.set_mode((width,height))
pygame.font.init()

#-----Images-----#
DNSImage = pygame.image.load('DNS.png').convert()
DNSPressedImage = pygame.image.load('DNS_pressed.png').convert()
MACPressedImage = pygame.image.load('MAC_pressed.png').convert()
MACImage = pygame.image.load('MAC.png').convert()
RefreshImage = pygame.image.load('refresh.png').convert()
ConstantUpdateImage = pygame.image.load('constantupdate.png').convert()
ConstantUpdatePressedImage = pygame.image.load('constantupdate_pressed.png').convert()
DeleteImage = pygame.image.load('delete.png').convert()

#-----Fonts-----#
fontLink = 'menlo.ttc'
FONT20 = pygame.font.Font(fontLink, 12)
FONT12 = pygame.font.Font(fontLink, 12)
FONT40 = pygame.font.Font(fontLink, 40)

#-----Set Up GUI-----#
findRangeButton = Button('findRangeButton', 24, 96, guyArray, text='Find Range', textFont=FONT20,
                         style='rounded', color=(153, 153, 153), borderSize=1)
setRangeButton = Button('setRangeButton', 120, 96, guyArray, text='Set Range', textFont=FONT20,
                        style='rounded', color=(153, 153, 153), borderSize=1)
startingIPText = Text('startingIPText', 24, 48, 'Starting IP:', FONT20, guyArray)
endingIPText = Text('endingIPText', 24, 72, 'Ending IP:', FONT20, guyArray)
searchRangeText = Text('searchRangeText', 24, 24, 'SEARCH RANGE', FONT20, guyArray)
startingIPInput = InputBox('startingIPInput', 120, 48, guyArray, textFont=FONT20)
endingIPInput = InputBox('endingIPInput', 120, 72, guyArray, textFont=FONT20)
searchMACToggle = PictureToggle('searchMACToggle', 300, 0, guyArray, 60, 60, MACImage, MACPressedImage, toggled=True)
searchDNSToggle = PictureToggle('searchDNSToggle', 300, 60, guyArray, 60, 60, DNSImage, DNSPressedImage)
constantUpdateToggle = PictureToggle('constantUpdateToggle', 240, 0, guyArray, 60, 60, ConstantUpdateImage, ConstantUpdatePressedImage)

trackSelectedItemButton = Button('trackSelectedItemButton', 24, 530, guyArray, text='Track Selected Item', textFont=FONT20,
                                 style='rounded', color=(153, 153, 153), borderSize=1)
addItemByMACButton = Button('addItemByMACButton', 24, 554, guyArray, text='Add Item by MAC', textFont=FONT20,
                            style='rounded', color=(153, 153, 153), borderSize=1)
refreshButton = Button('refreshButton', 240, 60, guyArray, height=60, width=60, image=RefreshImage)

#-----Set Up MAC Database-----#
MACOwners = {}
file = open('pie.txt', 'r')
s = file.read()
owners = s.split('\n')
for line in owners:
    c = line.split('%%%split%%%')
    name = c.pop()
    a = c.pop()
    a1 = a[0:2].lower()
    a2 = a[2:4].lower()
    a3 = a[4:6].lower()
    if not(os.name == 'nt'):
        if a1[:1] == '0':
            a1 = a1[1:2]
        if a2[:1] == '0':
            a2 = a2[1:2]
        if a3[:1] == '0':
            a3 = a3[1:2]
    asum = a1 + ':' + a2 + ':' + a3
    MACOwners[asum] = name
    
#-----Set Up Tracked MACs-----#
MACs = []
wellthen = safeOpenMyCSV('savedMACs.txt')
if wellthen != None:
    for pair in wellthen:
        if pair != ['']:
            name = pair.pop()
            mac = pair.pop()
            MACs.append(TrackedMAC(mac, name))
MACTracker = MACTrackRunner(MACs, FONT12)

#-----ICMP Server-----#
st = threading.Thread(target=listen, name='ICMPS')
st.setDaemon(True)
st.start()

#-----Game Loop----#
while running:
    #----Measure Time----#
    beginStep = time.time()
    if stepCount % 20 == 0:
        MACTracker.organize('name')
    
    # TODO: IP Constant update
    
    
    #----Process Events----#
    event = pygame.event.poll()
    if event.type == pygame.QUIT:
        file = open('savedMACs.txt', 'w')
        MACs = MACTracker.trackMACList
        macLen = len(MACs)
        num = 0
        for element in MACs:
            num += 1
            file.write(element.MAC + ', ' + element.name)
            if num != macLen:
                file.write('\n')
        icmpsRunning = 0
        running = 0
        break
    
    pingIPLock.acquire() # Receive pings from ICMPS
    if (len(pingIPStack) > 0):
        for u in pingIPStack:
            unit = globalUnitManager.getUnit(u)
            if (unit):
                unit.online = True
        pingIPStack = []
    pingIPLock.release()
    
    pingMACLock.acquire()
    if (len(pingMACStack) > 0):
        for u in pingMACStack:
            unit = globalUnitManager.getUnit(u[0])
            if (unit):
                unit.mac = u[1]
                unit.owner = findMACOwner(MACOwners, u[1])
        pingMACStack = []
    pingMACLock.release()
    
    pingDNSLock.acquire()
    if (len(pingDNSStack) > 0):
        for u in pingDNSStack:
            unit = globalUnitManager.getUnit(u[0])
            if (unit):
                unit.dns = u[1]
        pingDNSStack = []
    pingDNSLock.release()
    
    elementCount = 0
    ipCount = len(globalUnitManager.unitList)
    if ipCount != 0:
        ipPower = 0
        while (1 << ipPower) < ipCount:
            ipPower += 1
        widthCount = 1 << (ipPower/2)
        heightCount = 1 << (ipPower - ipPower/2)
        squareWidth = 512 / widthCount
        squareHeight = 512 / heightCount
    
    if event.type == pygame.MOUSEBUTTONDOWN:
        (mouse_x, mouse_y) = event.pos
        result = ''
        if event.button == 1:
            if dialogStatus != 0:
                if dialogStatus == 1:
                    dialog_x = mouse_x - 390
                    dialog_y = mouse_y - 250
                    for element in dialogArray:
                        if result == '':
                            if element.x <= dialog_x < element.x + element.width:
                                if element.y <= dialog_y < element.y + element.height:
                                    result = element.name
            for guy in guyArray:
                if result == '':
                    if guy.x <= mouse_x < guy.x + guy.width:
                        if guy.y <= mouse_y < guy.y + guy.height:
                            result = guy.name
            if result != '':
                if result == 'findRangeButton':
                    (displayIPStart, displayIPEnd) = findNetworkBoundaries()
                elif result == 'setRangeButton':
                    errorText = ''
                    if (displayIPStart == '' or displayIPEnd == ''):
                        errorText = 'No IP entered'
                    else:
                        globalUnitManager = UnitManager(displayIPStart, displayIPEnd)
                elif result == 'startingIPInput':
                    selectedBox = 1
                elif result == 'endingIPInput':
                    selectedBox = 2
                elif result == 'searchMACToggle':
                    searchMACToggle.toggled = not(searchMACToggle.toggled)
                elif result == 'searchDNSToggle':
                    searchDNSToggle.toggled = not(searchDNSToggle.toggled)
                elif result == 'constantUpdateToggle':
                    constantUpdateToggle.toggled = not(constantUpdateToggle.toggled)
                elif result == 'addItemByMACButton':
                    dialogStatus = 1
                    dialog = pygame.Surface((200, 100))
                    dialog.fill((255, 255, 255), rfp(1, 1, 199, 99))
                    dialog.blit(FONT20.render('MAC:', 1, (0, 0, 0), (255, 255, 255)), (24, 24))
                    dialog.blit(FONT20.render('Name:', 1, (0, 0, 0), (255, 255, 255)), (24, 48))
                    cancelButton = Button('cancelButton', 96, 72, dialogArray, text='Cancel', textFont=FONT20,style='rounded', color=(153, 153, 153))
                    addButton = Button('addButton', 24, 72, dialogArray, text='Add', textFont=FONT20, style='rounded', color=(153, 153, 153))
                    dialogMAC = ''
                    dialogName = ''
                    cancelButton.draw(dialog)
                    addButton.draw(dialog)
                    macInput = InputBox('macInput', 60, 24, dialogArray, textFont=FONT20)
                    nameInput = InputBox('nameInput', 60, 48, dialogArray, textFont=FONT20)
                elif result == 'trackSelectedItemButton':
                    dialogStatus = 1
                    dialog = pygame.Surface((200, 100))
                    dialog.fill((255, 255, 255), rfp(1, 1, 199, 99))
                    dialog.blit(FONT20.render('MAC:', 1, (0, 0, 0), (255, 255, 255)), (24, 24))
                    dialog.blit(FONT20.render('Name:', 1, (0, 0, 0), (255, 255, 255)), (24, 48))
                    if selectedIP != None:
                        if selectedIP.mac != 'no' or not(selectedIP.mac.startswith('(')):
                            dialogMAC = selectedIP.mac
                        else:
                            dialogMAC = ''
                    else:
                        dialogMAC = ''
                    dialogName = ''
                    cancelButton = Button('cancelButton', 96, 72, dialogArray, text='Cancel', textFont=FONT20,style='rounded', color=(153, 153, 153))
                    addButton = Button('addButton', 24, 72, dialogArray, text='Add', textFont=FONT20, style='rounded', color=(153, 153, 153))
                    cancelButton.draw(dialog)
                    addButton.draw(dialog)
                    macInput = InputBox('macInput', 60, 24, dialogArray, textFont=FONT20)
                    nameInput = InputBox('nameInput', 60, 48, dialogArray, textFont=FONT20)
                elif result == 'addButton':
                    MACTracker.trackMACList.append(TrackedMAC(dialogMAC, dialogName))
                    dialogStatus = 0
                    dialogArray = []
                elif result == 'cancelButton':
                    dialogStatus = 0
                    dialogArray = []
                elif result == 'macInput':
                    selectedBox = 3
                elif result == 'nameInput':
                    selectedBox = 4
                elif result == 'refreshButton':
                    globalUnitManager.pingAll()
            elif 404 <= mouse_x < 916:
                if 44 <= mouse_y < 556:
                        number = (mouse_y - 44) / squareHeight * widthCount + (mouse_x - 404) / squareWidth
                        #TODO: fix this eventually
                        wellthen = list(globalUnitManager.unitList) 
                        if len(wellthen) > number:
                            maySelectedIP = wellthen.pop(number)
                            if selectedIP != maySelectedIP:
                                selectedIP = maySelectedIP
                            else:
                                selectedIP = None
            elif 340 <= mouse_x < 352:
                if 266 <= mouse_y < 513:
                    sidebarSelected = True
            elif 324 <= mouse_x < 340:
                if 266 <= mouse_y < 513:
                    cutoffPoint = 247 * MACTracker.sliderPosition / MACTracker.sliderHeight
                    dist = mouse_y - 266 + cutoffPoint
                    lenny = int(dist / (MACTracker.font.get_linesize()))
                    if lenny + 1 <= len(MACTracker.trackMACList):
                        throwaway = MACTracker.trackMACList.pop(lenny)
    
    if event.type == pygame.MOUSEBUTTONUP:
        if event.button == 1:
            sidebarSelected = False
    
    if event.type == pygame.KEYDOWN:
        if event.key == 8: # backspace
            if selectedBox == 1:
                if displayIPStart != '':
                    displayIPStart = displayIPStart[:-1]
            elif selectedBox == 2:
                if displayIPEnd != '':
                    displayIPEnd = displayIPEnd[:-1]
            elif selectedBox == 3:
                if dialogMAC != '':
                    dialogMAC = dialogMAC[:-1]
            elif selectedBox == 4:
                if dialogName != '':
                    dialogName = dialogName[:-1]
        elif event.key == 13: # enter
            selectedBox = 0
        else:
            if selectedBox == 1:
                displayIPStart += event.unicode
            elif selectedBox == 2:
                displayIPEnd += event.unicode
            elif selectedBox == 3:
                dialogMAC += event.unicode
            elif selectedBox == 4:
                if event.unicode != ',':
                    dialogName += event.unicode
    
    #----Drawing Events----#
    screen.fill(backgroundColor)
    
    if event.type == pygame.MOUSEMOTION:
        (mouse_x, mouse_y) = event.pos
        (movse_x, movse_y) = event.rel
        if sidebarSelected:
            MACTracker.sliderPosition += movse_y
            if MACTracker.sliderPosition + MACTracker.sliderHeight > 248:
                MACTracker.sliderPosition = 248 - MACTracker.sliderHeight
            if MACTracker.sliderPosition < 0:
                MACTracker.sliderPosition = 0
    
    if True: # start & end & set range & refresh
        startingIPText.draw(screen)
        endingIPText.draw(screen)
        findRangeButton.draw(screen)
        setRangeButton.draw(screen)
        startingIPInput.draw(screen, displayIPStart)
        endingIPInput.draw(screen, displayIPEnd)
        searchRangeText.draw(screen)
        searchMACToggle.draw(screen)
        searchDNSToggle.draw(screen)
        MACTracker.draw(screen)
        trackSelectedItemButton.draw(screen)
        addItemByMACButton.draw(screen)
        constantUpdateToggle.draw(screen)
        refreshButton.draw(screen)
        netvizText = FONT40.render('netviz', 1, (0, 0, 0), (255, 255, 255))
        screen.blit(netvizText, (195, 533))
        if errorText != '':
            errorSurf = FONT20.render(errorText, 1, (255, 0, 0), (255, 255, 255))
            screen.blit(errorSurf, (120, 24))
        
        pygame.draw.rect(screen, (0, 0, 0), rfp(360, 0, 960, 600), 1)
        pygame.draw.rect(screen, (0, 0, 0), rfp(240, 0, 360, 120), 1)
        pygame.draw.rect(screen, (0, 0, 0), rfp(0, 240, 360, 600), 1)
    
    elementCount = 0
    ipCount = len(globalUnitManager.unitList)
    if ipCount != 0:
        ipPower = 0
        while (1 << ipPower) < ipCount:
            ipPower += 1
        widthCount = 1 << (ipPower/2)
        heightCount = 1 << (ipPower - ipPower/2)
        squareWidth = 512 / widthCount
        squareHeight = 512 / heightCount
        if squareWidth != 1 and squareHeight != 1:
            sub = 1
        else:
            sub = 0
    
    for element in globalUnitManager.unitList:
        element_x = elementCount % widthCount
        element_y = elementCount / widthCount
        inset_rect = pygame.Rect(405 + squareWidth*element_x,
                                 45 + squareHeight*element_y,
                                 squareWidth - sub, squareHeight - sub)
        if element == selectedIP:
            border_rect = inset_rect.copy()
            inset_rect = pygame.Rect(407 + squareWidth*element_x,
                                     47 + squareHeight*element_y,
                                     squareWidth - 5, squareHeight - 5)
            screen.fill((153, 153, 153), border_rect)
        if element.online:
            if (element.mac == 'no' or element.mac.startswith('(')) or not(searchMACToggle.toggled):
                if element.dns == '' or element.dns == 'Not found':
                    color = (255, 255, 0)
                else:
                    color = (0, 255, 0)
            else:
                color = (0, 255, 0)
        else:
            if (element.mac == 'no' or element.mac.startswith('(')) or not(searchMACToggle.toggled):
                if element.dns == '' or element.dns == 'Not found':
                    color = (0, 0, 0)
                else:
                    color = (255, 0, 0)
            else:
                color = (255, 0, 0)
            
        
        if element.mac != 'no' and not(element.mac.startswith('(')):
            for tracked in MACTracker.trackMACList:
                if tracked.MAC == element.mac:
                    color = (0, 0, 255)
                    tracked.ip = element.ip
                    tracked.online = element.online
                    tracked.inRange = True
                    element.username = tracked.name
        
        
        if element.ip == ownIP:
            color = (255, 255, 255)
            element.username = 'Myself'
        screen.fill(color, inset_rect)
        elementCount += 1
    
    if selectedIP == None:
        if 404 <= mouse_x < 916:
            if 44 <= mouse_y < 556: # TODO: this needs to be fixed
                    number = (mouse_y - 44) / squareHeight * widthCount + (mouse_x - 404) / squareWidth
                    wellthen = list(globalUnitManager.unitList)
                    if len(wellthen) > number:
                        mouseoverIP = wellthen.pop(number)
                        firstLine = 'IP: ' + mouseoverIP.ip + ' (' + mouseoverIP.username + ')'
                        if searchMACToggle.toggled:
                            macsurf = FONT20.render('MAC: ' + mouseoverIP.mac + ' (' + mouseoverIP.owner[:24] + ')', 1, (0, 0, 0), (255, 255, 255))
                        elif not(searchMACToggle.toggled):
                            macsurf = FONT20.render('MAC lookup is off', 1, (0, 0, 0), (255, 255, 255))
                        IPsurf = FONT20.render(firstLine, 1, (0, 0, 0), (255, 255, 255))
                        pingSurf = FONT20.render('Ping: ' + str(mouseoverIP.online), 1, (0, 0, 0), (255, 255, 255))
                        if searchDNSToggle.toggled:
                            dnssurf = FONT20.render('Server Name: ' + mouseoverIP.dns[:35], 1, (0, 0, 0), (255, 255, 255))
                        elif not(searchDNSToggle.toggled):
                            dnssurf = FONT20.render('DNS lookup is off', 1, (0, 0, 0), (255, 255, 255))
                        
                        screen.blit(pingSurf, (24, 158))
                        screen.blit(macsurf, (24, 182))
                        screen.blit(IPsurf, (24, 134))
                        screen.blit(dnssurf, (24, 206))
    else:
        mouseoverIP = selectedIP
        firstLine = 'IP: ' + mouseoverIP.ip + ' (' + mouseoverIP.username + ')'
        if searchMACToggle.toggled:
            macsurf = FONT20.render('MAC: ' + mouseoverIP.mac + ' (' + mouseoverIP.owner[:24] + ')', 1, (0, 0, 0), (255, 255, 255))
        elif not(searchMACToggle.toggled):
            macsurf = FONT20.render('MAC lookup is off', 1, (0, 0, 0), (255, 255, 255))
        IPsurf = FONT20.render(firstLine, 1, (0, 0, 0), (255, 255, 255))
        pingSurf = FONT20.render('Ping: ' + str(mouseoverIP.online), 1, (0, 0, 0), (255, 255, 255))
        if searchDNSToggle.toggled:
            dnssurf = FONT20.render('Server Name: ' + mouseoverIP.dns[:35], 1, (0, 0, 0), (255, 255, 255))
        elif not(searchDNSToggle.toggled):
            dnssurf = FONT20.render('DNS lookup is off', 1, (0, 0, 0), (255, 255, 255))
        
        screen.blit(pingSurf, (24, 158))
        screen.blit(macsurf, (24, 182))
        screen.blit(IPsurf, (24, 134))
        screen.blit(dnssurf, (24, 206))
    
    if 10 <= mouse_x < 340:
        if 266 <= mouse_y < 513:
            cutoffPoint = 247 * MACTracker.sliderPosition / MACTracker.sliderHeight
            dist = mouse_y - 266 + cutoffPoint
            lenny = int(dist / (MACTracker.font.get_linesize()))
            if lenny + 1 <= len(MACTracker.trackMACList):
                screen.blit(DeleteImage, (322, lenny * MACTracker.font.get_linesize() + 266 - cutoffPoint))
    
    if dialogStatus == 1:
        screen.blit(dialog, (390, 250))
        macBox = pygame.Surface((130, 24))
        macBox.fill((255, 255, 255), rfp(1, 1, 128, 22))
        nameBox = pygame.Surface((130, 24))
        nameBox.fill((255, 255, 255), rfp(1, 1, 128, 22))
        if dialogMAC != '':
            macBox.blit(FONT20.render(dialogMAC, 1, (0, 0, 0), (255, 255, 255)), (1, 1))
        if dialogName != '':
            nameBox.blit(FONT20.render(dialogName, 1, (0, 0, 0), (255, 255, 255)), (1, 1))
        screen.blit(macBox, (450, 274))
        screen.blit(nameBox, (450, 298))
    
    pygame.display.flip()
    
    endStep = time.time()
    stepLength = endStep - beginStep
    stepCount += 1
    if stepLength < 1.0/fps:
        time.sleep(1.0/fps - stepLength)

pygame.display.quit()
pygame.quit()

