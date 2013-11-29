#! /usr/bin/env python

#############################################################################
##                                                                         ##
## scapy6-teredo.py --- Teredo add-on for Scapy6                           ##
##               see http://namabiiru.hongo.wide.ad.jp/scapy6/             ##
##               for more informations                                     ##
##                                                                         ##
## Copyright (C) 2006  Guillaume Valadon <guedou@hongo.wide.ad.jp>         ##
##                     Arnaud Ebalard <arnaud.ebalard@eads.net>            ##
##                                                                         ##
## This program is free software; you can redistribute it and/or modify it ##
## under the terms of the GNU General Public License version 2 as          ##
## published by the Free Software Foundation; version 2.                   ##
##                                                                         ##
## This program is distributed in the hope that it will be useful, but     ##
## WITHOUT ANY WARRANTY; without even the implied warranty of              ##
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       ##
## General Public License for more details.                                ##
##                                                                         ##
#############################################################################

# TODO List / Lacks / Comments / Leads :
#
# [X] socket integration in Scapy6
# [ ] Check Routes6.resync() implementation to avoid existing Teredo
#     route to be wiped when called
# [ ] suppress useless comments
# [ ] suppress duplicated code 
# [X] make src6lladdr available in teredoInterfaceWorker class 
# [ ] Optional Refresh Interval Determination Procedure (section 5.2.7)
# [ ] Automatic sunset mechanism : will be done during activation if no 
#                                  default IPv6 route is available.
# [ ] 'direct IPv6 connectivity' test should be performed 3 times with a
#     2 seconds delay between the 3 shots.
# [ ] Deal in a robust manner with authentication when it can appear
# [ ] Multicast discovery : seems long and painful for a probably minor 
#                           functionality
# [ ] Enforce a 128 bytes MTU of 1280 by default : should be feasible 
#     with fragment6 code. Deal with the case of MTU option in RA.
# [ ] "Teredo implementations SHOULD NOT set the Don't Fragment (DF) bit of
#     the encapsulating IPv4 header."
# [ ] Enforce a pseudo-random refresh interval : is there a real need for 
#     that or is it useless for our cases
# [ ] deal with reception of a new prefix in advertisement (i.e. @ change):
#     is there any chance that happens ?
# [ ] Can we replace atexit() handler with something directly present in 
#     every interface worker ? => get a deeper understanding of python 
#     object ref count before doing that
# [ ] I should not recompute everything from local address for every
#     peer I instantiate.
# [ ] Replace setPeerType*()  methods by a setPeerType(flag)
# [ ] Replace setLocalType*() methods by a setLocalType(flag)
# [ ] check if a Teredo Relay that receive a packet from a
#     teredo Peer it has not heard from (or not heard) from 
#     for a long time will relay the packet or just ignore
#     it. This will be implementation dependant ... (see 
#     5.4.2). In fact, relay should drop the traffic if
# [ ] What about instantiating a teredo interface when Native 
#     connectivity is available but we want to speak with a
#     Teredo client. Ok, this looks like a bad idea ....
# [ ] Add some test to filter traffic to weird address : for
#     example if one want to send something to a link local
#     address.
# [ ] There's something annoying with the opening procedure for native
#     peers. It is that we open the door to the guy that send us an 
#     indirect bubble (that we receive with a Teredo Origin Indication
#     from our teredo server). There's no way to send a reply only
#     when we are sure that we open the door to the good relay. Get time
#     for reflexion about that specific point.
# [ ] bubbles sent by Vista stack have a HLIM value of 21. Reason ?
# [ ] Seems Echo Request sent by vista have a 4 null bytes data part
# [ ] We got no retry mechanism for contacting peers (on simple echo
#     req, one single indirect bubble, ... )
# [ ] When I'm restricted and peer is native, but i consider the 
#     connection as elapsed, I should send a direct bubble to 
#     the previous relay information I had for that peer in order
#     to open the door if it sends me a direct reply (considering
#     I'm always connected) -> better, I could maintain a list
#     of teredoRelay and update last sent time and last recv
#     time in order to get a better timing and avoid sending
#     packets where there's no need for them. 
# [ ] _validateTeredoRA() should process TeredoAuth. This is not the
#     case at the moment. We pass over it. We should also modify
#     the prototype of the function, 2 parameters are available 
#     in self.
# [ ] Teredo Qualification procedure routines were implemented a 
#     long time ago. We should take a closer look to them.
# [ ] Use a template for IPv6 link layer address and modify only 
#     the cone bit in it. At the moment, it is stored at many places.
# [ ] Houston, I suspect will get a problem if our Teredo Server is 
#     also a Relay. Deal with that in main loop.
# [ ] Use setNextHop() method instead of setting nh directly inside
#     teredoPeer instances.
# [ ] Check trd* interface name does not collide with some BSD 
#     ethernet interface name
# [ ] See if should use a higher buffer for our socket bound on service 
#     port (setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)) if
#     it is feasible.
# [ ] I don't think it's possible but we could take some time to see
#     if adding filter capabilities to our L3TeredoPacketSocket is
#     feasible.
# [ ] We could add a timeout to select() hack in L3TeredoPacketSocket
#     to finally return the fileno of main socket but it would no work
#     great if strict filters are applied to the socket.
# [ ] socket.socketpair() is not available on all platform but can be
#     reimplemented using pipes. Do it.
# [ ] Correct the fileno() hack in L3TeredoPacketSocket

# TODO : There's some understanding to gather from experiment against
#        bubble sending. Both reference documents (RFC and Teredo 
#        Overview) do not explicitly specify the kinds of addresses 
#        to use as source and destination of bubbles. I've got a 
#        capture with bubbles that incorporate link-local unicast and 
#        multicast IPv6 addresses.
# In fact, sect 5.2.6 of the draft states that when sending indirect bubbles,
# we must use "extract the Teredo IPv4 server address from the Teredo prefix
# of the IPv6 address of the target

# Simplified Teredo State diagram (scapy6 version)
#
#     me      |    peer    : State graph 
#------------------------------------------------------------------------------
# restricted  | restricted : None -- sendIndirectBubble+sendDirectBubble --> waitDirectBubble
#             |              waitDirectBubble -- recv DirectBubble or pkt --> connected 
#
# coned       | restricted : None -- sendIndirectBubble --> waitDirectBubble 
#             |              waitDirectBubble -- recv DirectBubble or pkt --> connected
#
# restricted  | native     : None -- send Echo Req through our Teredo srv --> waitEchoReply
#             |              waitEchoReply -- recv ind bubble with Teredo Ind -- send direct bubble to relay --> waitEchoReply
#             |              waitEchoReply -- recv Echo Reply from a relay --> connected
#
# coned       | native     : None -> send Echo Req Through our Teredo srv --> waitEchoReply
#             |              waitEchoReply -- recv Echo Reply --> connected 
#
# restricted  | coned      : None -> send pkt directly --> connected
#
# coned       | coned      : None -> send pkt directly --> connected
#

import logging
logging.getLogger("scapy").setLevel(1)

from scapy6 import *

from threading import Thread
import select


#####################################################################
# Instance destruction related code
#####################################################################

import atexit

# Keep a list of all .clientSock elements of teredoInterface instances
# When __del__() method of teredoInterface class is called (or ctrl-d
# is pressed), an empty string is send to the teredoInterfaceWorker
# instance and run() method ends.
# NB#1: maintaining a list of TeredoSocket directly is a bad idea
#       because refcount is incremented when a reference is put into
#       this list. That's why we store socket descriptors.
# NB#2: another solution would be to use weak references.
teredoOpenInterfaces = []

def teredoKillAll(l): # will be called when ctrl-d is pressed
    for clientSock in l:
	clientSock.send("")

atexit.register(teredoKillAll,teredoOpenInterfaces)

#####################################################################


# The way it works :
# teredoPeer class stores information specific to some peer.
# peer can be teredo or native. Information on local paramters is 
# also maintained, such as local Teredo address.
# Methods are provided to send specific packets to the peer, such as 
# bubbles and echo requests for native peers.
# 
# For every instance of teredoPeer, a specific state is maintained
# which is updated by the teredo socket methods this instance is 
# associated with.
#
class teredoPeer:
    # - peerAddr is the IPv6 address of the peer
    # - localAddr is our local Teredo Address resulting from qualification
    #   procedure.
    # - udpSock is the teredo UDP Socket
    def __init__(self, peerAddr, localAddr, udpSock):
        """
        From peerAddr (IPv6 address of this peer) and localAddr (our local 
        IPv6 Teredo address), we initialize the information for this peer.
        """

	self.peerAddr = peerAddr   # IPv6 addr in printable fmt
	self.localAddr = localAddr # Local teredo address in printable fmt
        self.udpSock = udpSock     # UDP socket bound on service port

        # state is the state of the peer. It is used by establishement
        # functions, to understand what kind of packet it should be
        # waiting for from peer, server or relay. Available state are:
        # - None : at class instantiation. Establishment procedure has
        #   not begun
        # - "connected" : connection with this peer was established. It
        #   means nh parameter has been updated to reflect the GW to
        #   use when sending packets to the peer.
        # - "waitDirectBubble" : next packet received for this peer
        #   should be a direct bubble coming from peer mapped addr/port
        # - waitEchoReply : next message should be an Echo Reply message
        #   from peer's Teredo relay
        # - elapsed : peer has been in connected state but no traffic 
        #   has been seen for more than 30 seconds. Nonetheless, all
        #   peer related parameters have already been set up (nh, ...)
        self.state = None
        self.stateData = None # state related data (Echo Req pkt, ...)
        
        self.queued = []  # queued pkt, sent when in 'connected' state
        
        # peerTeredoServer: stores the (addr, port=3544) of peer's Teredo 
        #     server. When peer is  native, this parameter has no meaning
        #     and is not used
        # nh : Next Hop to join Teredo peer, given as a tuple (v4dst, UDP 
        #      port). 
        #      When peer is native, this is the address and port of Teredo 
        #      Relay (extracted from received Teredo Origin Indication).
        #      When peer is Teredo, it stores the mapped address and port
        #      of the peer.
        self.peerTeredoServer = None # for Teredo Peer (TeredoServer@, 3544)
        self.nh = None

        # Last time of emission/reception of a packet to/from that peer.
        self.lastSentTime = 0
        self.lastRecvTime = 0

	### Set local address related information
	server, flag, maddr, mport = teredoAddrExtractInfo(localAddr)
	if   flag == 0x8000:
	    self.setLocalTypeConed()
	elif flag == 0x0000:
	    self.setLocalTypeRestricted()
        else: # should not happen
            warning("Weird flag (0x%.4x) in Teredo Address %s" % (flag, localAddr))
            raise badTeredoAddress
	self.localTeredoServer = (server, 3544)

	### Start setting peer address related information
	if in6_isaddrTeredo(peerAddr):
	    server, flag, maddr, mport = teredoAddrExtractInfo(peerAddr)
            self.peerTeredoServer = (server, 3544)
            self.setNextHop((maddr, mport))

	    if flag == 0x8000:   # peer behind cone NAT, so directly available
                self.setPeerTypeConed()
		self.setPeerStateConnected()
	    elif flag == 0x0000: # I'm behind restricted NAT. state will be updated later
		self.setPeerTypeRestricted()
	    else:
                warning("Weird flag (0x%.4x) in Teredo Address %s" % (flag, peerAddr))
                raise badTeredoAddress
	else: 
            # Native peer. Next Hop and state will be updated later, when 
            # receiving Echo Reply from relay (we can't when receiving Teredo
            # Origin Indication packet).
	    self.setPeerTypeNative()

    def _sendDirectBubble(self):
        """
        Send a direct bubble to the peer. nh is used, which means that :
        - if the peer is native, it will be sent to its relay. 
        - if the peer is Teredo, it will be sent to its mapped address and port.
        No state verification is performed before sending. 
        Last time of emission is updated to reflect the emission
        """
        bubble = IPv6(src=self.localAddr, dst=self.peerAddr, nh=59)
	self.udpSock.sendto(str(bubble), self.nh)
        self.lastSentTime = time.time()

    def _sendIndirectBubble(self):
        """
        Send an indirect bubble to the peer (through its Teredo server)
        This method is only used by teredo peers, it won't even work with
        native peers.
        """
        bubble = IPv6(src=self.localAddr, dst=self.peerAddr, nh=59)
	self.udpSock.sendto(str(bubble), self.peerTeredoServer)

    def _sendEchoReq(self):
        """
        Send an ICMPv6 Echo Request packet to the native peer, via
        our Teredo server.
        """
        echoreq  = IPv6(src=self.localAddr, dst=self.peerAddr)/ICMPv6EchoRequest(data=RandString(4))
        echoreq  = echoreq.__iter__().next() # Fixes volatile values
        self.udpSock.sendto(str(echoreq), self.localTeredoServer)
        self.lastEmission = time.time()
        self.stateData = echoreq # Stored to check if reply matches

    def startRecoverFromElapsed(self):
        """
        start reconnection reconnection to a peer by sending the first 
        shot of packets.
        """
	if self.isPeerTypeRestricted():
            if self.isLocalTypeRestricted():
	        self._sendDirectBubble()                
            self._sendIndirectBubble()
            self.setPeerStateWaitDirectBubble()
        else:
            self._sendEchoReq()
            self.setPeerStateWaitEchoReply()

    def send(self, spkt):
        """
        If peer is already in connected state, send packet. Else, 
        connection procedure is performed to open holes on all required
        parts (peer and local side).
        """

	if self.isPeerStateConnected():            # Connected -> send
	    self.udpSock.sendto(spkt, self.nh)
	    self.updateSentTime()
	    return len(spkt)

        self.addToQueue(spkt) # not connected yet -> queue packet

        if self.isPeerStateElapsed():              # elapsed -> recover
            return self.startRecoverFromElapsed()

	if self.isPeerTypeRestricted():            # restricted peer 
	    if not self.isPeerStateWaitDirectBubble(): 
                if self.isLocalTypeRestricted():
                    self._sendDirectBubble()
                self._sendIndirectBubble()
                self.setPeerStateWaitDirectBubble()
        else:                                      # native peer
	    if not self.isPeerStateWaitEchoReply():
                self._sendEchoReq()
                self.setPeerStateWaitEchoReply()
        return len(spkt)

    def recvfrom(self, spkt, frm):
        """
        This method is called internally when receiving a packet from that peer
        'frm' is a tuple containing IPv4 source and UDP port we received spkt
        from. All the management related work for the connexion is done here
        (for reception part).
        If we are in connected state and the packet is not management (data),
        it is returned. Basically, we simply filter all received management
        related data traffic for that peer and only push data traffic on return.
        """

	if self.isPeerStateConnected():
            if frm != self.nh:
                warning("Received data from non-expected source")
                return 
	    self.updateRecvTime()
            if len(spkt) > 40: 
                return spkt
            return # Drop bubbles. TODO : do more testing

        elif self.isPeerStateElapsed():
            if frm != self.nh:
                warning("Received data from non-expected source")
                return 
            self.setPeerStateConnected()
            return spkt
        
	elif self.isPeerStateWaitDirectBubble(): 
            # received packet is just a proof of reachability. If it is a bubble
            # we drop it after marking peer as connected.

            if frm != self.nh: # TODO : verify self.nh is set at that point
                return None

            if len(spkt) < 40:
                return None

	    try:
		p = IPv6(spkt)
	    except:
		return None

	    self.setPeerStateConnected()
	    self._sendQueued()

            if (p.nh == 59 and len(s) == 40):
                return None
            
            return spkt
	
	elif self.isPeerStateWaitEchoReply():
	    error_msg = "PeerStateWaitEchoReply: received weird packet instead of Echo Reply"
            if spkt[0:2] != '`\x00':
		warning(error_msg)
		# TODO : do not quit like that
		return None
	    
	    try:
                resp=IPv6(spkt)
	    except:
		warning(error_msg)
		# TODO : do not quit like that
		return
		
	    if self.stateData > resp:
                self.nh = frm
		self.setPeerStateConnected()
		self._sendQueued()
		return None            
	    else:
		warning(error_msg)
                
            return spkt
		
	else:
	    warning("inconsistent state found : %s" % self.state)
	    

    def _sendQueued(self):
        """
        All packet to the peer that have been queued (during establishment
        procedure) will be sent.
        """
        if not self.isPeerStateConnected():
            warning("_sendQueued: current state is '%s', not 'connected'" % self.state)
        for spkt in self.queued:
            self.send(spkt)

    def addToQueue(self, spkt):
        self.queued.append(spkt)
        
    # TODO See if we need it externally or if it should
    # be private : if we provide a send method in this
    # class, will be able to set it without the user even
    # knowing it
    def updateSentTime(self):
        """
        Update time of last traffic 
        """
        self.lastSentTime = time.time()

    def getSentTime(self, ):
        return self.lastSentTime


    def updateRecvTime(self):
        """
        Update the last time a packet was received from peer
        """
        self.lastRecvTime = time.time()


    def setNextHop(self, nh):
        """
        Set Next Hop information 
        """
        self.nh = nh

    def getNextHop(self):
        """
        Returns Next Hop information associated with peer. Return
        value is a couple containing IPv4 destination and UDP port
        the peer is reachable at.
        """
        return self.nh


    ### local type related methods ##################################
    
    def isLocalTypeConed(self):
	""" Return True if we are behind a cone NAT GW"""
	return self.localType == "conedTeredo"

    def setLocalTypeConed(self):
	""" Set the fact that we are behind a cone NAT GW"""
	self.localType = "conedTeredo"

    def isLocalTypeRestricted(self):
	""" Return True if we are behind a restricted NAT GW"""
	return self.localType == "restrictedTeredo"

    def setLocalTypeRestricted(self):
	""" Set the fact that we are behind a restricted NAT GW"""
	self.localType = "restrictedTeredo"


    ### peer type related method ####################################
    
    def isPeerTypeConed(self):
	""" Return True if we peer is behind a cone NAT GW"""
	return self.peerType == "conedTeredo"

    
    def setPeerTypeConed(self):
	""" Set the fact that peer addr is coned"""
	self.peerType = "conedTeredo"

    
    def isPeerTypeRestricted(self):
	""" Return True if peer is behind a restricted NAT GW"""
	return self.peerType == "restrictedTeredo"

    
    def setPeerTypeRestricted(self):
	""" Set the fact that pee is  are behind """
	self.peerType = "restrictedTeredo"

    
    def isPeerTypeNative(self):
	""" Return True if peer has a native IPv6 address"""
	return self.peerType == "native"

    
    def setPeerTypeNative(self):
	""" Set the fact that peer has a native IPv6 address"""
	self.peerType = "native"

    
    ### peer state related information ##############################

    def setPeerStateConnected(self):
        self.lastRecvTime = time.time()
        self.lastSentTime = time.time()
	self.state = "connected"

    def isPeerStateConnected(self):
        """
        return True if peer is in connected state. If last packet to the 
        peer was emitted more than 30 seconds ago, we reset state to 
        restart connection establishment. False is returned in this 
        case. """
        # Invalidate peer connection if last sent packet is older than 30 sec
        # TODO : won't work if coned. I should let the state to connected in 
        #        that specific case.
        if (self.state == "connected" and (time.time() - self.lastSentTime) > 30):
            if not self.isPeerTypeConed(): # Coned peer are always connected
                self.setPeerStateElapsed()
        
        return self.state == "connected"

    def setPeerStateElapsed(self):
        self.state = None
        self.stateData = None
        self.state = "elapsed"
        
    def isPeerStateElapsed(self):
        return self.state == "elapsed"
        
    def setPeerStateWaitDirectBubble(self):
	self.state = "waitDirectBubble"

    def isPeerStateWaitDirectBubble(self):
	return self.state == "waitDirectBubble"

    def setPeerStateWaitEchoReply(self):
	self.state = "waitEchoReply"

    def isPeerStateWaitEchoReply(self):
	return self.state == "waitEchoReply"



class teredoInterface:
    
    def __init__(self, 
                 server1="teredo-debian.remlab.net",  #"teredo.ipv6.microsoft.com", 
		 server2=None,
		 serviceport=None, 
		 iface=None):
	
        try:
            self.worker = teredoInterfaceWorker(server1=server1,
                                                server2=server2,
                                                serviceport = serviceport,
                                                iface = iface)
        except:
            print "Unable to instantiate Teredo interface"
            self.isDown = 1
            # TODO : Do not quit like that
            pass 
        
        self.isDown = self.worker.isDown
	self.clientSock = self.worker.clientSock
	self.teredoAddr = self.worker.ourv6addr

	global teredoOpenInterfaces
	teredoOpenInterfaces.append(self.clientSock)

    def send(self, pkt):
        dst6 = pkt.dst
        if dst6 is None:
	    warning("No destination provided")
            return 0

        spkt = str(pkt)

        mtu = 1280
        if len(spkt) > mtu:
            warning("Packet is too big for the link (MTU is 1280). Fragmentation is not supported.")
            return 0

	ret = self.clientSock.send(spkt)
	return ret

    # x is the MTU
    def recv(self, x):
        s = self.clientSock.recv(x)
        res = None
        try:
            res = IPv6(s)
        except:
            res = Raw(s)
        return res

    def nonblock_recv(self):
        self.clientSock.setblocking(0)
        try:
            s = self.clientSock.recv(MTU)
        except:
            self.clientSock.setblocking(1)
            return None
        self.clientSock.setblocking(1)
        res = None
        try:
            res = IPv6(s)
        except:
            res = Raw(s)
        return res  

    def close(self):
        return

    def fileno(self):
        return self.clientSock.fileno()

    def __del__(self):
	# stop the thread by sending it an empty string
	self.clientSock.send("")

	# suppress clientSock reference from global list
	global teredoOpenInterfaces
	teredoOpenInterfaces.remove(self.clientSock)

	self.clientSock = None
	self.worker = None

    

class teredoInterfaceWorker(Thread):
    def __init__(self, server1="teredo-debian.remlab.net",  #"teredo.ipv6.microsoft.com", 
		 server2=None, 
		 serviceport=None, 
		 iface=None):
	""" 
	Initializes our Teredo interface. Steps are following ones :
	- an UDP socket is opened to communicate with
	"""
	
	Thread.__init__(self)

        self.status="initial"         # interface status
        self.coned=0                  # are we behind Cone NAT ?
        self.oursrvaddr = None        # our Teredo server address
        self.ourv6addr= None          # our IPv6 Teredo address
        self.oursrc6lladdr = None     # our IPv6 link-local addr (for RS)
        self.ourv4addr = None         # our IPv4 address
        self.serviceport = None       # Our service port
        self.maddr = None             # our mapped address
        self.mport = None             # our mapped port
        self.lastEmission = 0         # Last time we contact our server
        self.lastReception = 0        # Last time our server contact us
        self.serverStateData = None   # Last packet sent to server
        self.udpSock = None           # UDP socket bound to service port
        self.peers={}                 # maintains list of teredoPeer instance

        # Pieces of information that WILL be used for secure qualification
        # Not used at the moment. 
        self.clientid=None            # Client identifier
        self.secret=None              # Shared secret
        self.authalg=None             # Authentication Algorithm
        self.isDown = 1               # Is the interface down
                    

	# Create pair socket for communication between our recv()/send()
	# and running thread (worker implemented in run())
	self.workerSock, self.clientSock = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)

	# Let's bind an UDP socket 
        if self._openTeredoSocket(serviceport=serviceport, iface=iface) is False:
            return

	# Qualification procedure is performed before launching thread
        self.ourv6addr = self._qualify(server1, server2)
        if self.ourv6addr is None:
            self.isDown = 1
            return 

        self.isDown = 0
	self.start()


    def run(self):
        # 3 simple actions : 
        #
        # - read data from user through workerSock and send them to the IPv6 
        #   destination through udpSock by passing them to send() method of
        #   associated instance. If destination is not already a peer, 
        #   create it. Internally in the peer instance, data will be queued 
        #   till completion of the establishment procedure.
        #
        # - read data from network through udpSock :
        #   - management data not related to an already existing peer are 
        #     processed directly (indirect bubbles from relays, for example)
        #   - data from an already existing peer are passed to teredoPeer
        #     instance recvfrom() function for internal structures to be 
        #     updated. If something is returned (it was data and not some 
        #     bubble or management traffic), it is sent to the user through
        #     workerSock.
        # 
        # - when a timeout occurs, send a bubble to our server in order to 
        #   maintain the hole in the NAT.
        #
        mtu = 1500 - 20 - 8
        timeout = 30

	while True:

            if (time.time() - self.lastEmission) > 30:
                rs = TeredoAuth()/IPv6(src=self.oursrc6lladdr, dst="ff02::2")/ICMPv6ND_RS()
                self.serverStateData = rs.__iter__().next()
                self.udpSock.sendto(str(self.serverStateData), (self.oursrvaddr, conf.teredoServerPort))
                self.lastEmission = time.time()

	    r,w,e = select.select([self.workerSock, self.udpSock], [], [], timeout)

	    if len(r) == 0: # timeout
		continue

	    for s in r:
		if s == self.workerSock: # We have data to send provided by our client
		    # TODO : accept more data and then drop if more than 1472
                    #        or simply fragment (which is quite simple)
		    data = s.recv(mtu)
		    
		    if len(data) == 0: return # this is the signal to exit
                    if len(data) < 40: continue 

		    dst6 = data[24:40]
		    if not self.peers.has_key(dst6):
			self.peers[dst6] = teredoPeer(inet_ntop(socket.AF_INET6, dst6), 
                                                      self.ourv6addr, 
                                                      self.udpSock)
                        
                    self.peers[dst6].send(data)

		else:  
		    data, frm = s.recvfrom(mtu)
                    if len(data) < 40: continue
                    
                    cls = IPv6
                    if not ((ord(data[0]) & 0xf0) == 0x60):
                        disp = {0x0000: TeredoOrigInd, 0x0001: TeredoAuth}
                        cls = disp.get(struct.unpack("!H",data[0:2])[0], Raw)
                        
                    # DATA FROM TEREDO SERVER
                    if (frm == (self.oursrvaddr, conf.teredoServerPort)):
                        # Teredo Origin Indication Message followed by relay/peer's bubble
                        if len(data) == 48 and cls is TeredoOrigInd:
                            try:
                                p = TeredoOrigInd(data)
                            except:
                                warning("received weird Origin Indication message from our server")
                                continue
                        
                            if not (isinstance(p.payload, IPv6) and 
                                    p.payload.nh == 59):
                                warning("received weird Origin Indication message from %s:%d" % frm)
                                continue

                            peerLLAddr = p.payload.src
                            if not in6_islladdr(peerLLAddr):
                                warning("received indirect bubble with non link-local address (%s) through relay %s:%d" % (peerLLAddr, frm[0], frm[1]))
                                continue
                            # print "Info : Received indirect bubble with IPv6 src addr %s through relay %s:%d" % (peerLLAddr, frm[0], frm[1])
                            # should be fe80::8000:5445:5345:444f or fe80::8000:5445:5345:444e depending on windows version.

                            bubble = IPv6(src=self.ourv6addr, dst=peerLLAddr, nh=59, hlim=255)
                            self.udpSock.sendto(str(bubble), (p.origip, p.oport))
                            continue
                        
                        # Should be an RA (TeredoAuth/TeredoOrigInd/IPv6/ICMPv6ND_RA/...) (at least 77 bytes)
                        # TODO : use validateRA function on incoming data
                        if len(data) >= 77 and cls is TeredoAuth: 
                            try:
                                p = TeredoAuth(data)
                            except:
                                print "Received weird packet from our Teredo server"
                                continue

                            if self._validateTeredoRA(p, self.oursrvaddr) is None: # Sanity check
                                warning("RA validation failed.")
                                continue 

                            if (self.serverStateData is not None and self.serverStateData > p):
                                # TODO : We should check if the interval between sent and recv is correct
                                self.lastReception = time.time()
                                self.serverStateData = None
                                continue

                        warning("received data from server that is neither a bubble or an RA.")
                        warning("data is : %s" % repr(data))
                            
                    # DATA FROM A PEER (management or real data, directly or through its RELAY)
                    if len(data) >= 40 and cls is IPv6: # direct bubble
                        src6 = data[8:24]
                        if self.peers.has_key(src6):
                            peer = self.peers[src6]
                            spkt = peer.recvfrom(data, frm)
                            if spkt:
                                self.workerSock.send(spkt)
                            continue

                        # Hey, we got a new pal !

                        psrc6 = inet_ntop(socket.AF_INET6, src6)
                        if in6_isaddrTeredo(psrc6): # Sanity checks for Teredo peer
                            server, flag, maddr, mport = teredoAddrExtractInfo(psrc6)
                            if (maddr, mport) != frm:
                                #warning("Nasty connection (mapped @ and port do not match) : %s from %s:%d" % (psrc6, frm[0], frm[1]))
                                continue
                        elif not in6_isgladdr(psrc6):
                            #warning("Nasty connection from non unicast global source : %s from %s:%d" % (psrc6, frm[0], frm[1]))
                            continue


                        peer = teredoPeer(inet_ntop(socket.AF_INET6, src6), 
                                          self.ourv6addr,
                                          self.udpSock)
                        peer.nh = frm
                        peer._sendDirectBubble()
                        peer.setPeerStateConnected()
                        self.peers[src6] = peer
                        spkt = self.peers[src6].recvfrom(data, frm)
                        if spkt:
                            self.workerSock.send(spkt)
		

    def __del__(self):
	self.workerSock.close()
	self.clientSock.close()
        if self.udpSock is not None:
            self.udpSock.close()
	self.clientSock = None
	self.workerSock = None
	self.udpSock = None
        self.peers = None

    # Used internally by __init__() to bind a UDP socket. If not provided, service
    # port is selected randomly over 1024
    # Also, by default (aka if not provided), iface is scapy default iface.
    def _openTeredoSocket(self, serviceport=None, iface=None):
        """
        Internal function. Opens a UDP socket to listen for incoming
        Teredo traffic on service port. 1 is return on error. 0 on success.

        serviceport : specifies a specific Teredo service port for the socket.
                      if this parameter is not provided, a random port is used.
        iface       : specifies the interface or address to bind our socket on.
                      if this parameter is omitted, the iface used for default
                      route is used (and preferentially conf.iface if many are 
                      available). 
        """

        if iface is None:
            # let's find default route(s)
            l = filter(lambda x: x[0] == 0 and x[1] == 0, conf.route.routes)
            if l: # Some default routes available
                l = map(lambda x: x[3], l)
                if conf.iface in l: # Check if conf.iface is used by one.
                    iface = conf.iface
                else:
                    iface = l[0]
                    conf.iface = iface
	
	if iface is None:
	    warning("No interface available : unable to create a socket.")
	    return False
	
	# Get interface address and perform sanity check
        try:
            ourv4addr = get_if_addr(iface) 	
        except IOError:
	    warning("Has your %s interface an IPv4 address? Seems not. Exiting..." % iface)            
            return False

	try:
	    inet_pton(socket.AF_INET, ourv4addr)
	except:
	    warning("Unable to get interface address (iface is %s). Exiting" % iface)
	    return False
	
	try:
	    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	except:
	    warning("Unable to get socket. Exiting ...")
	    return False
	

	# If user provides us with a serviceport, we won't retry on error 
	# (for example, if port is already in use). Else, we will retry at
	# most 4 times (with a new random value) if port is already in use.
        if serviceport is None:
            maxretries=4
        else: # no port randomization. We won't retry on error
            maxretries=1

        retries=0  

        while(retries < maxretries):
            if maxretries > 1: # implies port randomization
                serviceport = random.randint(1025,65535)
            try:
                s.bind((ourv4addr, serviceport))
                break
            except:
		warning("Unable to bind socket to port %d on %s (%s) : %s. Retrying" % (serviceport,
											iface,
											ourv4addr,
											sys.exc_info()[1]))
            retries += 1
            
        if retries == maxretries: # Things went bad
	    warning("After %d retries, we were unable to bind our socket. Exiting" % retries)
            return False

	# Everything went fine Update internal value
	self.udpSock = s
        self.serviceport = serviceport
	self.ourv4addr = ourv4addr
        return True


    # This function is used during qualification to get information from 
    # Teredo server. It does not modify internally stored parameters but
    # uses UDP socket to send and receive traffic. Unknown traffic received
    # on socket during that time is dropped, so it shouldn't be uses after
    # qualification (i.e. after teredoInterface has been instantiated).
    #
    # It returns packet received in response to emitted Teredo RS or None
    # if nothing was received after T seconds ()
    # src6lladdr is the source link local IPv6 address used to send RS.
    # Be aware that peer (aka server) behavior is bound to the kind of 
    # source address used (coned or not coned). In first case, response is
    # expected from server address. In the second case, response is expected
    # from another address
    def _sendRSAndReceiveRA(self, server, T):
        """
        Sends a Router Solicitation message to our Teredo server and filters
        incoming traffic on our socket against Router Advertisements. You should
        be aware that other kind of traffic received on the socket is dropped.
        No RA validation is performed.

        server     : the Teredo server we are sending traffic to.
        T          : The time we wait for a RA after a RS has been sent.
        """


        s = self.udpSock
        rs = TeredoAuth()/IPv6(src=self.oursrc6lladdr, dst="ff02::2")/ICMPv6ND_RS()
        s.sendto(str(rs), (server, conf.teredoServerPort))
	remain = T
        emitted = time.time()

        while remain > 0:
            s.settimeout(float(remain))
            try:
                recvstring, addr = s.recvfrom(200) # TODO : 200 ?
            except:
                # Houston, we have a problem !
                remain = T - (time.time() - emitted)
                continue
            
            ip, port = addr

            coned = inet_pton(socket.AF_INET6, self.oursrc6lladdr)[8:10] == '\x80\x00' 

	    # Note : in coned case, matching of sender is performed later
            if coned or (not coned and ip == server and port == conf.teredoServerPort):
                # At least reply seems to come from our server
                # Let's try to dissect the response
                try:
                    resp = TeredoAuth(recvstring)
                except:
		    remain = T - (time.time() - emitted)
                    continue
                if rs > resp:
                    return resp

		remain = T - (time.time() - emitted)
                continue  

        return None


    def _validateTeredoRA(self, r, server):
        """
        This internal function validates received RA message (Teredo Origin
        Indication header must be included) and returns mapped UDP IP and
        port from Origin Indication header. None is returned on error.
        
        r          : UDP Payload IPv6 packet to be validated as RA.
        server     : IPv4 address of the Teredo server. Used to validate
                     correctness of returned prefix.
        """
        
        # TODO : should deal with Authentication Header more specifically
        
        # Let's get Teredo Origin Indication (packet can have TeredoAuth _before_)
        r = r[TeredoOrigInd]
        if r is None:
	    print "No Teredo Origin Indication in Response from server. Discarding."
	    # TODO : revoir la sortie
            return None

        # mapped address and port are stored to be returned after validation
        oport = r.oport
        origip = r.origip

        r = r.payload

        # After Teredo Origin Indication, IPv6 must follow
        if not isinstance(r, IPv6):
	    print "Teredo Origin Indication not followed by IPv6 packet. Discarding."
	    # TODO : revoir la sortie
            return None

        # IPv6 destination address of RA must be source address of RS
        if r.dst != self.oursrc6lladdr:
	    print "RA Destination address differs from source address of RS. Discarding."
	    # TODO : revoir la sortie
            return None

        if r.hlim != 255:
	    print "Hop-Limit in RA is %d. Expected 255. Discarding." % r.hlim
	    # TODO : revoir la sortie
            return None

        # We also store the source address of the RA and test it is link-local
        srvlladdr = r.src
        if not in6_islladdr(srvlladdr):
	    print "Source address of RA is not Link-Local. Discarding."
	    # TODO : revoir la sortie
            return None

        r = r.payload

        # validating IPv6 packet is carrying a RA.
        if not isinstance(r, ICMPv6ND_RA):
	    print "Packet is not a valid RA. Discarding."
	    # TODO : revoir la sortie
            return None

        r = r.payload

        # As specified in Teredo draft, RA must contain exactly one Prefix
        # Information Option, with a valid Teredo prefix. This is the purpose
        # of following tests.
        if not ICMPv6NDOptPrefixInfo in r:
	    print "RA does not contain a Prefix Information option. Discarding."
	    # TODO : revoir la sortie
            return None

        r = r[ICMPv6NDOptPrefixInfo]
        
        if r.prefixlen != 64:
	    print "Carried prefix length is invalid. Discarding."
	    # TODO : revoir la sortie
            return None

        # test if carried prefix is Teredo
        prefix = r.prefix
        if not in6_isaddrTeredo(prefix):
	    print "Prefix (%s) is not a valid Teredo Prefix. Discarding." % prefix
	    # TODO : revoir la sortie
            return None

        if (teredoAddrExtractInfo(prefix)[0] != server):
	    print "Address encapsulated in received Teredo prefix does"
	    print "not match Teredo server address. Discarding."
            return None

        # TODO : no test is performed against the public/private status of
        # server address.
        
        r = r.payload
        
        # Test if RA does not contain another ND Prefix Information option.
        if ICMPv6NDOptPrefixInfo in r:
	    print "RA contains 2 Prefix Information options. Discarding."
	    # TODO : revoir la sortie
            return None

        return origip, oport


    # Note : no verification is performed on given parameters. 
    def _constructTeredoAddress(self):
        """
        This function construct a Teredo address using given Teredo server
        address, NAT type, mapped IP and port (typically extracted from Teredo
        Origin Indication header). Teredo address is returned in network format.

	- self.oursrvaddr is used to get IPv4 server address. 
	- Cone status is gathered from self.coned
	- mapped address of the client (public IPv4 address of the NAT GW) is
	  gathered from self.maddr parameter. 
        - Mapped port of the client (UDP port associated with the service port 
	  of the client on the NAT GW) is gathered from self.mport parameter.
        """

        # TODO : create a global variable for the teredo /32 prefix
        prefix = inet_pton(socket.AF_INET6,conf.teredoPrefix)[:4]
        prefix += inet_pton(socket.AF_INET,self.oursrvaddr)
        
        # Create the interface ID by packing the 3 elements together
        maddr = inet_pton(socket.AF_INET, self.maddr)
        if self.coned:
            flag = '\x80\x00'
        else:
            flag = '\x00\x00'
        ifaceid = flag+struct.pack("!H",self.mport ^ 0xffff)+strxor('\xff'*4,maddr)
        
        return inet_ntop(socket.AF_INET6, prefix+ifaceid)

    
    # This function performs the qualification procedure
    def _qualify(self, server1,server2, testCone=0, T=4, N=3):
        """
        This internal function performs the qualification procedure for the
        Teredo interface.

        server1 : our Teredo server address. If none is provided, we perform
	          a resolution against "teredo.ipv6.microsoft.com" and
		  get first response.
        server2 : second address of teredo server use in qualification procedure.
                  If not provided, server1 address with last byte incremented
                  by 1 is used.
        testCone : start qualification procedure by testing if we are behind a
                   Cone NAT. Not performed by default. Makes qualification
                   procedure faster not to do it. Set it to 1 if you want to 
		   test if you are behind a cone nat.
        T : timeout value used when waiting for a RA from the Teredo server
            after a RS has been sent. Same value is used for Cone NAT flaged
            and non Cone NAT flaged RS. Default value is 4 seconds as specified
            in RFC 2461 (ND)
        N : number of retries if no RA is received for our RS. Same value is
            used for Cone NAT and non cone NAT test procedure. Default value is
            3 as specified by RFC 2461.
        """

        # simple sanity checks against current status
        if self.status != "initial":
            if self.status == "qualified":
		print "Passing state from qualified to initial."
		print "Restarting qualification procedure."
                # Autre chose a reinitialiser ?
                self.status = "initial"
            elif self.status == "off-line":
		print "Passing state from off-line to initial."
		print "Restarting qualification procedure."
                # Autre chose a reinitialiser ?
                self.status = "initial"
            else:
		print "Don't modify internal variables by hand !!!"
		print 'value "%s" for status variable is incorrect' % self.status
		return None


	#############################################################
	# Initialize server addresses (main and secondary)
	#############################################################

	# if server1 is an IP, gethostbyname does nothing and returns the address
	try:
	    server1 = socket.gethostbyname(server1)
	except:
	    warning("Unable to resolve '%s'. Aborting Teredo Qualification procedure." % server1)
	    return None

	if server2 is not None:
	    try:
		server2 = socket.gethostbyname(server1)
	    except:
		warning("Unable to resolve '%s'. Aborting Teredo Qualification procedure." % server2)
		return None
	else: # Second address of Teredo server not provided. Increment that of server1
	    tmp = inet_pton(socket.AF_INET, server1)
	    lastbyte = struct.unpack("B", tmp[3])[0]
	    if lastbyte == 255: # Silly test
		warning("Unable to increment last byte of address. It is 255 !!!")
		return None
	    tmp = tmp[:3] + struct.pack("B", lastbyte+1)
	    server2 = inet_ntop(socket.AF_INET, tmp)


	#############################################################
	# Perform optional Cone NAT test procedure
	#############################################################
            
	# TODO : Reread that code
        if testCone: # Should I test if we are behind a Cone NAT ?
            currentShot=1
            while currentShot <= N:
                # Our "Cone NAT" Link-Layer address 
                # src6lladdr = "fe80::8000:5445:5245:444f" #(the one used by Win XP). 
		# src6lladdr = "fe80::8000:ffff:ffff:ffff" : the one used by vista beta version 
		# src6lladdr = "fe80::8000:ffff:ffff:fffe" : the one used by vista RC version 
                self.oursrc6lladdr = "fe80::8000:ffff:ffff:fffe" # Vista RC1 

                r = self._sendRSAndReceiveRA(server1, T)
                if r is None: # No RA received after T seconds
                    currentShot += 1
                    continue
                
                mappedvals = self._validateTeredoRA(r, server1)
                if mappedvals is None: # Validation failed : our server sends weird packets
                    print "RA validation failed. Unable to get an address."
                    print "Teredo server we are dealing with has a weird behavior."
                    self.status="off-line"
                    return None
                
                # Here, we are behind cone NAT, i.e. fully qualified.
                self.status="qualified"
		self.nattype = "cone NAT"
                self.oursrvaddr = server1
                self.coned = 1
                self.maddr, self.mport = mappedvals
		# modify the function prototype to suppress server1 and
		# use self.oursrvaddr instead 
                return self._constructTeredoAddress()


	#############################################################
	# Get our mapped address and port from server
	#############################################################
	    
        # Behind that point, we know we are no more considering Cone NAT.
        # Only symmetric or restricted NAT
        currentShot=1
        while currentShot <= N:
            # Our "non-Cone NAT" Link-Layer address 
	    # src6lladdr = "fe80::5445:5245:444f" #(the one used by Win XP). 
	    # src6lladdr = "fe80::ffff:ffff:ffff" # the one used by vista beta version
	    # src6lladdr = "fe80::ffff:ffff:fffe" # the one used by vista RC version
            self.oursrc6lladdr = "fe80::ffff:ffff:fffe" # Vista RC1

            r = self._sendRSAndReceiveRA(server1, T)
            if r is None: # No RA received
                currentShot += 1
                continue
            
            mappedvals1 = self._validateTeredoRA(r, server1)

            if mappedvals1 is None: # Validation failed : our server sends weird packets
                    print "RA validation failed. Unable to get an address."
                    print "Teredo server we are dealing with has a weird behavior."
                    self.status="off-line"
		    self.nattype = "unknown NAT (unusable connection)"
                    return None
            break

	#############################################################
	# Now, get the specific type of NAT we are stuck behind
	#############################################################
                
        # From that point, we know we can talk using UDP but we don't
        # know the specific kind of NAT our GW implements : restricted or
        # symmetric. Let's test it with our second Teredo server.

        CurrentShot=1
        while CurrentShot <= N:

            r = self._sendRSAndReceiveRA(server2, T)
            if r is None: # No RA received
                CurrentShot += 1
                continue

            mappedvals2 = self._validateTeredoRA(r, server1)
            
            # Pour le test suivant, on devrait peut-etre rajouter une comparaison
            # avec currenShot histoire de laisser une autre chance au serveur
            if mappedvals2 is None:
                print "RA validation failed. Unable to get an address."
                print "Teredo server we are dealing with has a weird behavior."
                self.status="off-line"
		self.nattype = "unknown NAT (unusable connection)"
		return None
            break
        
        # Second server returned an address. Let's compare the mapped address
        # and port to the one first server returned to determine the kind of
        # NAT we are dealing with.
        if mappedvals1 != mappedvals2:
	    print "You are behind a symmetric NAT : Teredo service is not usable."
	    self.nattype = "symmetric NAT"
	    self.status="off-line"
            return None

	#############################################################
	# Here, Qualification is over, we got our parameters.
	#############################################################

        # Here is the "Happy End" : we are behind a restricted NAT. Teredo
        # service is usable
        self.maddr, self.mport = mappedvals1
        self.status="qualified"
	self.nattype = "restricted NAT"
        self.oursrvaddr = server1
        self.coned=0
        return self._constructTeredoAddress()


    def show(self):
	"""
	Print information associated with Teredo socket (addresses, ports, ...). 
	"""
	print "Socket status        : %s" % self.status

	if self.status != None:
	    print "NAT qualification    : %s" % self.nattype
	
	if self.s is None:
	    return
	
	print "Teredo server address: %s" % self.oursrvaddr
	print "Our IPv4 address/port: %s / %s" % (self.ourv4addr, self.serviceport)
	print "Our mapped parameters: %s / %s" % (self.maddr, self.mport)
	print "Our Teredo IPv6 addr : %s" % self.ourv6addr
	print "Our src Link-Local @ : %s" % self.oursrc6lladdr
	# Last packet sent to our Teredo Server
	lastcontact = None
	if self.lastEmission is None:
	    lastcontact = "never sent one"
	else:
	    lastcontact = "%d sec ago" % int(time.time() - self.lastEmission)
	print "Last packet to server: %s" % lastcontact

	self.peers.show()

	# TODO : add that information later. 
	#clientid=None            # Client identifier
	#secret=None              # Shared secret
	#authalg=None             # Authentication Algorithm
	#self.relays.show()


class TeredoPortField(ShortField):
    def addfield(self, pkt, s, val):
        return s+struct.pack("!H", self.i2m(pkt,val) ^ 0xffff )
    def getfield(self, pkt, s):
        return s[2:], self.m2i(pkt, struct.unpack("!H",s[:2])[0] ^ 0xffff)

class TeredoIPField(IPField):
    def addfield(self, pkt, s, val):
        return s+struct.pack(self.fmt, strxor(self.i2m(pkt,val), '\xff\xff\xff\xff'))
    def getfield(self, pkt, s):
        return  s[self.sz:], self.m2i(pkt, strxor(struct.unpack(self.fmt, s[:self.sz])[0], '\xff\xff\xff\xff'))


class _TeredoGuessPayload:
    def guess_payload_class(self,p):
        if len(p) > 2:
            if (struct.unpack("B",p[0])[0] & 0xf0) == 0x60:
                return IPv6
            dispatcher = struct.unpack("!H",p[0:2])[0]
            if dispatcher == 0x0000:   # origin indication
                return TeredoOrigInd
            elif dispatcher == 0x0001: # Authentication
                return TeredoAuth
            else:                       # What is it ?
                return TeredoUnknown
        return Raw


class TeredoUnknown(_TeredoGuessPayload, Packet):
    name = "Teredo Unknown (not implemened in Scapy)"
    fields_desc = [ StrField("data","") ]

class TeredoOrigInd(_TeredoGuessPayload, Packet):
    name = "Teredo Origin Indication"
    fields_desc = [ XShortField("fixed", 0x0000),
                    TeredoPortField("oport",0x0000),
                    TeredoIPField("origip","0.0.0.0") ]
    def answers(self,other): 
        return self.payload.answers(other)


# TODO : Add automatic randomization to nonce field
class TeredoAuth(_TeredoGuessPayload, Packet):
    name = "Teredo Authentication"
    fields_desc = [ ShortField("fixed", 0x0001),
                    FieldLenField("idlen", None, "clientid", "B"),
                    FieldLenField("aulen", None, "authid", "B"),
                    StrLenField("clientid", "", 
                                length_from = lambda pkt: pkt.idlen),
                    StrLenField("authid", "", 
                                length_from = lambda pkt: pkt.aulen),
                    StrFixedLenField("nonce", '\x00'*8, 8),
                    ByteField("confirm",0) ]
    def default_payload_class(self, p):
            if len(p) > 2:
                dispatcher = struct.unpack("!H",p[0:2])[0]
                if dispatcher == 0x0000: # origin indication
                    return TeredoOrigInd
                else:                    # must be IPv6 
                    return IPv6
    def hashret(self):
        return self.nonce+self.payload.hashret()
        
# La section 5.2 du draft fournit les informations suffisantes pour gerer un
# "Etat Teredo" :
# "The client will maintain the following variables that reflect the
# state of the Teredo service:
#
# - Teredo Connectivity status,
# - Mapped address and port number associated with the Teredo Service
#   port,
# - Teredo IPv6 prefix associated with the Teredo service port,
# - Teredo IPv6 address or addresses derived from the prefix,
# - Link Local address,
# - Date and time of the last interaction with the Teredo server,
# - Teredo Refresh Interval,
# - Randomized Refresh Interval,
# - List of recent Teredo peers.

def dispatch(p, **kargs): # used by bind_layers
    cls = Raw
    if len(p) > 2:
	if (struct.unpack("B",p[0])[0] & 0xf0) == 0x60:
	    cls = IPv6
        else:
            dispatcher = struct.unpack("!H",p[0:2])[0]
            if dispatcher == 0x0000:   # origin indication
                cls = TeredoOrigInd
            elif dispatcher == 0x0001: # Authentication
                cls = TeredoAuth
            else:                       # What is it ?
                cls = TeredoUnknown
    return cls(p, **kargs)

bind_bottom_up( UDP, dispatch, { "dport": conf.teredoServerPort })
bind_bottom_up( UDP, dispatch, { "sport": conf.teredoServerPort })



conf.teredoIface = None
conf.teredoAutoActivation = True

# Idea is to dispatch IPv6 traffic to the teredo socket and send IPv4
# traffic unmodified.

# TODO : find a better way to know if a default route exists
# TODO : try to implement missing elements of __init__() method (see L3PacketSocket)
#        - filter
#        - promisc
#        - iface
#        - nofilter
#        - see family parameter in SuperSocket __init__() method
class L3TeredoPacketSocket(L3PacketSocket):

    def __init__(self, *args, **kargs):


        L3PacketSocket.__init__(self, *args, **kargs)

    # TODO: see with phil why there's no MTU parameter to that function
    def nonblock_recv(self): # For FREEBSD and DARWIN (for ex, in sndrcv)
        p = conf.teredoIface.nonblockrecv()
        if p:
            return p
        return L3PacketSocket.nonblock_recv()

    def recv(self, x):
        r,w,e = select.select([conf.teredoIface, self.ins], [], [])
        if len(r) == 2 and r[0] != conf.teredoIface:
            r.reverse() # make teredo replies being processed first
                
        if r[0] == conf.teredoIface:
            return conf.teredoIface.recv(x)
        else:
            res = L3PacketSocket.recv(self, x)
            return res
    
    def send(self, x):
        if isinstance(x, IPv6):
            iff, a, gw = conf.route6.route(x.dst)
            if iff.startswith("trd"):
                return conf.teredoIface.send(x)
        elif hasattr(x, "dst"):
            iff, a, gw = conf.route.route(x.dst)
        else:
            iff = conf.iface
        sdto = (iff, self.type)
        self.outs.bind(sdto)
        sn = self.outs.getsockname()
        if sn[3] == ARPHDR_PPP:
            sdto = (iff, ETH_P_IP)
        elif LLTypes.has_key(sn[3]):
            x = LLTypes[sn[3]]()/x
        self.outs.sendto(str(x), sdto)            

    def fileno(self):
        # PURE HACK BELOW :-(. Rationale: We deal with 2 sockets (teredo and ins)
        # When someone ask for one fileno() for our L3TeredoPacketSocket, if we
        # only return one of the fileno associated with our sockets, chances are 
        # high that clients will make a select on it and wait for traffic, even
        # if traffic is available on the other one. As a matter of fact, we always 
        # return a  fileno for a socket that has data available for reading (but 
        # we are blocking till that happens)
        r,w,e = select.select([conf.teredoIface, self.ins], [], [])
        return r[0].fileno()

def activateTeredo(doit=True):
    if conf.teredoIface is None and doit == True: 
        
        # simple "automatic sunset" : check if a default route exists.
        rt_targets = map(lambda x: x[0] == '::' and x[1] == 0, conf.route6.routes)
        has_def_route = reduce(lambda x,y: x or y, rt_targets, 0) 

        if not has_def_route:
            try:
                t = teredoInterface()
                if not t.isDown:
                    conf.teredoIface = t
            except:
                pass

            if conf.teredoIface is None:
                warning("Teredo qualification failed. No default IPv6 route will be available ...")
                conf.L3socket = L3PacketSocket
                return                
            
            # TODO : this route has some wrong parameters
            # using conf.iface is a hack
            conf.route6.routes.append(('::', 0, 'fe80::1', "trd0", [conf.teredoIface.teredoAddr]))
            conf.L3socket = L3TeredoPacketSocket

activateTeredo(doit=conf.teredoAutoActivation)

if __name__ == "__main__":
    interact(mydict=globals(), mybanner="Scapy6 - Teredo add-on")


#     def show(self):
# 	if len(self.l) == 0:
# 	    print "Teredo peers list    : no peers"
# 	    return
# 	else:
# 	    print "%s | %s | %s | %s" % ("Peer address".ljust(24), 
# 					 "IPv4 contact".ljust(15), 
# 					 "Port".ljust(5),
# 					 "Last contact (in sec)")
	
# 	print "+".join(map(lambda x: "-"*x, [25, 17, 7, 22]))
# 	for peer in self.l.keys():
# 	    elapsed = "%d" % int(time.time() - self.l[peer][1])
# 	    ip, port = self.l[peer][0]
# 	    port = "%d" % port
# 	    print "%s | %s | %s | %s" % (peer.ljust(24), ip.ljust(15), 
# 					 port.ljust(5), elapsed.rjust(21))




