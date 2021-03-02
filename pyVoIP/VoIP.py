from enum import Enum
from pyVoIP import SIP, RTP
from threading import Timer, Lock
import io
import pyVoIP
import random
import socket
import warnings

__all__ = ['CallState', 'InvalidRangeError', 'InvalidStateError', 'VoIPCall', 'VoIPPhone']
debug = pyVoIP.debug

class InvalidRangeError(Exception):
  pass

class InvalidStateError(Exception):
  pass

class CallState(Enum):
  DIALING = "DIALING"
  RINGING = "RINGING"
  ANSWERED = "ANSWERED"
  ENDED = "ENDED"

'''
For initiating a phone call, try sending the packet and the recieved OK packet will be sent to the VoIPCall request header.
'''
class VoIPCall():
  def __init__(self, phone, callstate, request, session_id, myIP, portRange=(10000, 20000), ms = None):
    self.state = callstate
    self.phone = phone
    self.sip = self.phone.sip
    self.request = request
    self.call_id = request.headers['Call-ID']
    self.session_id = str(session_id)
    self.myIP = myIP
    self.rtpPortHigh = portRange[1]
    self.rtpPortLow = portRange[0]
    
    self.dtmfLock = Lock()
    self.dtmf = io.StringIO()
    
    self.RTPClients = []
    
    self.connections = 0
    self.audioPorts = 0
    self.videoPorts = 0
    
    self.assignedPorts = {}
    
    
    if callstate == CallState.RINGING:
      audio = []
      video = []
      for x in self.request.body['c']:
        self.connections += x['address_count']
      for x in self.request.body['m']:
        if x['type'] == "audio":
          self.audioPorts += x['port_count']
          audio.append(x)
        elif x['type'] == "video":
          self.videoPorts += x['port_count']
          video.append(x)
        else:
          warnings.warn("Unknown media description: "+x['type'], stacklevel=2)
      
      #Ports Adjusted is used in case of multiple m=audio or m=video tags.
      if len(audio) > 0:
        audioPortsAdj = self.audioPorts/len(audio)
      else:
        audioPortsAdj = 0
      if len(video) > 0:
        videoPortsAdj = self.videoPorts/len(video)
      else:
        videoPortsAdj = 0
      
      if not ((audioPortsAdj == self.connections or self.audioPorts == 0) and (videoPortsAdj == self.connections or self.videoPorts == 0)):
        warnings.warn("Unable to assign ports for RTP.", stacklevel=2) #TODO: Throw error to PBX in this case
        return
      
      for i in request.body['m']:
        assoc = {}
        e = False
        for x in i['methods']:
          try:
            p = RTP.PayloadType(int(x))
            assoc[int(x)] = p
          except ValueError:
            try:
              p = RTP.PayloadType(i['attributes'][x]['rtpmap']['name'])
              assoc[int(x)] = p
            except ValueError:
              #e = True
              pt = i['attributes'][x]['rtpmap']['name']
              warnings.warn(f"RTP Payload type {pt} not found.", stacklevel=20)
              warnings.simplefilter("default") #Resets the warning filter so this warning will come up again if it happens.  However, this also resets all other warnings as well.
              p = RTP.PayloadType("UNKOWN")
              assoc[int(x)] = p
        
        if e:
          raise RTP.RTPParseError("RTP Payload type {} not found.".format(str(pt)))
        
        #Make sure codecs are compatible. 
        codecs = {}
        for m in assoc:
          if assoc[m] in pyVoIP.RTPCompatibleCodecs:
            codecs[m] = assoc[m]
        #TODO: If no codecs are compatible then send error to PBX.
        
        port = None
        while port == None:
          proposed = random.randint(self.rtpPortLow, self.rtpPortHigh)
          if not proposed in self.phone.assignedPorts:
            self.phone.assignedPorts.append(proposed)
            self.assignedPorts[proposed] = codecs
            port = proposed
        for ii in range(len(request.body['c'])):
          self.RTPClients.append(RTP.RTPClient(codecs, self.myIP, port, request.body['c'][ii]['address'], i['port']+ii, request.body['a']['transmit_type'], dtmf=self.dtmfCallback)) #TODO: Check IPv4/IPv6
    elif callstate == CallState.DIALING:
      self.ms = ms
      for m in self.ms:
        self.port = m
        self.assignedPorts[m] = self.ms[m]

  def dtmfCallback(self, code):
    self.dtmfLock.acquire()
    bufferloc = self.dtmf.tell()
    self.dtmf.seek(0, 2)
    self.dtmf.write(code)
    self.dtmf.seek(bufferloc, 0)
    self.dtmfLock.release()

  def getDTMF(self, length=1):
    self.dtmfLock.acquire()
    packet = self.dtmf.read(length)
    self.dtmfLock.release()
    return packet

  def genMs(self): #For answering originally and for re-negotiations
    m = {}
    for x in self.RTPClients:
      x.start()
      m[x.inPort] = x.assoc
    
    return m

  def renegotiate(self, request):
    m = self.genMs()
    message = self.sip.genAnswer(request, self.session_id, m, request.body['a']['transmit_type'])
    self.sip.out.sendto(message.encode('utf8'), (self.phone.server, self.phone.port))
    for i in request.body['m']:
      for ii, client in zip(range(len(request.body['c'])), self.RTPClients):
        client.outIP = request.body['c'][ii]['address']
        client.outPort = i['port']+ii #TODO: Check IPv4/IPv6

  def answer(self):
    if self.state != CallState.RINGING:
      raise InvalidStateError("Call is not ringing")
    m = self.genMs()
    message = self.sip.genAnswer(self.request, self.session_id, m, self.request.body['a']['transmit_type'])
    self.sip.out.sendto(message.encode('utf8'), (self.phone.server, self.phone.port))
    self.state = CallState.ANSWERED
    
  def answered(self, request):
    if self.state != CallState.DIALING:
      return
    
    for i in request.body['m']:
      assoc = {}
      e = False
      for x in i['methods']:
        try:
          p = RTP.PayloadType(int(x))
          assoc[int(x)] = p
        except ValueError:
          try:
            p = RTP.PayloadType(i['attributes'][x]['rtpmap']['name'])
            assoc[int(x)] = p
          except ValueError:
            e = True
      
      if e:
        raise RTP.ParseError("RTP Payload type {} not found.".format(str(pt)))
      
      
      for ii in range(len(request.body['c'])):
        self.RTPClients.append(RTP.RTPClient(assoc, self.myIP, self.port, request.body['c'][ii]['address'], i['port']+ii, request.body['a']['transmit_type'], dtmf=self.dtmfCallback)) #TODO: Check IPv4/IPv6
    
    for x in self.RTPClients:
      x.start()
    self.request.headers['Contact'] = request.headers['Contact']
    self.request.headers['To']['tag'] = request.headers['To']['tag']
    self.state = CallState.ANSWERED
  
  def notFound(self, request):
    if self.state != CallState.DIALING:
      debug(f"TODO: 500 Error, received a not found response for a call not in the dailing state.  Call: {self.call_id}, Call State: {self.state}")
      return
    
    for x in self.RTPClients:
      x.stop()
    self.state = CallState.ENDED
    del self.phone.calls[self.request.headers['Call-ID']]
    debug("Call not found and terminated")
    warnings.warn(f"The number '{request.headers['To']['number']}' was not found.  Did you call the wrong number? CallState set to CallState.ENDED.", stacklevel=20)
    warnings.simplefilter("default") #Resets the warning filter so this warning will come up again if it happens.  However, this also resets all other warnings as well.
  
  def unavailable(self, request):
    if self.state != CallState.DIALING:
      debug(f"TODO: 500 Error, received an unavailable response for a call not in the dailing state.  Call: {self.call_id}, Call State: {self.state}")
      return
    
    for x in self.RTPClients:
      x.stop()
    self.state = CallState.ENDED
    del self.phone.calls[self.request.headers['Call-ID']]
    debug("Call unavailable and terminated")
    warnings.warn(f"The number '{request.headers['To']['number']}' was unavailable.  CallState set to CallState.ENDED.", stacklevel=20)
    warnings.simplefilter("default") #Resets the warning filter so this warning will come up again if it happens.  However, this also resets all other warnings as well.
  
  def deny(self):
    if self.state != CallState.RINGING:
      raise InvalidStateError("Call is not ringing")
    message = self.sip.genBusy(self.request)
    self.sip.out.sendto(message.encode('utf8'), (self.phone.server, self.phone.port))
    self.RTPClients = []
    self.state = CallState.ENDED
  
  def hangup(self):
    if self.state != CallState.ANSWERED:
      raise InvalidStateError("Call is not answered")
    for x in self.RTPClients:
      x.stop()
    self.sip.bye(self.request)
    self.state = CallState.ENDED
    del self.phone.calls[self.request.headers['Call-ID']]
    
  def bye(self):
    if self.state == CallState.ANSWERED:
      for x in self.RTPClients:
        x.stop()
      self.state = CallState.ENDED
    del self.phone.calls[self.request.headers['Call-ID']]
    
  def writeAudio(self, data):
    for x in self.RTPClients:
      x.write(data)
      
  def readAudio(self, length=160, blocking=True):
    if len(self.RTPClients) == 1:
      return self.RTPClients[0].read(length, blocking)
    data = []
    for x in self.RTPClients:
      data.append(x.read(length))
    nd = audioop.add(data.pop(0), data.pop(0), 1) #Mix audio from different sources before returning
    for d in data:
      nd = audioop.add(nd, d, 1)
    return nd
      

class VoIPPhone():
  def __init__(self, server, port, username, password, callCallback=None, myIP=None, sipPort=5060, rtpPortLow=10000, rtpPortHigh=20000):
    if rtpPortLow > rtpPortHigh:
      raise InvalidRangeError("'rtpPortHigh' must be >= 'rtpPortLow'")
      
    self.rtpPortLow = rtpPortLow
    self.rtpPortHigh = rtpPortHigh
    
    self.assignedPorts = []
    self.session_ids = []
    
    self.server = server
    self.port = port
    self.hostname = socket.gethostname()
    self.myIP = socket.gethostbyname(self.hostname)
    if myIP!=None:
      self.myIP = myIP
    self.username = username
    self.password = password
    self.callCallback = callCallback
    
    self.calls = {}    
    self.sip = SIP.SIPClient(server, port, username, password, myIP=self.myIP, myPort=sipPort, callCallback=self.callback)
    
  def callback(self, request):
    call_id = request.headers['Call-ID']
    #debug("Callback: "+request.summary())
    if request.type == pyVoIP.SIP.SIPMessageType.MESSAGE:
      #debug("This is a message")
      if request.method == "INVITE":
        if call_id in self.calls:
          debug("Re-negotiation detected!")
          self.calls[call_id].renegotiate(request)
          #message = self.sip.genAnswer(request, self.calls[call_id].session_id, self.calls[call_id].genMs(), request.body['a']['transmit_type'])
          #self.sip.out.sendto(message.encode('utf8'), (self.server, self.port))
          return #Raise Error
        if self.callCallback == None:
          message = self.sip.genBusy(request)
          self.sip.out.sendto(message.encode('utf8'), (self.server, self.port))
        else:
          debug("New call!")
          sess_id = None
          while sess_id == None:
            proposed = random.randint(1, 100000)
            if not proposed in self.session_ids:
              self.session_ids.append(proposed)
              sess_id = proposed
          message = self.sip.genRinging(request)
          self.sip.out.sendto(message.encode('utf8'), (self.server, self.port))
          self.calls[call_id] = VoIPCall(self, CallState.RINGING, request, sess_id, self.myIP, portRange=(self.rtpPortLow, self.rtpPortHigh))
          try:
            t = Timer(1, self.callCallback, [self.calls[call_id]])
            t.name = "Phone Call: "+call_id
            t.start()
          except Exception as e:
            message = self.sip.genBusy(request)
            self.sip.out.sendto(message.encode('utf8'), (self.server, self.port))
            raise e
      elif request.method == "BYE":
        if not call_id in self.calls:
          return
        self.calls[call_id].bye()
    else:
      if request.status == SIP.SIPStatus.OK:
        debug("OK recieved")
        if not call_id in self.calls:
          debug("Unknown call")
          return
        self.calls[call_id].answered(request)
        debug("Answered")
        ack = self.sip.genAck(request)
        self.sip.out.sendto(ack.encode('utf8'), (self.server, self.port))
      elif request.status == SIP.SIPStatus.NOT_FOUND:
        debug("Not Found recieved, invalid number called?")
        if not call_id in self.calls:
          debug("Unkown call")
          debug("TODO: Add 481 here as server is probably waiting for an ACK")
        self.calls[call_id].notFound(request)
        debug("Terminating Call")
        ack = self.sip.genAck(request)
        self.sip.out.sendto(ack.encode('utf8'), (self.server, self.port))
      elif request.status == SIP.SIPStatus.SERVICE_UNAVAILABLE:
        debug("Service Unavailable recieved")
        if not call_id in self.calls:
          debug("Unkown call")
          debug("TODO: Add 481 here as server is probably waiting for an ACK")
        self.calls[call_id].unavailable(request)
        debug("Terminating Call")
        ack = self.sip.genAck(request)
        self.sip.out.sendto(ack.encode('utf8'), (self.server, self.port))
    
  def start(self):
    self.sip.start()
    
  def stop(self):
    for x in self.calls.copy():
      try:
        self.calls[x].hangup()
      except InvalidStateError:
        pass
    self.sip.stop()
    
  def call(self, number):
    port = None
    while port == None:
      proposed = random.randint(self.rtpPortLow, self.rtpPortHigh)
      if not proposed in self.assignedPorts:
        self.assignedPorts.append(proposed)
        port = proposed
    medias = {}
    medias[port] = {0: pyVoIP.RTP.PayloadType.PCMU, 101: pyVoIP.RTP.PayloadType.EVENT}
    request, call_id, sess_id = self.sip.invite(number, medias, pyVoIP.RTP.TransmitType.SENDRECV)
    self.calls[call_id] = VoIPCall(self, CallState.DIALING, request, sess_id, self.myIP, ms = medias)
    
    return self.calls[call_id]