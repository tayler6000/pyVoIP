from enum import Enum
from pyVoIP import SIP, RTP
from threading import Timer, Lock
import io
import pyVoIP
import random
import socket

__all__ = ['CallState', 'InvalidRangeError', 'InvalidStateError', 'VoIPCall', 'VoIPPhone']

class InvalidRangeError(Exception):
  pass

class InvalidStateError(Exception):
  pass

class CallState(Enum):
  RINGING = 0
  ANSWERED = 1
  ENDED = 2

class VoIPCall():
  def __init__(self, phone, request, session_id, myIP, rtpPortLow, rtpPortHigh):
    self.state = CallState.RINGING
    self.phone = phone
    self.sip = self.phone.sip
    self.request = request
    self.call_id = request.headers['Call-ID']
    self.session_id = str(session_id)
    self.myIP = myIP
    self.rtpPortHigh = rtpPortHigh
    self.rtpPortLow = rtpPortLow
    
    self.dtmfLock = Lock()
    self.dtmf = io.StringIO()
    
    self.RTPClients = []
    
    self.connections = 0
    self.audioPorts = 0
    self.videoPorts = 0
    
    self.assignedPorts = {}
    
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
        print("Unknown media description: "+x['type'])
    
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
      print("Unable to assign ports for RTP.") 
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
      
      port = None
      while port == None:
        proposed = random.randint(rtpPortLow, rtpPortHigh)
        if not proposed in self.phone.assignedPorts:
          self.phone.assignedPorts.append(proposed)
          self.assignedPorts[proposed] = assoc
          port = proposed
      for ii in range(len(request.body['c'])):
        offset = ii * 2
        self.RTPClients.append(RTP.RTPClient(assoc, self.myIP, port, request.body['c'][ii]['address'], i['port']+ii, request.body['a']['transmit_type'], dtmf=self.dtmfCallback)) #TODO: Check IPv4/IPv6

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

  def answer(self):
    if self.state != CallState.RINGING:
      raise InvalidStateError("Call is not ringing")
    m = {}
    for x in self.RTPClients:
      x.start()
      m[x.inPort] = x.assoc
    message = self.sip.genAnswer(self.request, self.session_id, m, self.request.body['a']['transmit_type'])
    self.sip.out.sendto(message.encode('utf8'), (self.phone.server, self.phone.port))
    self.state = CallState.ANSWERED
      
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
      
  def readAudio(self, length=160, blocking=False):
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
    if request.method == "INVITE":
      if call_id in self.calls:
        return #Raise Error
      if self.callCallback == None:
        message = self.sip.genBusy(request)
        self.sip.out.sendto(message.encode('utf8'), (self.server, self.port))
      else:
        sess_id = None
        while sess_id == None:
          proposed = random.randint(1, 100000)
          if not proposed in self.session_ids:
            self.session_ids.append(proposed)
            sess_id = proposed
        self.calls[call_id] = VoIPCall(self, request, sess_id, self.myIP, self.rtpPortLow, self.rtpPortHigh)
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
    
  def start(self):
    self.sip.start()
    
  def stop(self):
    for x in self.calls.copy():
      try:
        self.calls[x].hangup()
      except InvalidStateError:
        pass
    self.sip.stop()