from enum import Enum, IntEnum
from threading import Timer
import audioop
import io
import pyVoIP
import random
import socket
import threading
import time

__all__ = ['add_bytes', 'byte_to_bits', 'DynamicPayloadType', 'PayloadType', 'RTPParseError', 'RTPProtocol', 'RTPPacketManager', 'RTPClient', 'TransmitType']
debug = pyVoIP.debug

def byte_to_bits(byte):
  byte = bin(ord(byte)).lstrip('-0b')
  byte = ("0"*(8-len(byte)))+byte
  return byte
    
def add_bytes(byte_string):
  binary = ""
  for byte in byte_string:
    byte = bin(byte).lstrip('-0b')
    byte = ("0"*(8-len(byte)))+byte
    binary += byte
  return int(binary, 2)

class DynamicPayloadType(Exception):
  pass
  
class RTPParseError(Exception):
  pass

class RTPProtocol(Enum):
  UDP = 'udp'
  AVP = 'RTP/AVP'
  SAVP = 'RTP/SAVP'

class TransmitType(Enum):
  RECVONLY = 'recvonly'
  SENDRECV = 'sendrecv'
  SENDONLY = 'sendonly'
  INACTIVE = 'inactive'
  
  def __str__(self):
    return self.value

class PayloadType(Enum):
  def __new__(cls, value, clock, channel, description):
    obj = object.__new__(cls)
    obj._value_ = value
    obj.rate = clock
    obj.channel = channel
    obj.description = description
    return obj
  
  def __int__(self):
    try:
      return int(self.value)
    except ValueError:
      pass
    raise DynamicPayloadType(self.description + " is a dynamically assigned payload")
    
  def __str__(self):
    if type(self.value)==int:
      return self.description
    return str(self.value)
  
  #Audio
  PCMU = 0, 8000, 1, "PCMU"
  GSM = 3, 8000, 1, "GSM"
  G723 = 4, 8000, 1, "G723"
  DVI4_8000 = 5, 8000, 1, "DVI4"
  DVI4_16000 = 6, 16000, 1, "DVI4"
  LPC = 7, 8000, 1, "LPC"
  PCMA = 8, 8000, 1, "PCMA"
  G722 = 9, 8000, 1, "G722"
  L16_2 = 10, 44100, 2, "L16"
  L16 = 11, 44100, 1, "L16"
  QCELP = 12, 8000, 1, "QCELP"
  CN = 13, 8000, 1, "CN"
  MPA = 14, 90000, 0, "MPA" #MPA channel varries, should be defined in the RTP packet.
  G728 = 15, 8000, 1, "G728"
  DVI4_11025 = 16, 11025, 1, "DVI4"
  DVI4_22050 = 17, 22050, 1, "DVI4"
  G729 = 18, 8000, 1, "G729"
  
  #Video
  CELB = 25, 90000, 0, "CelB"
  JPEG = 26, 90000, 0, "JPEG"
  NV = 28, 90000, 0, "nv"
  H261 = 31, 90000, 0, "H261"
  MPV = 32, 90000, 0, "MPV"
  MP2T = 33, 90000, 1, "MP2T" #MP2T is both audio and video per RFC 3551 July 2003 5.7
  H263 = 34, 90000, 0, "H263"
  
  #Non-codec
  EVENT = "telephone-event", 8000, 0, "telephone-event"
  UNKOWN = "UNKOWN", 0, 0, "UNKOWN CODEC"

class RTPPacketManager(): 
  def __init__(self):
    self.offset = 4294967296 #The largest number storable in 4 bytes + 1.  This will ensure the offset adjustment in self.write(offset, data) works.
    self.buffer = io.BytesIO()
    self.bufferLock = threading.Lock()
    self.log = {}
    self.rebuilding = False
    
  def read(self, length=160):
    while self.rebuilding: #This acts functionally as a lock while the buffer is being rebuilt.
      time.sleep(0.01)
    self.bufferLock.acquire()
    packet = self.buffer.read(length)
    if len(packet)<length:
      packet = packet + (b'\x80' * (length-len(packet)))
    self.bufferLock.release()
    return packet
    
  def rebuild(self, reset, offset=0, data=b''):
    self.rebuilding = True
    if reset:
      self.log={}
      self.log[offset] = data
      self.buffer = io.BytesIO(data)
    else:
      bufferloc = self.buffer.tell()
      self.buffer = io.BytesIO()
      for pkt in self.log:
        self.write(pkt, self.log[pkt])
      self.buffer.seek(bufferloc, 0)
    self.rebuilding = False
    
  def write(self, offset, data):
    self.bufferLock.acquire()
    self.log[offset] = data
    bufferloc = self.buffer.tell()
    if offset<self.offset:
      reset = (abs(offset - self.offset)>=100000) #If the new timestamp is over 100,000 bytes before the earliest, erase the buffer.  This will stop memory errors.
      self.offset = offset
      self.bufferLock.release()
      self.rebuild(reset, offset, data) #Rebuilds the buffer if something before the earliest timestamp comes in, this will stop overwritting.
      return
    offset = offset - self.offset
    self.buffer.seek(offset, 0)
    self.buffer.write(data)
    self.buffer.seek(bufferloc, 0)
    self.bufferLock.release()
    
class RTPMessage():
  def __init__(self, data, assoc):
    self.RTPCompatibleVersions = pyVoIP.RTPCompatibleVersions
    self.assoc = assoc
    
    self.parse(data)
  
  def summary(self):
    data = ""
    data += "Version: "+str(self.version)+"\n"
    data += "Padding: "+str(self.padding)+"\n"
    data += "Extension: "+str(self.extension)+"\n"
    data += "CC: "+str(self.CC)+"\n"
    data += "Marker: "+str(self.marker)+"\n"
    data += "Payload Type: "+str(self.payload_type)+" ("+str(self.payload_type.value)+")"+"\n"
    data += "Sequence Number: "+str(self.sequence)+"\n"
    data += "Timestamp: "+str(self.timestamp)+"\n"
    data += "SSRC: "+str(self.SSRC)+"\n"
    return data
  
  def parse(self, packet):
    byte = byte_to_bits(packet[0:1])
    self.version = int(byte[0:2], 2)
    if not self.version in self.RTPCompatibleVersions:
      raise RTPParseError("RTP Version {} not compatible.".format(self.version))
    self.padding = bool(int(byte[2], 2))
    self.extension = bool(int(byte[3], 2)) 
    self.CC = int(byte[4:], 2)
    
    byte = byte_to_bits(packet[1:2])
    self.marker = bool(int(byte[0], 2))
    
    pt = int(byte[1:], 2)
    if pt in self.assoc:
      self.payload_type = self.assoc[pt]
    else:
      try:
        self.payload_type = PayloadType(pt)
        e = False
      except ValueError:
        e = True
      if e:
        raise RTPParseError("RTP Payload type {} not found.".format(str(pt)))
        
    self.sequence = add_bytes(packet[2:4])
    self.timestamp = add_bytes(packet[4:8])
    self.SSRC = add_bytes(packet[8:12])
    
    self.CSRC = []
    
    i = 12
    for x in range(self.CC):
      self.CSRC.append(packet[i:i+4])
      i += 4
    
    if self.extension:
      pass
      
    
    self.payload = packet[i:]
    
class RTPClient():
  def __init__(self, assoc, inIP, inPort, outIP, outPort, sendrecv, dtmf = None):
    self.NSD = True
    self.assoc = assoc # Example: {0: PayloadType.PCMU, 101: PayloadType.EVENT}
    debug("Selecting audio codec for transmission")
    for m in assoc:
      try:
        if int(assoc[m]) is not None:
          debug(f"Selected {assoc[m]}")
          self.preference = assoc[m] #Select the first available actual codec to encode with.  TODO: will need to change if video codecs are ever implemented.
          break
      except:
        debug(f"{assoc[m]} cannot be selected as an audio codec")
    
    self.inIP = inIP
    self.inPort = inPort
    self.outIP = outIP
    self.outPort = outPort
    
    self.dtmf = dtmf
    
    self.pmout = RTPPacketManager() #To Send
    self.pmin = RTPPacketManager() #Received
    self.outOffset = random.randint(1,5000)
    
    self.outSequence = random.randint(1,100)
    self.outTimestamp = random.randint(1,10000)
    self.outSSRC = random.randint(1000,65530)
    
  def start(self):
    self.sin = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.sout = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.sin.bind((self.inIP, self.inPort))
    self.sin.setblocking(False)
    
    r = Timer(1, self.recv)
    r.name = "RTP Receiver"
    r.start()
    t = Timer(1, self.trans)
    t.name = "RTP Transmitter"
    t.start()
    
  def stop(self):
    self.NSD = False
    self.sin.close()
    self.sout.close()
    
  def read(self, length=160, blocking=True):
    if not blocking:
      return self.pmin.read(length)
    packet = self.pmin.read(length)
    while packet == (b'\x80'*length) and self.NSD:
      time.sleep(0.01)
      packet = self.pmin.read(length)
    return packet
    
  def write(self, data):
    self.pmout.write(self.outOffset, data)
    self.outOffset += len(data)
    
  def recv(self):
    while self.NSD:
      try:
        packet = self.sin.recv(8192)
        self.parsePacket(packet)
      except BlockingIOError:
        time.sleep(0.01)
      except RTPParseError as e:
        debug(str(e))
      except OSError:
        pass
    
  def trans(self):
    while self.NSD:
      payload = self.pmout.read()
      payload = self.encodePacket(payload)
      packet = b"\x80" #RFC 1889 V2 No Padding Extension or CC.
      packet += chr(int(self.preference)).encode('utf8')
      try:
        packet += self.outSequence.to_bytes(2, byteorder='big')
      except OverflowError:
        self.outSequence = 0
      try:
        packet += self.outTimestamp.to_bytes(4, byteorder='big')
      except OverflowError:
        self.outTimestamp = 0
      packet += self.outSSRC.to_bytes(4, byteorder='big')
      packet += payload
      
      #debug(payload)
      
      try:
        self.sout.sendto(packet, (self.outIP, self.outPort))
      except OSError:
        pass
      
      self.outSequence += 1
      self.outTimestamp += len(payload)
      time.sleep((1/self.preference.rate)*160) #1/8000 *160
    
  def parsePacket(self, packet):
    packet = RTPMessage(packet, self.assoc)
    if packet.payload_type == PayloadType.PCMU:
      self.parsePCMU(packet)
    elif packet.payload_type == PayloadType.PCMA:
      self.parsePCMA(packet)
    elif packet.payload_type == PayloadType.EVENT:
      self.parseTelephoneEvent(packet)
    else:
      raise RTPParseError("Unsupported codec (parse): "+str(packet.payload_type))
  
  def encodePacket(self, payload):
    if self.preference == PayloadType.PCMU:
      return self.encodePCMU(payload)
    elif self.preference == PayloadType.PCMA:
      return self.encodePCMA(payload)
    else:
      raise RTPParseError("Unsupported codec (encode): "+str(self.preference))
  
  def parsePCMU(self, packet):
    data = audioop.ulaw2lin(packet.payload, 1)
    data = audioop.bias(data, 1, 128)
    self.pmin.write(packet.timestamp, data)
    
  def encodePCMU(self, packet):
    packet = audioop.bias(packet, 1, -128)
    packet = audioop.lin2ulaw(packet, 1)
    return packet
    
  def parsePCMA(self, packet):
    data = audioop.alaw2lin(packet.payload, 1)
    data = audioop.bias(data, 1, 128)
    self.pmin.write(packet.timestamp, data)
    
  def encodePCMA(self, packet):
    packet = audioop.bias(packet, 1, -128)
    packet = audioop.lin2alaw(packet, 1)
    return packet

  def parseTelephoneEvent(self, packet):
    key = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '*', '#', 'A', 'B', 'C', 'D']
    end = False

    payload = packet.payload
    event = key[payload[0]]
    byte = byte_to_bits(payload[1:2])
    if byte[0]=='1':
      end = True
    volume = int(byte[2:], 2)
    
    if packet.marker:
      if self.dtmf != None:
        self.dtmf(event)
      
