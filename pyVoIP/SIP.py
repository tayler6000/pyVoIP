from enum import IntEnum
from threading import Timer, Lock
import pyVoIP
import hashlib
import socket
import random
import re
import time

__all__ = ['Counter', 'InvalidAccountInfoError', 'SIPClient', 'SIPMessage', 'SIPMessageType', 'SIPParseError', 'SIPStatus']

class InvalidAccountInfoError(Exception):
  pass

class SIPParseError(Exception):
  pass

class Counter():
  def __init__(self, start=1):
    self.x = start
    
  def count(self):
    x = self.x
    self.x += 1
    return x
    
  def next(self):
    return self.count()

class SIPStatus(IntEnum):
    def __new__(cls, value, phrase, description=''):
        obj = int.__new__(cls, value)
        obj._value_ = value

        obj.phrase = phrase
        obj.description = description
        return obj

    # informational
    TRYING = 100, 'Trying', 'Extended search being performed, may take a significant time'
    RINGING = (180, 'Ringing',
            'Destination user agent received INVITE, and is alerting user of call')
    FORWARDED = 181, 'Call is Being Forwarded'
    QUEUED = 182, 'Queued'
    SESSION_PROGRESS = 183, 'Session Progress'
    TERMINATED = 199, 'Early Dialog Terminated'

    # success
    OK = 200, 'OK', 'Request successful'
    ACCEPTED = (202, 'Accepted',
        'Request accepted, processing continues (Deprecated.)')
    NO_NOTIFICATION = 204, 'No Notification', 'Request fulfilled, nothing follows'

    # redirection
    MULTIPLE_CHOICES = (300, 'Multiple Choices',
        'Object has several resources -- see URI list')
    MOVED_PERMANENTLY = (301, 'Moved Permanently',
        'Object moved permanently -- see URI list')
    MOVED_TEMPORARILY = 302, 'Moved Temporarily', 'Object moved temporarily -- see URI list'
    USE_PROXY = (305, 'Use Proxy',
        'You must use proxy specified in Location to access this resource')
    ALTERNATE_SERVICE = (380, 'Alternate Service',
        'The call failed, but alternatives are available -- see URI list')

    # client error
    BAD_REQUEST = (400, 'Bad Request',
        'Bad request syntax or unsupported method')
    UNAUTHORIZED = (401, 'Unauthorized',
        'No permission -- see authorization schemes')
    PAYMENT_REQUIRED = (402, 'Payment Required',
        'No payment -- see charging schemes')
    FORBIDDEN = (403, 'Forbidden',
        'Request forbidden -- authorization will not help')
    NOT_FOUND = (404, 'Not Found',
        'Nothing matches the given URI')
    METHOD_NOT_ALLOWED = (405, 'Method Not Allowed',
        'Specified method is invalid for this resource')
    NOT_ACCEPTABLE = (406, 'Not Acceptable',
        'URI not available in preferred format')
    PROXY_AUTHENTICATION_REQUIRED = (407,
        'Proxy Authentication Required',
        'You must authenticate with this proxy before proceeding')
    REQUEST_TIMEOUT = (408, 'Request Timeout',
        'Request timed out; try again later')
    CONFLICT = 409, 'Conflict', 'Request conflict'
    GONE = (410, 'Gone',
        'URI no longer exists and has been permanently removed')
    LENGTH_REQUIRED = (411, 'Length Required',
        'Client must specify Content-Length')
    CONDITIONAL_REQUEST_FAILED = (412, 'Conditional Request Failed')
    REQUEST_ENTITY_TOO_LARGE = (413, 'Request Entity Too Large',
        'Entity is too large')
    REQUEST_URI_TOO_LONG = (414, 'Request-URI Too Long',
        'URI is too long')
    UNSUPPORTED_MEDIA_TYPE = (415, 'Unsupported Media Type',
        'Entity body in unsupported format')
    UNSUPPORTED_URI_SCHEME = (416,
        'Unsupported URI Scheme',
        'Cannot satisfy request')
    UNKOWN_RESOURCE_PRIORITY = (417, 'Unkown Resource-Priority',
        'There was a resource-priority option tag, but no Resource-Priority header')
    BAD_EXTENSION = (420, 'Bad Extension', 
        'Bad SIP Protocol Extension used, not understood by the server.')
    EXTENSION_REQUIRED = (421, 'Extension Required',
        'Server requeires a specific extension to be listed in the Supported header.')
    SESSION_INTERVAL_TOO_SMALL = 422, 'Session Interval Too Small'
    SESSION_INTERVAL_TOO_BRIEF = 423, 'Session Interval Too Breif'
    BAD_LOCATION_INFORMATION = 424, 'Bad Location Information'
    USE_IDENTITY_HEADER = (428, 'Use Identity Header',
        'The server requires an Identity header, and one has not been provided.')
    PROVIDE_REFERRER_IDENTITY = (429, 'Provide Referrer Identity')
    FLOW_FAILED = (430, 'Flow Failed',
        'A specific flow to a user agent has failed, although other flows may succeed.') #This response is intended for use between proxy devices, and should not be seen by an endpoint (and if it is seen by one, should be treated as a 400 Bad Request response).
    ANONYMITY_DISALLOWED = (433,
        'Anonymity Disallowed')
    BAD_IDENTITY_INFO = (436, 'Bad Identity-Info')
    UNSUPPORTED_CERTIFICATE = (437, 'Unsupported Certificate')
    INVALID_IDENTITY_HEADER = (438, 'Invalid Identity Header')
    FIRST_HOP_LACKS_OUTBOUND_SUPPORT = (439, 'First Hop Lacks Outbound Support')
    MAX_BREADTH_EXCEEDED = (440, 'Max-Breadth Exceeded')
    BAD_INFO_PACKAGE = (469, 'Bad Info Package')
    CONSENT_NEEDED = (470, 'Consent Needed')
    TEMPORARILY_UNAVAILABLE = (480, 'Temporarily Unavailable')
    CALL_OR_TRANSACTION_DOESNT_EXIST = (481, 'Call/Transaction Does Not Exist')
    LOOP_DETECTED = 482, 'Loop Detected'
    TOO_MANY_HOPS = (483, 'Too Many Hops')
    ADDRESS_INCOMPLETE = (484, 'Address Incomplete')
    AMBIGUOUS = (485, 'Ambiguous')
    BUSY_HERE = (486, 'Busy Here', 'Callee is busy')
    REQUEST_TERMINATED = (487, 'Request Terminated')
    NOT_ACCEPTABLE_HERE = (488, 'Not Acceptable Here')
    BAD_EVENT = (489, 'Bad Event')
    REQUEST_PENDING = (491, 'Request Pending')
    UNDECIPHERABLE = (493, 'Undecipherable')
    SECURITY_AGREEMENT_REQUIRED = (494, 'Security Agreement Required')
    
    # server errors
    INTERNAL_SERVER_ERROR = (500, 'Internal Server Error',
        'Server got itself in trouble')
    NOT_IMPLEMENTED = (501, 'Not Implemented',
        'Server does not support this operation')
    BAD_GATEWAY = (502, 'Bad Gateway',
        'Invalid responses from another server/proxy')
    SERVICE_UNAVAILABLE = (503, 'Service Unavailable',
        'The server cannot process the request due to a high load')
    GATEWAY_TIMEOUT = (504, 'Server Timeout',
        'The server did not receive a timely response')
    SIP_VERSION_NOT_SUPPORTED = (505, 'SIP Version Not Supported',
        'Cannot fulfill request')
    MESSAGE_TOO_LONG = (513, 'Message Too Long')
    PUSH_NOTIFICATION_SERVICE_NOT_SUPPORTED = (555, 'Push Notification Service Not Supported')
    PRECONDITION_FAILURE = (580, 'Precondition Failure')

    #Global Failure Responses
    BUSY_EVERYWHERE = 600, 'Busy Everywhere'
    DECLINE = 603, 'Decline'
    DOES_NOT_EXIST_ANYWHERE = 604, 'Does Not Exist Anywhere'
    GLOBAL_NOT_ACCEPTABLE = 606, 'Not Acceptable'
    UNWANTED = 607, 'Unwanted'
    REJECTED = 608, 'Rejected'

class SIPMessageType(IntEnum):
  def __new__(cls, value):
    obj = int.__new__(cls, value)
    obj._value_ = value
    return obj

    
  MESSAGE = 1
  RESPONSE = 0

class SIPMessage():
  def __init__(self, data):
    self.SIPCompatibleVersions = pyVoIP.SIPCompatibleVersions
    self.SIPCompatibleMethods = pyVoIP.SIPCompatibleMethods
    self.heading = ""
    self.type = None
    self.status = 0
    self.headers = {}
    self.body = {}
    self.authentication = {}
    self.raw = data
    self.parse(data)
    
  def summary(self):
    data = ""
    if self.type == SIPMessageType.RESPONSE:
      data += "Status: "+str(int(self.status))+" "+str(self.status.phrase)+"\n\n"
    else:
      data += "Method: "+str(self.method)+"\n\n"
    data += "Headers:\n"
    for x in self.headers:
      data += x+": "+str(self.headers[x])+"\n"
    data += "\n"
    data += "Body:\n"
    for x in self.body:
      data += x+": "+str(self.body[x])+"\n"
    
    return data
    
  def parse(self, data):
    headers = data.split(b'\r\n\r\n')[0]
    body = data.split(b'\r\n\r\n')[1]
    
    headers_raw = headers.split(b'\r\n')
    heading = headers_raw.pop(0)
    check = str(heading.split(b" ")[0], 'utf8')
    
    if check in self.SIPCompatibleVersions:
      self.type = SIPMessageType.RESPONSE
      self.parseSIPResponce(data)
    elif check in self.SIPCompatibleMethods:
      self.type = SIPMessageType.MESSAGE
      self.parseSIPMessage(data)
    else:
      raise SIPParseError("Unable to decipher SIP request: "+str(heading, 'utf8'))
    
  def parseHeader(self, header, data):
    if header=="Via":
      info = re.split(" |;", data)
      self.headers['Via'] = {'type': info[0], 'address':(info[1].split(':')[0], info[1].split(':')[1]), 'branch': info[2].split('=')[1]}
    elif header=="From" or header=="To":
      info = data.split(';tag=')
      tag = ''
      if len(info) >= 2:
        tag = info[1]
      raw = info[0]
      contact = raw.split('<sip:')
      contact[0] = contact[0].strip('"').strip("'")
      address = contact[1].strip('>')
      number = address.split('@')[0]
      host = address.split('@')[1]
      
      self.headers[header] = {'raw': raw, 'tag': tag, 'address': address, 'number': number, 'caller': contact[0], 'host': host}
    elif header=="CSeq":
      self.headers[header] = {'check': data.split(" ")[0], 'method': data.split(" ")[1]}
    elif header=="Allow" or header=="Supported":
      self.headers[header] = data.split(", ")
    elif header=="Content-Length":
      self.headers[header] = int(data)
    elif header=='WWW-Authenticate' or header=="Authorization":
      info = data.split(", ")
      header_data = {}
      for x in info:
        header_data[x.split('=')[0]] = x.split('=')[1].strip('"')
      self.headers[header] = header_data
      self.authentication = header_data
    else:
      self.headers[header] = data
      
  def parseBody(self, header, data):
    if 'Content-Encoding' in self.headers:
      raise SIPParseError("Unable to parse encoded content.")
    if self.headers['Content-Type'] == 'application/sdp':
      #Referenced RFC 4566 July 2006
      if header == "v":
        #SDP 5.1 Version
        self.body[header] = int(data)
      elif header == "o":
        #SDP 5.2 Origin
        #o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address>
        data = data.split(' ')
        self.body[header] = {'username': data[0], 'id': data[1], 'version': data[2], 'network_type': data[3], 'address_type': data[4], 'address': data[5]}
      elif header == "s":
        #SDP 5.3 Session Name
        #s=<session name>
        self.body[header] = data
      elif header  == "i":
        #SDP 5.4 Session Information
        #i=<session-description>
        self.body[header] = data
      elif header == "u":
        #SDP 5.5 URI
        #u=<uri>
        self.body[header] = data
      elif header == "e" or header == "p":
        #SDP 5.6 Email Address and Phone Number of person responsible for the conference
        #e=<email-address>
        #p=<phone-number>
        self.body[header] = data
      elif header == "c":
        #SDP 5.7 Connection Data
        #c=<nettype> <addrtype> <connection-address>
        if not 'c' in self.body:
          self.body['c'] = []
        data = data.split(' ')
        #TTL Data and Multicast addresses may be specified.
        #For IPv4 its listed as addr/ttl/number of addresses.
        #c=IN IP4 224.2.1.1/127/3 means:
        #c=IN IP4 224.2.1.1/127
        #c=IN IP4 224.2.1.2/127
        #c=IN IP4 224.2.1.3/127
        #With the TTL being 127.  IPv6 does not support time to live so you will only see a / for multicast addresses.
        if '/' in data[2]:
          if data[1] == "IP6":
            self.body[header].append({'network_type': data[0], 'address_type': data[1], 'address': data[2].split('/')[0], 'ttl': None, 'address_count': int(data[2].split('/')[1])})
          else:
            address_data=data[2].split('/')
            if len(address_data) == 2:
              self.body[header].append({'network_type': data[0], 'address_type': data[1], 'address': address_data[0], 'ttl': int(address_data[1]), 'address_count': 1})
            else:
              self.body[header].append({'network_type': data[0], 'address_type': data[1], 'address': address_data[0], 'ttl': int(address_data[1]), 'address_count': int(address_data[2])})
        else:
          self.body[header].append({'network_type': data[0], 'address_type': data[1], 'address': data[2], 'ttl': None, 'address_count': 1})
      elif header == "b":
        #SDP 5.8 Bandwidth
        #b=<bwtype>:<bandwidth>
        #A bwtype of CT means Conference Total between all medias and all devices in the conference.
        #A bwtype of AS means Applicaton Specific total for this media and this device.
        #The bandwidth is given in kilobits per second.  As this was written in 2006, this could be Kibibits.
        #TODO: Implement Bandwidth restrictions
        data = data.split(':')
        self.body[header] = {'type': data[0], 'bandwidth': data[1]}
      elif header == "t":
        #SDP 5.9 Timing
        #t=<start-time> <stop-time>
        data = data.split(' ')
        self.body[header] = {'start': data[0], 'stop': data[1]}
      elif header == "r":
        #SDP 5.10 Repeat Times
        #r=<repeat interval> <active duration> <offsets from start-time>
        data = data.split(' ')
        self.body[header] = {'repeat': data[0], 'duration': data[1], 'offset1': data[2], 'offset2': data[3]}
      elif header == "z":
        #SDP 5.11 Time Zones
        #z=<adjustment time> <offset> <adjustment time> <offset> ....
        #Used for change in timezones such as day light savings time.
        data = data.split(0)
        amount = len(data)/2
        self.body[header] = {}
        for x in range(amount):
          self.body[header]['adjustment-time'+str(x)]  = data[x*2]
          self.body[header]['offset'+str(x)]  = data[x*2+1]
      elif header == "k":
        #SDP 5.12 Encryption Keys
        #k=<method>
        #k=<method>:<encryption key>
        if ':' in data:
          data = data.split(':')
          self.body[header] = {'method': data[0], 'key': data[1]}
        else:
          self.body[header] = {'method': data}
      elif header == "m":
        #SDP 5.14 Media Descriptions
        #m=<media> <port>/<number of ports> <proto> <fmt> ...
        #<port> should be even, and <port>+1 should be the RTCP port.
        #<number of ports> should coinside with number of addresses in SDP 5.7 c=
        if not 'm' in self.body:
          self.body['m'] = []
        data = data.split(' ')
        
        if '/' in data[1]:
          ports_raw = data[1].split('/')
          port = ports_raw[0]
          count = ports_raw[1]
        else:
          port = data[1]
          count = 1
        methods = data[3:]
        
        self.body['m'].append({'type': data[0], 'port': int(port), 'port_count': int(count), 'protocol': pyVoIP.RTP.RTPProtocol(data[2]), 'methods': methods, 'attributes': {}})
        for x in self.body['m'][-1]['methods']:
          self.body['m'][-1]['attributes'][x] = {}
      elif header == "a":
        #SDP 5.13 Attributes & 6.0 SDP Attributes
        #a=<attribute>
        #a=<attribute>:<value>
        
        if not "a" in self.body:
          self.body['a'] = {}
        
        if ':' in data:
          data = data.split(':')
          attribute = data[0]
          value = data[1]
        else:
          attribute = data
          value = None
        
        if value != None:
          if attribute == "rtpmap":
            #a=rtpmap:<payload type> <encoding name>/<clock rate> [/<encoding parameters>]
            value = re.split(" |/", value)
            for x in self.body['m']:
              if value[0] in x['methods']:
                index = self.body['m'].index(x)
                break
            if len(value) == 4:
              encoding = value[3]
            else:
              encoding = None
            self.body['m'][int(index)]['attributes'][value[0]]['rtpmap'] = {'id': value[0], 'name': value[1], 'frequency': value[2], 'encoding': encoding}
          elif attribute == "fmtp":
            #a=fmtp:<format> <format specific parameters>
            value = value.split(' ')
            for x in self.body['m']:
              if value[0] in x['methods']:
                index = self.body['m'].index(x)
                break
                
            self.body['m'][int(index)]['attributes'][value[0]]['fmtp'] = {'id': value[0], 'settings': value[1:]}
          else:
            self.body['a'][attribute] = value
        else:
          if attribute == "recvonly" or attribute == "sendrecv" or attribute == "sendonly" or attribute == "inactive":
            self.body['a']['transmit_type'] = pyVoIP.RTP.TransmitType(attribute)
      else:
        self.body[header] = data
      
    else:
      self.body[header] = data    
      
  def parseSIPResponce(self, data):
    headers = data.split(b'\r\n\r\n')[0]
    body = data.split(b'\r\n\r\n')[1]
    
    headers_raw = headers.split(b'\r\n')
    self.heading = headers_raw.pop(0)
    self.version = str(self.heading.split(b" ")[0], 'utf8')
    if self.version not in self.SIPCompatibleVersions:
      raise SIPParseError("SIP Version {} not compatible.".format(self.version))
      
    self.status = SIPStatus(int(self.heading.split(b" ")[1]))
    
    headers = {}
    
    for x in headers_raw:
      i = str(x, 'utf8').split(': ')
      headers[i[0]] = i[1]
      
    for x in headers:
      self.parseHeader(x, headers[x])
  
  def parseSIPMessage(self, data):
    headers = data.split(b'\r\n\r\n')[0]
    body = data.split(b'\r\n\r\n')[1]
    
    headers_raw = headers.split(b'\r\n')
    self.heading = headers_raw.pop(0)
    self.version = str(self.heading.split(b" ")[2], 'utf8')
    if self.version not in self.SIPCompatibleVersions:
      raise SIPParseError("SIP Version {} not compatible.".format(self.version))
      
    self.method = str(self.heading.split(b" ")[0], 'utf8')
    
    headers = {}
    
    for x in headers_raw:
      i = str(x, 'utf8').split(': ')
      headers[i[0]] = i[1]
      
    for x in headers:
      self.parseHeader(x, headers[x])
      
    if len(body)>0:
      body_raw = body.split(b'\r\n')
      body_tags={}
      for x in body_raw:
        i = str(x, 'utf8').split('=')
        if i != ['']:
          self.parseBody(i[0], i[1])
      
class SIPClient():
  def __init__(self, server, port, username, password, myIP=None, myPort=5060, callCallback=None):
    self.NSD = True
    self.server = server
    self.port = port
    self.hostname = socket.gethostname()
    self.myIP = socket.gethostbyname(self.hostname)
    if myIP!=None:
      self.myIP = myIP
    self.username = username
    self.password = password
    
    self.callCallback=callCallback
    
    self.tag=hashlib.md5(str(random.randint(1, 10000)).encode('utf8')).hexdigest()[0:8]
    
    self.myPort = myPort
    
    self.inviteCounter = Counter()
    self.registerCounter = Counter()
    self.byeCounter = Counter()
    self.callID = Counter()
    
    self.registerThread = None
    self.recvLock = Lock()
    
  
  def recv(self):
    while self.NSD:
      self.recvLock.acquire()
      self.s.setblocking(False)
      try:
        message = SIPMessage(self.s.recv(8192))
        #print(message.summary())
        if message.type != SIPMessageType.MESSAGE:
          if message.status == SIPStatus.OK:
            pass
          else:
            print("TODO: Add 500 Error on Receiving SIP Response")
          self.s.setblocking(True)
          self.recvLock.release()
          continue
        if message.method == "INVITE":
          if self.callCallback == None:
            request = self.genBusy(message)
            self.out.sendto(request.encode('utf8'), (self.server, self.port))
          else:
            request = self.genRinging(message)
            self.out.sendto(request.encode('utf8'), (self.server, self.port))
            self.callCallback(message)
        elif message.method == "BYE":
          self.callCallback(message)
        elif message.method == "ACK":
          pass
        else:
          print("TODO: Add 400 Error on non processable request")
      except BlockingIOError:
        time.sleep(0.01)
      except SIPParseError as e:
        if "SIP Version" in str(e):
          request = self.genSIPVersionNotSupported(message)
          self.out.sendto(request.encode('utf8'), (self.server, self.port))
        else:
          print(str(e))
      #except Exception as e:
        #print("SIP recv error: "+str(e))
      self.s.setblocking(True)
      self.recvLock.release()
  
  def start(self):
    self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.s.bind((self.myIP, self.myPort))
    register = self.register()
    t = Timer(1, self.recv)
    t.name = "SIP Recieve"
    t.start()
     
  def stop(self):
    self.NSD = False
    self.registerThread.cancel()
    self.deregister()
    self.s.close()
    self.out.close()
    
  def genCallID(self):
    return hashlib.sha256(str(self.callID.next()).encode('utf8')).hexdigest()
  
  def genSIPVersionNotSupported(self, request):
    regRequest = "SIP/2.0 505 SIP Version Not Supported\r\n"
    regRequest += "Via: SIP/2.0/UDP "+request.headers['Via']['address'][0]+":"+request.headers['Via']['address'][1]+";branch="+request.headers['Via']['branch']+"\r\n"
    regRequest += "From: "+request.headers['From']['raw']+";tag="+request.headers['From']['tag']+"\r\n"
    regRequest += "To: "+request.headers['To']['raw']+";tag="+self.tag+"\r\n"
    regRequest += "Call-ID: "+request.headers['Call-ID']+"\r\n"
    regRequest += "CSeq: "+request.headers['CSeq']['check']+" "+request.headers['CSeq']['method']+"\r\n"
    regRequest += "Contact: "+request.headers['Contact']+"\r\n" #TODO: Add Supported
    regRequest += "User-Agent: pyVoIP """+pyVoIP.__version__+"\r\n"
    regRequest += "Warning: 399 GS \"Unable to accept call\"\r\n"
    regRequest += "Allow: "+(", ".join(pyVoIP.SIPCompatibleMethods))+"\r\n"
    regRequest += "Content-Length: 0\r\n\r\n"
  
  def genAuthorization(self, request):
    HA1 = hashlib.md5(self.username.encode('utf8')+b':'+request.authentication['realm'].encode('utf8')+b':'+self.password.encode('utf8')).hexdigest().encode('utf8')
    HA2 = hashlib.md5(b'REGISTER:sip:'+self.server.encode('utf8')+b';transport=UDP').hexdigest().encode('utf8')
    nonce = request.authentication['nonce'].encode('utf8')
    response = hashlib.md5(HA1+b':'+nonce+b':'+HA2).hexdigest().encode('utf8')
    
    return response
  
  def genRegister(self, request):
    response = self.genAuthorization(request)
    nonce = request.authentication['nonce']
    
    regRequest = "REGISTER sip:"+self.server
    regRequest += " SIP/2.0\r\nVia: SIP/2.0/UDP "+self.myIP+":"+str(self.myPort)
    regRequest += "\r\nMax-Forwards: 70\r\nContact: <sip:"
    regRequest += self.username+"@"+self.myIP+":"+str(self.myPort)
    regRequest += ";transport=UDP>\r\nTo: <sip:"""+self.username+"@"
    regRequest += self.server+";transport=UDP>\r\nFrom: <sip:"+self.username
    regRequest += "@192.168.0.102;transport=UDP>;tag="+self.tag
    regRequest += "\r\nCall-ID: "+request.headers['Call-ID']
    regRequest += "\r\nCSeq: "+str(self.registerCounter.next())+" REGISTER"
    regRequest +="\r\nExpires: 300\r\nAllow: "+(", ".join(pyVoIP.SIPCompatibleMethods))+"\r\nUser-Agent: pyVoIP """+pyVoIP.__version__+"\r\n"
    regRequest += 'Authorization: Digest username="'+self.username
    regRequest += '",realm="asterisk",nonce="'+nonce
    regRequest += '",uri="sip:'+self.server
    regRequest += ';transport=UDP",response="'+str(response, 'utf8')
    regRequest += '",algorithm=MD5\r\n'+"Allow-Events: presence, kpml, talk\r\nContent-Length: 0\r\n\r\n"
    
    return regRequest
    
  def genBusy(self, request):
    regRequest = "SIP/2.0 486 Busy Here\r\n"
    regRequest += "Via: SIP/2.0/UDP "+request.headers['Via']['address'][0]+":"+request.headers['Via']['address'][1]+";branch="+request.headers['Via']['branch']+"\r\n"
    regRequest += "From: "+request.headers['From']['raw']+";tag="+request.headers['From']['tag']+"\r\n"
    regRequest += "To: "+request.headers['To']['raw']+";tag="+self.tag+"\r\n"
    regRequest += "Call-ID: "+request.headers['Call-ID']+"\r\n"
    regRequest += "CSeq: "+request.headers['CSeq']['check']+" "+request.headers['CSeq']['method']+"\r\n"
    regRequest += "Contact: "+request.headers['Contact']+"\r\n" #TODO: Add Supported
    regRequest += "User-Agent: pyVoIP """+pyVoIP.__version__+"\r\n"
    regRequest += "Warning: 399 GS \"Unable to accept call\"\r\n"
    regRequest += "Allow: "+(", ".join(pyVoIP.SIPCompatibleMethods))+"\r\n"
    regRequest += "Content-Length: 0\r\n\r\n"
    
    return regRequest
  
  def genRinging(self, request):
    regRequest = "SIP/2.0 180 Ringing\r\n"
    regRequest += "Via: SIP/2.0/UDP "+request.headers['Via']['address'][0]+":"+request.headers['Via']['address'][1]+";branch="+request.headers['Via']['branch']+"\r\n"
    regRequest += "From: "+request.headers['From']['raw']+";tag="+request.headers['From']['tag']+"\r\n"
    regRequest += "To: "+request.headers['To']['raw']+";tag="+self.tag+"\r\n"
    regRequest += "Call-ID: "+request.headers['Call-ID']+"\r\n"
    regRequest += "CSeq: "+request.headers['CSeq']['check']+" "+request.headers['CSeq']['method']+"\r\n"
    regRequest += "Contact: "+request.headers['Contact']+"\r\n" #TODO: Add Supported
    regRequest += "User-Agent: pyVoIP """+pyVoIP.__version__+"\r\n"
    regRequest += "Allow: "+(", ".join(pyVoIP.SIPCompatibleMethods))+"\r\n"
    regRequest += "Content-Length: 0\r\n\r\n"
    
    return regRequest
  
  def genAnswer(self, request, sess_id, ms, sendtype):
    #Generate body first for content length
    body = "v=0\r\n"
    body += "o=pyVoIP "+sess_id+" "+sess_id+" IN IP4 "+self.myIP+"\r\n" #TODO: Check IPv4/IPv6
    body += "s=pyVoIP """+pyVoIP.__version__+"\r\n"
    body += "c=IN IP4 "+self.myIP+"\r\n" #TODO: Check IPv4/IPv6
    body += "t=0 0\r\n"
    for x in ms: 
      body += "m=audio "+str(x)+" RTP/AVP" #TODO: Check AVP mode from request
      for m in ms[x]:
        body += " "+str(m)
    body += "\r\n" #m=audio <port> RTP/AVP <codecs>\r\n
    for x in ms:
      for m in ms[x]:
        body += "a=rtpmap:"+str(m)+" "+str(ms[x][m])+"/"+str(ms[x][m].rate)+"\r\n"
        if str(ms[x][m]) == "telephone-event":
          body += "a=fmtp:"+str(m)+" 0-15\r\n"
    body += "a=ptime:20\r\n"
    body += "a=maxptime:150\r\n"
    body += "a="+str(sendtype)+"\r\n"
    
    regRequest = "SIP/2.0 200 OK\r\n"
    regRequest += "Via: SIP/2.0/UDP "+request.headers['Via']['address'][0]+":"+request.headers['Via']['address'][1]+";branch="+request.headers['Via']['branch']+"\r\n"
    regRequest += "From: "+request.headers['From']['raw']+";tag="+request.headers['From']['tag']+"\r\n"
    regRequest += "To: "+request.headers['To']['raw']+";tag="+self.tag+"\r\n"
    regRequest += "Call-ID: "+request.headers['Call-ID']+"\r\n"
    regRequest += "CSeq: "+request.headers['CSeq']['check']+" "+request.headers['CSeq']['method']+"\r\n"
    regRequest += "Contact: <sip:"+self.username+"@"+self.myIP+":"+str(self.myPort)+">\r\n" #TODO: Add Supported
    regRequest += "User-Agent: pyVoIP """+pyVoIP.__version__+"\r\n"
    regRequest += "Allow: "+(", ".join(pyVoIP.SIPCompatibleMethods))+"\r\n"
    regRequest += "Content-Type: application/sdp\r\n"
    regRequest += "Content-Length: "+str(len(body))+"\r\n\r\n"
    regRequest += body
    
    return regRequest
  
  def genBye(self, request):
    byeRequest = "BYE "+request.headers['Contact'].strip('<').strip('>')+" SIP/2.0\r\n"
    byeRequest += "Via: SIP/2.0/UDP "+self.myIP+":"+str(self.myPort)+";branch="+request.headers['Via']['branch']+"\r\n"
    byeRequest += "To: "+request.headers['From']['raw']+";tag="+request.headers['From']['tag']+"\r\n"
    byeRequest += "From: "+request.headers['To']['raw']+";tag="+self.tag+"\r\n"
    byeRequest += "Call-ID: "+request.headers['Call-ID']+"\r\n"
    byeRequest += "CSeq: "+str(self.byeCounter.next())+" BYE\r\n"
    byeRequest += "Contact: <sip:"+self.username+"@"+self.myIP+":"+str(self.myPort)+">\r\n"
    byeRequest += "User-Agent: pyVoIP """+pyVoIP.__version__+"\r\n"
    byeRequest += "Allow: "+(", ".join(pyVoIP.SIPCompatibleMethods))+"\r\n"
    byeRequest += "Content-Length: 0\r\n\r\n"
    
    return byeRequest
  
  def bye(self, request):
    message = self.genBye(request)
    self.out.sendto(message.encode('utf8'), (self.server, self.port))

  def deregister(self):
    self.recvLock.acquire()
    fake = SIPMessage(b'SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP 192.168.0.64:5060;received=192.168.0.64\r\nFrom: <sip:5555555@192.168.0.102;transport=UDP>;tag=b4dbea69\r\nTo: <sip:5555555@192.168.0.102;transport=UDP>;tag=as6845844a\r\nCall-ID: '+self.genCallID().encode('utf8')+b'\r\nCSeq: 25273 REGISTER\r\nServer: Asterisk PBX 16.2.1~dfsg-1+deb10u1\r\nAllow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE\r\nSupported: replaces, timer\r\nWWW-Authenticate: Digest algorithm=MD5, realm="asterisk", nonce="7140386d"\r\nContent-Length: 0\r\n\r\n')
    
    regRequest = self.genRegister(fake).replace('Expires: 300', 'Expires: 0')
    
    self.out.sendto(regRequest.encode('utf8'), (self.server, self.port))
    
    response = SIPMessage(self.s.recv(8192))
    
    
    while response.status != SIPStatus(401):
      if response.status == SIPStatus(500):
        self.recvLock.release()
        time.sleep(5)
        return self.deregister()
      response = SIPMessage(self.s.recv(8192))
    
    regRequest = self.genRegister(response).replace('Expires: 300', 'Expires: 0')
    
    self.out.sendto(regRequest.encode('utf8'), (self.server, self.port))
    
    response = SIPMessage(self.s.recv(8192))
    self.recvLock.release()
    if response.status==SIPStatus.OK:
      return True
    self.recvLock.release()
    
  def register(self):
    self.recvLock.acquire()
    fake = SIPMessage(b'SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP 192.168.0.64:5060;received=192.168.0.64\r\nFrom: <sip:5555555@192.168.0.102;transport=UDP>;tag=b4dbea69\r\nTo: <sip:5555555@192.168.0.102;transport=UDP>;tag=as6845844a\r\nCall-ID: '+self.genCallID().encode('utf8')+b'\r\nCSeq: 25273 REGISTER\r\nServer: Asterisk PBX 16.2.1~dfsg-1+deb10u1\r\nAllow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE\r\nSupported: replaces, timer\r\nWWW-Authenticate: Digest algorithm=MD5, realm="asterisk", nonce="7140386d"\r\nContent-Length: 0\r\n\r\n')
    
    regRequest = self.genRegister(fake)
    
    
    self.out.sendto(regRequest.encode('utf8'), (self.server, self.port))
    
    response = SIPMessage(self.s.recv(8192))
    print(response.summary())
    if response.status != SIPStatus(401):
      if response.status == SIPStatus(500):
        self.recvLock.release()
        time.sleep(5)
        return self.register()
    
    regRequest = self.genRegister(response)
    
    self.out.sendto(regRequest.encode('utf8'), (self.server, self.port))
    
    response = SIPMessage(self.s.recv(8192))
    self.recvLock.release()
    if response.status==SIPStatus.OK:
      if self.NSD:
        self.registerThread=Timer(295, self.register)
        self.registerThread.start()
      return True
    else:
      raise InvalidAccountInfoError("Invalid Username or Password for SIP server "+self.server+':'+str(self.myPort))
    
    
  