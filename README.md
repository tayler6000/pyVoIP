# pyVoIP
PyVoIP is a pure python VoIP/SIP/RTP library.  Currently, it supports PCMA, PCMU, and telephone-event.

This library does not depend on a sound library, i.e. you can use any sound library that can handle linear sound data i.e. pyaudio or even wave.  Keep in mind PCMU/PCMA only supports 8000Hz, 1 channel, 8 bit audio.

## Getting Started
Simply run `pip install pyVoIP`, or if installing from source:

```bash
git clone https://github.com/tayler6000/pyVoIP.git
cd pyVoIP
pip install .
```

Don't forget to check out [the documentation](https://pyvoip.readthedocs.io/)!

### Basic Example
This basic code will simple make a phone that will automatically answer then hang up.

```python
from pyVoIP.VoIP import VoIPPhone, InvalidStateError

def answer(call): # This will be your callback function for when you receive a phone call.
    try:
      call.answer()
      call.hangup()
    except InvalidStateError:
      pass
  
if __name__ == "__main__":
    phone=VoIPPhone(<SIP Server IP>, <SIP Server Port>, <SIP Server Username>, <SIP Server Password>, callCallback=answer, myIP=<Your computer's local IP>, sipPort=<Port to use for SIP (int, default 5060)>, rtpPortLow=<low end of the RTP Port Range>, rtpPortHigh=<high end of the RTP Port Range>)
    phone.start()
    input('Press enter to disable the phone')
    phone.stop()
```

### Sponsors

- [Nabu Casa](https://www.nabucasa.com/)
- [Home Assistant](https://www.home-assistant.io/)
