# pyVoIP
PyVoIP is a pure python VoIP/SIP/RTP library. Currently, it supports PCMA, PCMU, and telephone-event.

This library does not depend on a sound library, i.e. you can use any sound library that can handle linear sound data such as pyaudio or even wave. Keep in mind PCMU/PCMA only supports 8000Hz, 1 channel, 8 bit audio.

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
from pyVoIP.credentials import CredentialsManager
from pyVoIP.VoIP.call import VoIPCall
from pyVoIP.VoIP.error import InvalidStateError
from pyVoIP.VoIP.phone import VoIPPhone, VoIPPhoneParamter

class Call(VoIPCall):

  def ringing(self, invite_request):
      try:
          self.answer()
          self.hangup()
      except InvalidStateError:
          pass

if __name__ == "__main__":
  cm = CredentialsManager()
  cm.add(<SIP server username>, <SIP server password>)
  params = VoIPPhoneParamter(<SIP server IP>, <SIP server port>, <SIP server user>, cm, bind_ip=<Your computers local IP>, call_class=Call)
  phone = VoIPPhone(params)
  phone.start()
  input('Press enter to disable the phone')
  phone.stop()
```

### Sponsors

- [Nabu Casa](https://www.nabucasa.com/)
- [Home Assistant](https://www.home-assistant.io/)
