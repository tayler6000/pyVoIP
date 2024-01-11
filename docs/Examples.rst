Examples
########

Here we will go over a few basic phone setups.

Setup
*****

PyVoIP uses a :ref:`VoIPPhone` class to receive and initiate phone calls. The settings for our phone are passed via the :ref:`VoIPPhoneParameter` dataclass. When a call is received, a new instance of a :ref:`VoIPCall` is initialized. You can overwrite this class in initialization of VoIPPhone.

In this example, we are importing :ref:`CredentialsManager`, :ref:`VoIPPhone`, :ref:`VoIPPhoneParameter`, :ref:`VoIPCall`, and :ref:`InvalidStateError<InvalidStateError>`. :ref:`CredentialsManager` stores and retreives passwords for authentication with registrars. :ref:`VoIPPhone` is the main class for our `softphone <https://en.wikipedia.org/wiki/Softphone>`_. :ref:`VoIPPhoneParameter` is the settings for our :ref:`VoIPPhone`. :ref:`VoIPCall` will be used to create our custom answering class. An :ref:`InvalidStateError<InvalidStateError>` is thrown when you try to perform an impossible command. For example, denying the call when the phone is already answered, answering when it's already answered, etc.

The following will create a phone that answers and automatically hangs up:

.. code-block:: python
   
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
    
Announcement Board
******************

Let's say you want to make a phone that when you call it, it plays an announcement message, then hangs up. We can accomplish this with the builtin libraries `wave <https://docs.python.org/3/library/wave.html>`_, `audioop <https://docs.python.org/3/library/audioop.html>`_, `time <https://docs.python.org/3/library/time.html>`_, and by importing :ref:`CallState<callstate>`.

.. code-block:: python

  from pyVoIP.credentials import CredentialsManager
  from pyVoIP.VoIP.call import VoIPCall
  from pyVoIP.VoIP.error import InvalidStateError
  from pyVoIP.VoIP.phone import VoIPPhone, VoIPPhoneParamter
  import time
  import wave

  class Call(VoIPCall):

      def ringing(self, invite_request):
          try:
              f = wave.open('announcment.wav', 'rb')
              frames = f.getnframes()
              data = f.readframes(frames)
              f.close()
          
              call.answer()
              call.write_audio(data)  # This writes the audio data to the transmit buffer, this must be bytes.
          
              stop = time.time() + (frames / 8000)  # frames/8000 is the length of the audio in seconds. 8000 is the hertz of PCMU.
          
              while time.time() <= stop and call.state == CallState.ANSWERED:
                  time.sleep(0.1)
              call.hangup()
          except InvalidStateError:
              pass
          except:
              call.hangup()

  if __name__ == "__main__":
      cm = CredentialsManager()
      cm.add(<SIP server username>, <SIP server password>)
      params = VoIPPhoneParamter(<SIP server IP>, <SIP server port>, <SIP server user>, cm, bind_ip=<Your computer's local IP>, call_class=Call)
      phone = VoIPPhone(params)
      phone.start()
      input('Press enter to disable the phone')
      phone.stop()

Something important to note is our wait function. We are currently using:

.. code-block:: python

  stop = time.time() + (frames / 8000)  # The number of frames/8000 is the length of the audio in seconds.
      
  while time.time() <= stop and call.state == CallState.ANSWERED:
      time.sleep(0.1)

This could be replaced with ``time.sleep(frames / 8000)``. However, doing so will not cause the thread to automatically close if the user hangs up, or if ``VoIPPhone().stop()`` is called. Using the while loop method will fix this issue. The ``time.sleep(0.1)`` inside the while loop is also important. Supplementing ``time.sleep(0.1)`` for ``pass`` will cause your CPU to ramp up while running the loop, making the RTP (audio being sent out and received) lag. This can make the voice audibly slow or choppy.

    **Important Note:** *Audio must be 8 bit, 8000Hz, and Mono/1 channel. You can accomplish this in a free program called* `Audacity <https://www.audacityteam.org/>`_. *To make an audio recording Mono, go to Tracks > Mix > Mix Stereo Down to Mono. To make an audio recording 8000 Hz, go to Tracks > Resample... and select 8000, then ensure that your 'Project Rate' in the bottom left is also set to 8000. To make an audio recording 8 bit, go to File > Export > Export as WAV, then change 'Save as type:' to 'Other uncompressed files', then set 'Header:' to 'WAV (Microsoft)', then set the 'Encoding:' to 'Unsigned 8-bit PCM'*

IVR/Phone Menus
****************

We can use the following code to create `IVR Menus <https://en.wikipedia.org/wiki/Interactive_voice_response>`_. Currently, we cannot make 'breaking' IVR menus. Breaking IVR menus in this context means, a user selecting an option mid-prompt will cancel the prompt, and start the next action. Support for breaking IVR's will be made in the future. For now, here is the code for a non-breaking IVR:

.. code-block:: python

  from pyVoIP.credentials import CredentialsManager
  from pyVoIP.VoIP.call import VoIPCall
  from pyVoIP.VoIP.error import InvalidStateError
  from pyVoIP.VoIP.phone import VoIPPhone, VoIPPhoneParamter
  import time
  import wave
  
  class Call(VoIPCall):

      def ringing(self, invite_request):
          try:
              f = wave.open('prompt.wav', 'rb')
              frames = f.getnframes()
              data = f.readframes(frames)
              f.close()
          
              call.answer()
              call.write_audio(data)
          
              while call.state == CallState.ANSWERED:
                  dtmf = call.get_dtmf()
                  if dtmf == "1":
                      if call.transfer("sales")  # Transfer to same registrar
                        return
                  elif dtmf == "2":
                      if call.transfer(uri="<100@different_regisrar.com>")
                        return
                  time.sleep(0.1)
          except InvalidStateError:
              pass
          except:
              call.hangup()

  if __name__ == '__main__':
      cm = CredentialsManager()
      cm.add(<SIP server username>, <SIP server password>)
      params = VoIPPhoneParamter(<SIP server IP>, <SIP server port>, <SIP server user>, cm, bind_ip=<Your computer's local IP>, call_class=Call)
      phone = VoIPPhone(params)
      phone.start()
      input('Press enter to disable the phone')
      phone.stop()

Please note that ``get_dtmf()`` is actually ``get_dtmf(length=1)``, and as it is technically an ``io.StringBuffer()``, it will return ``""`` instead of ``None``. This may be important if you wanted an 'if anything else, do that' clause. Lastly, VoIPCall stores all DTMF keys pressed since the call was established; meaning, users can press any key they want before the prompt even finishes, or may press a wrong key before the prompt even starts.

Call State Handling
*******************

We can use the following code to handle various states for calls:

.. code-block:: python

  from pyVoIP.credentials import CredentialsManager
  from pyVoIP.VoIP.call import VoIPCall
  from pyVoIP.VoIP.error import InvalidStateError
  from pyVoIP.VoIP.phone import VoIPPhone, VoIPPhoneParamter
  import time
  import wave

  class Call(VoIPCall):

      def progress(self, request):
          print('Progress')
          super().progress(request)

      def busy(self, request):
          print('Call ended - callee is busy')
          super().busy(request)

      def answered(self, request):
          print('Answered')
          super().answered()

      def bye(self):
          print('Bye')
          super().bye()

  if __name__ == '__main__':
      cm = CredentialsManager()
      cm.add(<SIP server username>, <SIP server password>)
      params = VoIPPhoneParamter(<SIP server IP>, <SIP server port>, <SIP server user>, cm, bind_ip=<Your computer's local IP>, call_class=Call)
      phone = VoIPPhone(params)
      phone.start()
      phone.call(<Phone Number>)
      input('Press enter to disable the phone\n')
      phone.stop()
