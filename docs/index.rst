.. pyVoIP documentation master file, created by
   sphinx-quickstart on Fri Jul 17 19:40:26 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to pyVoIP's documentation!
==================================

PyVoIP is a pure python VoIP/SIP/RTP library.  Currently, it supports PCMA, PCMU, and telephone-event.

Please note this is is still in development and can only originate calls with PCMU.  In future, it will be able to initiate calls in PCMA as well.

This library does not depend on a sound library, i.e. you can use any sound library that can handle linear sound data such as pyaudio or even wave.  Keep in mind PCMU only supports 8000Hz, 1 channel, 8 bit audio.

In this documentation we will use the following terms:

.. glossary::
  
  client
    For the purposes of this documentation, the term *client* will be defined as the person calling this library.
  
  user
    For the purposes of this documentation, the term *user* will be defined as the programmer, i.e. the 'server-side' if using the `Client-Server model <https://en.wikipedia.org/wiki/Client%E2%80%93server_model>`_.

.. toctree::
   :maxdepth: 3
   :caption: Contents:

   Examples
   Globals
   VoIP
   Credentials
   SIP
   RTP
   Networking
   Types
