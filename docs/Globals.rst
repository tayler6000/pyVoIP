Global Variables
########

There are a few global variables that may assist you if you're having problems with the library.

pyVoIP.\ **DEBUG** = False
    If set to true, pyVoIP will print debug messages that may be useful if you need to open a GitHub issue.  Otherwise, does nothing.

pyVoIP.\ **TRANSMIT_DELAY_REDUCTION** = 0.0
    The higher this variable is, the more often RTP packets are sent.  This *should* only ever need to be 0.0.  However, when testing on Windows, there has sometimes been jittering, setting this to 0.75 fixed this in testing, but you may need to tinker with this number on a per-system basis.
