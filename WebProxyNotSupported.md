## Explanation ##

The python urllib2 module (which is what posthandler.py is built on) does not support https requests through a web proxy.

Python docs contains a recipe for implementing a workaround but this has not been incorporated into the lgvtotal.py/posthandler.py code.

See http://docs.python.org/howto/urllib2.html#id15 for more information.