from gevent import monkey

monkey.patch_all(thread=True)

import logging

from gevent.pywsgi import WSGIServer

# from geventwebsocket.handler import WebSocketHandler
from routes import *

logging.basicConfig(level=logging.DEBUG)

http_server = WSGIServer(("0.0.0.0", 8000), app)
logging.info("Starting gevent WSGI Server")
http_server.serve_forever()
