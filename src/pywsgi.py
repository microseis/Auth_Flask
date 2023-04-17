from gevent import monkey

monkey.patch_all(thread=True)

from gevent.pywsgi import WSGIServer

# from geventwebsocket.handler import WebSocketHandler
from main import app
from src.core.logger import logger

http_server = WSGIServer(("0.0.0.0", 8000), app)
logger.info("Starting gevent WSGI Server")
http_server.serve_forever()
