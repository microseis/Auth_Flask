from gevent import monkey

monkey.patch_all(thread=True)

from gevent.pywsgi import WSGIServer

from core.logger import logger
# from geventwebsocket.handler import WebSocketHandler
from main import create_app

app = create_app()

http_server = WSGIServer(("0.0.0.0", 8000), app)
logger.info("Starting gevent WSGI Server")
http_server.serve_forever()
