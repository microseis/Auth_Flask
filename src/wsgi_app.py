from gevent import monkey

monkey.patch_all()
from app import app
from routes import *
