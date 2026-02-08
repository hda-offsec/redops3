from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_login import LoginManager
import os

db = SQLAlchemy()
redis_url = os.getenv('REDIS_URL', 'redis://127.0.0.1:6379/0')
socketio = SocketIO(message_queue=redis_url, async_mode="threading")
login_manager = LoginManager()
