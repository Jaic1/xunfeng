import sys
from datetime import timedelta
from flask import Flask
from flask_wtf.csrf import CSRFProtect
from config import ProductionConfig
from views.lib import Conn
import os

reload(sys)
sys.setdefaultencoding('utf-8')
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(64)
app.config.from_object(ProductionConfig)
csrf = CSRFProtect()
csrf.init_app(app)
Mongo = Conn.MongoDB(app.config.get('DB'), app.config.get('PORT'), app.config.get('DBNAME'),
                     app.config.get('DBUSERNAME'), app.config.get('DBPASSWORD'))
app.permanent_session_lifetime = timedelta(hours=6)
page_size = 60
sys.path.append(sys.path[0] + '/vulscan/vuldb/')
file_path = os.path.split(os.path.realpath(__file__))[0] + '/../vulscan/vuldb/'
