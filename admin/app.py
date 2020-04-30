from flask import Flask
from flask_login import LoginManager
from flask_migrate import Migrate

from admin.utils import Database

import os
import configparser

path = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(path, 'config', 'db.conf')

config = configparser.ConfigParser()
config.read(config_path)

database_uri = 'mysql+pymysql://{user}:{password}@{host}:{port}/{database}'\
    .format(**config['MYSQL'])

app = Flask(__name__)
app.config['SECRET_KEY'] = config.get('SECRET', 'key')
app.config['SQLALCHEMY_DATABASE_URI'] = database_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

# init database singleton
db = Database()
db.get_instance().init_app(app)
migrate = Migrate(app, db.get_instance())

from admin.bp_template import chart
from admin.bp_template import login
from admin.bp_template import recommendation
from admin.bp_template import index

app.register_blueprint(chart)
app.register_blueprint(login)
app.register_blueprint(recommendation)
app.register_blueprint(index)

from admin.bp_rest import auth
from admin.bp_rest import predictions
app.register_blueprint(auth)
app.register_blueprint(predictions, url_prefix='/predictions')


login_manager = LoginManager()
login_manager.login_view = 'login.render_login'
login_manager.init_app(app)

from admin.models import User


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


if __name__ == '__main__':
    app.run()
