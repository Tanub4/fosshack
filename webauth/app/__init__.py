from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
bcrypt = Bcrypt()

def create_app():
    app = Flask(__name__)

    # Secret Key for Forms
    app.config['SECRET_KEY'] = 'supersecretkey'
    
    # Database Configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)

    # Redirect to login page if user isn't authenticated
    login_manager.login_view = "auth.login"

    # Import Blueprints
    from app.routes import auth_bp
    app.register_blueprint(auth_bp)

    return app
