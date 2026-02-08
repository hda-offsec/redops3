import os
from flask import Flask
from dotenv import load_dotenv
from core.extensions import db, socketio, login_manager
from core.celery_app import celery

# Import models so they are registered with SQLAlchemy
from core import models
from core.models import User

load_dotenv()


def create_app():
    app = Flask(__name__, template_folder="ui/web/templates", static_folder="ui/web/static")
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")

    basedir = os.path.abspath(os.path.dirname(__file__))
    default_db = "sqlite:///" + os.path.join(basedir, "data", "redops3.db")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", default_db)
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    socketio.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    with app.app_context():
        from ui.web.views.main import main_bp
        from ui.web.views.auth import auth_bp
        app.register_blueprint(main_bp)
        app.register_blueprint(auth_bp)

    return app


if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        if "sqlite" in app.config["SQLALCHEMY_DATABASE_URI"]:
            uri = app.config["SQLALCHEMY_DATABASE_URI"]
            if uri.startswith("sqlite:////"):
                db_path = uri.replace("sqlite:////", "")
            elif uri.startswith("sqlite:///"):
                db_path = uri.replace("sqlite:///", "")
            else:
                db_path = uri.replace("sqlite://", "")
            if not os.path.isabs(db_path):
                db_path = os.path.join(app.root_path, db_path)
            os.makedirs(os.path.dirname(db_path), exist_ok=True)

        os.makedirs(os.path.join(app.root_path, "data", "results"), exist_ok=True)
        os.makedirs(os.path.join(app.root_path, "data", "reports"), exist_ok=True)
        os.makedirs(os.path.join(app.root_path, "data", "wordlists"), exist_ok=True)

        db.create_all()
        
        # Enable WAL mode for SQLite to prevent "database is locked" errors
        if "sqlite" in app.config["SQLALCHEMY_DATABASE_URI"]:
            with db.engine.connect() as conn:
                conn.execute(db.text("PRAGMA journal_mode=WAL;"))
                
        print("Database initialized (WAL mode enabled).")

        # Create default admin user if not exists
        if not User.query.filter_by(username="admin").first():
            user = User(username="admin")
            user.set_password("redops3")
            db.session.add(user)
            db.session.commit()
            print("Default admin user created (admin/redops3)")

    socketio.run(app, debug=True, host="0.0.0.0", port=5001, allow_unsafe_werkzeug=True)
