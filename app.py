import os
from flask import Flask
from dotenv import load_dotenv
from core.extensions import db, socketio
from core.celery_app import celery
from sqlalchemy.engine.url import make_url

# Import models so they are registered with SQLAlchemy
from core import models

load_dotenv()


def ensure_sqlite_directory(uri, root_path):
    """Ensure the directory for the SQLite database exists."""
    if "sqlite" not in uri:
        return

    try:
        url = make_url(uri)
    except Exception:
        return

    db_path = url.database

    if db_path is None or db_path == ':memory:':
        return

    if not os.path.isabs(db_path):
        db_path = os.path.join(root_path, db_path)

    os.makedirs(os.path.dirname(db_path), exist_ok=True)


def create_app():
    app = Flask(__name__, template_folder="ui/web/templates", static_folder="ui/web/static")
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")

    basedir = os.path.abspath(os.path.dirname(__file__))
    default_db = "sqlite:///" + os.path.join(basedir, "data", "redops3.db")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", default_db)
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    socketio.init_app(app)

    with app.app_context():
        from ui.web.views.main import main_bp
        app.register_blueprint(main_bp)

    return app


if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        ensure_sqlite_directory(app.config["SQLALCHEMY_DATABASE_URI"], app.root_path)

        os.makedirs(os.path.join(app.root_path, "data", "results"), exist_ok=True)
        os.makedirs(os.path.join(app.root_path, "data", "reports"), exist_ok=True)
        os.makedirs(os.path.join(app.root_path, "data", "wordlists"), exist_ok=True)

        db.create_all()
        
        # Enable WAL mode for SQLite to prevent "database is locked" errors
        if "sqlite" in app.config["SQLALCHEMY_DATABASE_URI"]:
            with db.engine.connect() as conn:
                conn.execute(db.text("PRAGMA journal_mode=WAL;"))
                
        print("Database initialized (WAL mode enabled).")

    socketio.run(app, debug=True, host="0.0.0.0", port=5001, allow_unsafe_werkzeug=True)
