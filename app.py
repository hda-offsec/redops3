import os
import sys
# Ensure project root is in path
_root = os.path.dirname(os.path.abspath(__file__))
if _root not in sys.path:
    sys.path.insert(0, _root)

from flask import Flask
from dotenv import load_dotenv
from sqlalchemy.engine.url import make_url
from core.extensions import db, socketio, login_manager
from core.celery_app import celery
import urllib3

# Suppress insecure request warnings for the local security tool
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import models and tasks so they are registered
from core import models
from core.models import User
import core.tasks
import tasks.nmap_tasks

load_dotenv()


def run_runtime_migrations(app):
    """Best-effort SQLite migrations for backward-compatible schema extensions."""
    if "sqlite" not in app.config.get("SQLALCHEMY_DATABASE_URI", ""):
        return
    try:
        with app.app_context():
            with db.engine.connect() as conn:
                result = conn.execute(db.text("PRAGMA table_info(findings);")).fetchall()
                columns = {row[1] for row in result}
                alter_map = {
                    "module": "ALTER TABLE findings ADD COLUMN module TEXT;",
                    "category": "ALTER TABLE findings ADD COLUMN category TEXT;",
                    "target": "ALTER TABLE findings ADD COLUMN target TEXT;",
                    "endpoint": "ALTER TABLE findings ADD COLUMN endpoint TEXT;",
                    "parameter": "ALTER TABLE findings ADD COLUMN parameter TEXT;",
                    "payload": "ALTER TABLE findings ADD COLUMN payload TEXT;",
                    "evidence": "ALTER TABLE findings ADD COLUMN evidence TEXT;",
                    "reproduction": "ALTER TABLE findings ADD COLUMN reproduction TEXT;",
                    "raw_output": "ALTER TABLE findings ADD COLUMN raw_output TEXT;",
                    "metadata_json": "ALTER TABLE findings ADD COLUMN metadata_json JSON;",
                    "remediation": "ALTER TABLE findings ADD COLUMN remediation TEXT;",
                    "risk_scorecard": "ALTER TABLE findings ADD COLUMN risk_scorecard JSON;",
                    "chain_metadata": "ALTER TABLE findings ADD COLUMN chain_metadata JSON;",
                }
                for col, ddl in alter_map.items():
                    if col not in columns:
                        conn.execute(db.text(ddl))

                signal_cols = {row[1] for row in conn.execute(db.text("PRAGMA table_info(signals);")).fetchall()}
                signal_alter = {
                    "module": "ALTER TABLE signals ADD COLUMN module TEXT;",
                    "status_code": "ALTER TABLE signals ADD COLUMN status_code INTEGER;",
                    "response_headers": "ALTER TABLE signals ADD COLUMN response_headers JSON;",
                    "response_evidence": "ALTER TABLE signals ADD COLUMN response_evidence TEXT;",
                }
                for col, ddl in signal_alter.items():
                    if col not in signal_cols:
                        conn.execute(db.text(ddl))

                mission_cols = {row[1] for row in conn.execute(db.text("PRAGMA table_info(missions);")).fetchall()}
                mission_alter = {
                    "objectives": "ALTER TABLE missions ADD COLUMN objectives JSON;",
                    "scope_summary": "ALTER TABLE missions ADD COLUMN scope_summary TEXT;",
                    "priority": "ALTER TABLE missions ADD COLUMN priority TEXT DEFAULT 'medium';",
                    "tags": "ALTER TABLE missions ADD COLUMN tags JSON;",
                    "updated_at": "ALTER TABLE missions ADD COLUMN updated_at DATETIME;",
                }
                for col, ddl in mission_alter.items():
                    if col not in mission_cols:
                        conn.execute(db.text(ddl))

                conn.execute(db.text("CREATE TABLE IF NOT EXISTS assets (id INTEGER PRIMARY KEY, mission_id INTEGER NOT NULL REFERENCES missions(id), type TEXT NOT NULL DEFAULT 'domain', identifier TEXT NOT NULL, label TEXT, confidence TEXT NOT NULL DEFAULT 'medium', source TEXT, provenance JSON, tags JSON, created_at DATETIME);"))
                conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_assets_mission_id ON assets(mission_id);"))
                conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_assets_identifier ON assets(identifier);"))

                conn.execute(db.text("CREATE TABLE IF NOT EXISTS asset_target_links (id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id), target_id INTEGER NOT NULL REFERENCES targets(id), link_type TEXT NOT NULL DEFAULT 'observed', confidence TEXT NOT NULL DEFAULT 'medium', source TEXT, metadata JSON, created_at DATETIME, CONSTRAINT uq_asset_target_link UNIQUE (asset_id, target_id));"))
                conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_asset_target_links_asset_id ON asset_target_links(asset_id);"))
                conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_asset_target_links_target_id ON asset_target_links(target_id);"))
                conn.execute(db.text("CREATE TABLE IF NOT EXISTS operator_actions (id INTEGER PRIMARY KEY, mission_id INTEGER NOT NULL REFERENCES missions(id), action_key TEXT NOT NULL, related_asset_ids JSON, related_target_ids JSON, related_finding_ids JSON, related_signal_ids JSON, objective_type TEXT NOT NULL, action_type TEXT NOT NULL DEFAULT 'review', title TEXT NOT NULL, description TEXT, rationale TEXT, confidence FLOAT DEFAULT 0, attack_priority TEXT DEFAULT 'medium', estimated_value TEXT DEFAULT 'medium', estimated_complexity TEXT DEFAULT 'low', status TEXT NOT NULL DEFAULT 'suggested', blocker_summary JSON, required_conditions JSON, evidence_summary TEXT, metadata JSON, created_at DATETIME, updated_at DATETIME, CONSTRAINT uq_operator_action_mission_key UNIQUE (mission_id, action_key));"))
                conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_operator_actions_mission_id ON operator_actions(mission_id);"))
                conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_operator_actions_status ON operator_actions(status);"))

                conn.execute(db.text("CREATE TABLE IF NOT EXISTS replay_vault_entries (id INTEGER PRIMARY KEY, scan_id INTEGER REFERENCES scans(id), finding_id INTEGER REFERENCES findings(id), mission_id INTEGER REFERENCES missions(id), target_id INTEGER REFERENCES targets(id), source TEXT, method TEXT NOT NULL DEFAULT 'GET', url TEXT NOT NULL, endpoint TEXT, query_params JSON, request_headers JSON, request_cookies JSON, request_body_summary JSON, status_code INTEGER, response_headers JSON, response_body_summary JSON, content_type TEXT, redirect_chain JSON, identity_context JSON, provenance JSON, observed_at DATETIME, created_at DATETIME);"))
                conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_replay_vault_entries_scan_id ON replay_vault_entries(scan_id);"))
                conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_replay_vault_entries_finding_id ON replay_vault_entries(finding_id);"))
                conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_replay_vault_entries_mission_id ON replay_vault_entries(mission_id);"))
                conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_replay_vault_entries_target_id ON replay_vault_entries(target_id);"))
                conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_replay_vault_entries_observed_at ON replay_vault_entries(observed_at);"))

                conn.execute(db.text("CREATE TABLE IF NOT EXISTS auth_identity_maps (id INTEGER PRIMARY KEY, replay_id INTEGER REFERENCES replay_vault_entries(id), scan_id INTEGER REFERENCES scans(id), mission_id INTEGER REFERENCES missions(id), target_id INTEGER REFERENCES targets(id), route TEXT, route_auth_hints JSON, session_cookie_names JSON, bearer_token_present BOOLEAN NOT NULL DEFAULT 0, bearer_token_preview TEXT, jwt_like_token BOOLEAN NOT NULL DEFAULT 0, response_session_cookie_hint BOOLEAN NOT NULL DEFAULT 0, role_scope_claim_hints JSON, observation_only BOOLEAN NOT NULL DEFAULT 1, notes TEXT, source TEXT, created_at DATETIME);"))
                conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_auth_identity_maps_replay_id ON auth_identity_maps(replay_id);"))
                conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_auth_identity_maps_scan_id ON auth_identity_maps(scan_id);"))
                conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_auth_identity_maps_mission_id ON auth_identity_maps(mission_id);"))
                conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_auth_identity_maps_target_id ON auth_identity_maps(target_id);"))

                replay_cols = {row[1] for row in conn.execute(db.text("PRAGMA table_info(replay_vault_entries);")).fetchall()}
                if "graphql_summary" not in replay_cols:
                    conn.execute(db.text("ALTER TABLE replay_vault_entries ADD COLUMN graphql_summary JSON;"))

                conn.execute(db.text("CREATE TABLE IF NOT EXISTS operator_feedback (id INTEGER PRIMARY KEY, mission_id INTEGER NOT NULL REFERENCES missions(id), action_id INTEGER REFERENCES operator_actions(id), finding_id INTEGER REFERENCES findings(id), replay_id INTEGER REFERENCES replay_vault_entries(id), feedback_type TEXT NOT NULL, signal_family TEXT, subject_type TEXT, subject_key TEXT, sentiment INTEGER NOT NULL DEFAULT 0, notes TEXT, metadata JSON, created_at DATETIME);"))
                conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_operator_feedback_mission_id ON operator_feedback(mission_id);"))
                conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_operator_feedback_action_id ON operator_feedback(action_id);"))
                conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_operator_feedback_finding_id ON operator_feedback(finding_id);"))
                conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_operator_feedback_replay_id ON operator_feedback(replay_id);"))
                conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_operator_feedback_type ON operator_feedback(feedback_type);"))

                conn.execute(db.text("CREATE TABLE IF NOT EXISTS global_settings (id INTEGER PRIMARY KEY, key TEXT UNIQUE NOT NULL, value TEXT, description TEXT, category TEXT, updated_at DATETIME);"))
                conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_global_settings_key ON global_settings(key);"))
    except Exception as e:
        app.logger.warning(f"Runtime migration check failed: {e}")


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
    app.jinja_env.add_extension('jinja2.ext.do')
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")

    # Configure logging
    import logging
    from logging.handlers import RotatingFileHandler
    
    if not os.path.exists('data'):
        os.makedirs('data')
        
    file_handler = RotatingFileHandler('data/app.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('RedOps3 startup')

    basedir = os.path.abspath(os.path.dirname(__file__))
    default_db = "sqlite:///" + os.path.join(basedir, "data", "redops3.db")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", default_db)
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    socketio.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    app.config["LOGIN_DISABLED"] = True

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @login_manager.request_loader
    def request_loader(request):
        # Always return the admin user to bypass authentication
        return User.query.filter_by(username="admin").first()

    with app.app_context():
        db.create_all()
        run_runtime_migrations(app)
        from ui.web.views.main import main_bp
        from ui.web.views.auth import auth_bp
        import core.socket_events # Ensure socket handlers are registered
        app.register_blueprint(main_bp)
        app.register_blueprint(auth_bp)

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

        # Create default admin user if not exists
        if not User.query.filter_by(username="admin").first():
            user = User(username="admin")
            user.set_password("redops3")
            db.session.add(user)
            db.session.commit()
            print("Default admin user created (admin/redops3)")

        # --- MIGRATION CHECK ---
        # Ensure parent_scan_id exists (SQLite doesn't support easy ALTER via SQLAlchemy)
        if "sqlite" in app.config["SQLALCHEMY_DATABASE_URI"]:
            try:
                with db.engine.connect() as conn:
                    # Check if column exists
                    result = conn.execute(db.text("PRAGMA table_info(scans);")).fetchall()
                    columns = [row[1] for row in result]
                    if "parent_scan_id" not in columns:
                        print("Migrating database: Adding parent_scan_id to scans table...")
                        conn.execute(db.text("ALTER TABLE scans ADD COLUMN parent_scan_id INTEGER REFERENCES scans(id);"))
                        print("Migration successful.")
                    
                    if "task_id" not in columns:
                        print("Migrating database: Adding task_id to scans table...")
                        conn.execute(db.text("ALTER TABLE scans ADD COLUMN task_id TEXT;"))
                        print("Migration successful.")
                    
                    # Check Finding table
                    result = conn.execute(db.text("PRAGMA table_info(findings);")).fetchall()
                    columns = [row[1] for row in result]
                    if "confidence" not in columns:
                        print("Migrating database: Adding confidence, request, response, repro_command to findings table...")
                        conn.execute(db.text("ALTER TABLE findings ADD COLUMN confidence TEXT DEFAULT 'medium';"))
                        conn.execute(db.text("ALTER TABLE findings ADD COLUMN request TEXT;"))
                        conn.execute(db.text("ALTER TABLE findings ADD COLUMN response TEXT;"))
                        conn.execute(db.text("ALTER TABLE findings ADD COLUMN repro_command TEXT;"))
                        print("Migration successful.")
                    
                    if "id_stable" not in columns:
                        print("Migrating database: Adding id_stable to findings table...")
                        conn.execute(db.text("ALTER TABLE findings ADD COLUMN id_stable TEXT;"))
                        conn.execute(db.text("CREATE INDEX idx_findings_id_stable ON findings(id_stable);"))
                        print("Migration successful.")

                    # Signal table bootstrap
                    conn.execute(db.text("CREATE TABLE IF NOT EXISTS signals (id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, tool TEXT DEFAULT 'unknown', module TEXT, type TEXT DEFAULT 'generic', target TEXT, endpoint TEXT, parameter TEXT, payload TEXT, status_code INTEGER, response_headers JSON, response_evidence TEXT, raw_output TEXT, metadata JSON, timestamp DATETIME);"))
                    conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_signals_scan_id ON signals(scan_id);"))

                    signal_columns = [row[1] for row in conn.execute(db.text("PRAGMA table_info(signals);")).fetchall()]
                    required_signal_columns = {
                        "module": "ALTER TABLE signals ADD COLUMN module TEXT;",
                        "status_code": "ALTER TABLE signals ADD COLUMN status_code INTEGER;",
                        "response_headers": "ALTER TABLE signals ADD COLUMN response_headers JSON;",
                        "response_evidence": "ALTER TABLE signals ADD COLUMN response_evidence TEXT;",
                    }
                    for col_name, ddl in required_signal_columns.items():
                        if col_name not in signal_columns:
                            print(f"Migrating database: adding {col_name} to signals table...")
                            conn.execute(db.text(ddl))

                    # Ensure hardened finding columns exist
                    required_finding_columns = {
                        "signal_ids": "ALTER TABLE findings ADD COLUMN signal_ids JSON;",
                        "target": "ALTER TABLE findings ADD COLUMN target TEXT;",
                        "tool": "ALTER TABLE findings ADD COLUMN tool TEXT;",
                        "module": "ALTER TABLE findings ADD COLUMN module TEXT;",
                        "category": "ALTER TABLE findings ADD COLUMN category TEXT;",
                        "endpoint": "ALTER TABLE findings ADD COLUMN endpoint TEXT;",
                        "parameter": "ALTER TABLE findings ADD COLUMN parameter TEXT;",
                        "payload": "ALTER TABLE findings ADD COLUMN payload TEXT;",
                        "raw_output": "ALTER TABLE findings ADD COLUMN raw_output TEXT;",
                        "metadata": "ALTER TABLE findings ADD COLUMN metadata JSON;",
                        "evidence": "ALTER TABLE findings ADD COLUMN evidence TEXT;",
                        "reproduction": "ALTER TABLE findings ADD COLUMN reproduction TEXT;",
                        "remediation": "ALTER TABLE findings ADD COLUMN remediation TEXT;",
                        "risk_scorecard": "ALTER TABLE findings ADD COLUMN risk_scorecard JSON;"
                    }
                    result = conn.execute(db.text("PRAGMA table_info(findings);")).fetchall()
                    columns = [row[1] for row in result]
                    for col_name, ddl in required_finding_columns.items():
                        if col_name not in columns:
                            print(f"Migrating database: adding {col_name} to findings table...")
                            conn.execute(db.text(ddl))


                    mission_columns = [row[1] for row in conn.execute(db.text("PRAGMA table_info(missions);")).fetchall()]
                    required_mission_columns = {
                        "objectives": "ALTER TABLE missions ADD COLUMN objectives JSON;",
                        "scope_summary": "ALTER TABLE missions ADD COLUMN scope_summary TEXT;",
                        "priority": "ALTER TABLE missions ADD COLUMN priority TEXT DEFAULT 'medium';",
                        "tags": "ALTER TABLE missions ADD COLUMN tags JSON;",
                        "updated_at": "ALTER TABLE missions ADD COLUMN updated_at DATETIME;",
                    }
                    for col_name, ddl in required_mission_columns.items():
                        if col_name not in mission_columns:
                            print(f"Migrating database: adding {col_name} to missions table...")
                            conn.execute(db.text(ddl))

                    conn.execute(db.text("CREATE TABLE IF NOT EXISTS assets (id INTEGER PRIMARY KEY, mission_id INTEGER NOT NULL REFERENCES missions(id), type TEXT NOT NULL DEFAULT 'domain', identifier TEXT NOT NULL, label TEXT, confidence TEXT NOT NULL DEFAULT 'medium', source TEXT, provenance JSON, tags JSON, created_at DATETIME);"))
                    conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_assets_mission_id ON assets(mission_id);"))
                    conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_assets_identifier ON assets(identifier);"))

                    conn.execute(db.text("CREATE TABLE IF NOT EXISTS asset_target_links (id INTEGER PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id), target_id INTEGER NOT NULL REFERENCES targets(id), link_type TEXT NOT NULL DEFAULT 'observed', confidence TEXT NOT NULL DEFAULT 'medium', source TEXT, metadata JSON, created_at DATETIME, CONSTRAINT uq_asset_target_link UNIQUE (asset_id, target_id));"))
                    conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_asset_target_links_asset_id ON asset_target_links(asset_id);"))
                    conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_asset_target_links_target_id ON asset_target_links(target_id);"))
                    conn.execute(db.text("CREATE TABLE IF NOT EXISTS operator_actions (id INTEGER PRIMARY KEY, mission_id INTEGER NOT NULL REFERENCES missions(id), action_key TEXT NOT NULL, related_asset_ids JSON, related_target_ids JSON, related_finding_ids JSON, related_signal_ids JSON, objective_type TEXT NOT NULL, action_type TEXT NOT NULL DEFAULT 'review', title TEXT NOT NULL, description TEXT, rationale TEXT, confidence FLOAT DEFAULT 0, attack_priority TEXT DEFAULT 'medium', estimated_value TEXT DEFAULT 'medium', estimated_complexity TEXT DEFAULT 'low', status TEXT NOT NULL DEFAULT 'suggested', blocker_summary JSON, required_conditions JSON, evidence_summary TEXT, metadata JSON, created_at DATETIME, updated_at DATETIME, CONSTRAINT uq_operator_action_mission_key UNIQUE (mission_id, action_key));"))
                    conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_operator_actions_mission_id ON operator_actions(mission_id);"))
                    conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_operator_actions_status ON operator_actions(status);"))

                    replay_columns = [row[1] for row in conn.execute(db.text("PRAGMA table_info(replay_vault_entries);")).fetchall()]
                    if "graphql_summary" not in replay_columns:
                        print("Migrating database: adding graphql_summary to replay_vault_entries table...")
                        conn.execute(db.text("ALTER TABLE replay_vault_entries ADD COLUMN graphql_summary JSON;"))

                    conn.execute(db.text("CREATE TABLE IF NOT EXISTS operator_feedback (id INTEGER PRIMARY KEY, mission_id INTEGER NOT NULL REFERENCES missions(id), action_id INTEGER REFERENCES operator_actions(id), finding_id INTEGER REFERENCES findings(id), replay_id INTEGER REFERENCES replay_vault_entries(id), feedback_type TEXT NOT NULL, signal_family TEXT, subject_type TEXT, subject_key TEXT, sentiment INTEGER NOT NULL DEFAULT 0, notes TEXT, metadata JSON, created_at DATETIME);"))
                    conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_operator_feedback_mission_id ON operator_feedback(mission_id);"))
                    conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_operator_feedback_action_id ON operator_feedback(action_id);"))
                    conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_operator_feedback_finding_id ON operator_feedback(finding_id);"))
                    conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_operator_feedback_replay_id ON operator_feedback(replay_id);"))
                    conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_operator_feedback_type ON operator_feedback(feedback_type);"))

                    conn.execute(db.text("CREATE TABLE IF NOT EXISTS global_settings (id INTEGER PRIMARY KEY, key TEXT UNIQUE NOT NULL, value TEXT, description TEXT, category TEXT, updated_at DATETIME);"))
                    conn.execute(db.text("CREATE INDEX IF NOT EXISTS idx_global_settings_key ON global_settings(key);"))
            except Exception as e:
                print(f"Migration check failed: {e}")

        # --- DB HYGIENE: Reset stale scans ---
        try:
            from core.models import Scan
            stale_scans = Scan.query.filter(Scan.status.in_(['running', 'pending'])).all()
            if stale_scans:
                print(f"Cleaning up {len(stale_scans)} stale scans from previous session...")
                for s in stale_scans:
                    s.status = 'aborted'
                db.session.commit()
        except Exception as e:
            print(f"DB Hygiene check failed: {e}")

    # Use environment variable for debug mode (defaulting to False for security)
    debug_mode = os.getenv("FLASK_DEBUG", "False").lower() in ("true", "1", "t")
    allow_unsafe = os.getenv("ALLOW_UNSAFE_WERKZEUG", "False").lower() in ("true", "1", "t")

    run_args = {
        "host": "0.0.0.0",
        "port": 5001,
        "debug": debug_mode
    }

    if debug_mode or allow_unsafe:
        run_args["allow_unsafe_werkzeug"] = True

    socketio.run(app, **run_args)
