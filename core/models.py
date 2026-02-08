from datetime import datetime
from core.extensions import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


class Mission(db.Model):
    __tablename__ = "missions"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default="active") # active, archived
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    targets = db.relationship("Target", backref="mission", lazy=True)
    loots = db.relationship("Loot", backref="mission", lazy=True)

    def __repr__(self):
        return f"<Mission {self.name}>"


class Target(db.Model):
    __tablename__ = "targets"

    id = db.Column(db.Integer, primary_key=True)
    mission_id = db.Column(db.Integer, db.ForeignKey("missions.id"), nullable=True)
    identifier = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scans = db.relationship("Scan", backref="target", lazy=True)

    def __repr__(self):
        return f"<Target {self.identifier}>"


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id"), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default="pending")
    params = db.Column(db.Text, nullable=True)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    findings = db.relationship("Finding", backref="scan", lazy=True)
    logs = db.relationship("ScanLog", backref="scan", lazy=True)
    notes = db.Column(db.Text, nullable=True)
    geolocation_data = db.Column(db.JSON, nullable=True)

    def __repr__(self):
        return f"<Scan {self.id} - {self.scan_type}>"


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    severity = db.Column(db.String(20), default="info")
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    tool_source = db.Column(db.String(50))
    screenshot_path = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Loot(db.Model):
    __tablename__ = "loots"

    id = db.Column(db.Integer, primary_key=True)
    mission_id = db.Column(db.Integer, db.ForeignKey("missions.id"), nullable=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=True)
    type = db.Column(db.String(50), nullable=False) # credential, file, token
    content = db.Column(db.Text, nullable=False) # username:password or file path
    context = db.Column(db.String(255), nullable=True) # where it was found
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ScanLog(db.Model):
    __tablename__ = "scan_logs"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    message = db.Column(db.Text, nullable=False)
    level = db.Column(db.String(20), default="INFO")


class Suggestion(db.Model):
    __tablename__ = "suggestions"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    tool_name = db.Column(db.String(50), nullable=False)
    command_suggestion = db.Column(db.Text, nullable=False)
    reason = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"
