from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from core.extensions import db


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"


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
    parent_scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=True)
    children = db.relationship("Scan", backref=db.backref("parent", remote_side=[id]), lazy=True)
    scan_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default="pending")
    task_id = db.Column(db.String(50), nullable=True)
    params = db.Column(db.Text, nullable=True)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    findings = db.relationship("Finding", backref="scan", lazy=True, cascade="all, delete-orphan")
    signals = db.relationship("Signal", backref="scan", lazy=True, cascade="all, delete-orphan")
    logs = db.relationship("ScanLog", backref="scan", lazy=True, cascade="all, delete-orphan")
    suggestions = db.relationship("Suggestion", backref="scan", lazy=True, cascade="all, delete-orphan")
    knowledge_nodes = db.relationship("KnowledgeNode", backref="scan", lazy=True, cascade="all, delete-orphan")
    knowledge_edges = db.relationship("KnowledgeEdge", backref="scan", lazy=True, cascade="all, delete-orphan")
    notes = db.Column(db.Text, nullable=True)
    geolocation_data = db.Column(db.JSON, nullable=True)

    def __repr__(self):
        return f"<Scan {self.id} - {self.scan_type}>"


class Signal(db.Model):
    __tablename__ = "signals"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False, index=True)
    tool = db.Column(db.String(64), nullable=False, default="unknown")
    type = db.Column(db.String(64), nullable=False, default="generic")
    target = db.Column(db.String(1024), nullable=True)
    endpoint = db.Column(db.String(2048), nullable=True)
    parameter = db.Column(db.String(255), nullable=True)
    payload = db.Column(db.Text, nullable=True)
    raw_output = db.Column(db.Text, nullable=True)
    metadata_json = db.Column("metadata", db.JSON, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    severity = db.Column(db.String(20), default="info")
    confidence = db.Column(db.String(20), default="medium") # low, medium, high, certain
    id_stable = db.Column(db.String(128), index=True, nullable=True) # V6 Stable ID
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    tool_source = db.Column(db.String(50))
    signal_ids = db.Column(db.JSON, nullable=True)
    target = db.Column(db.String(1024), nullable=True)
    tool = db.Column(db.String(64), nullable=True)
    module = db.Column(db.String(128), nullable=True)
    category = db.Column(db.String(128), nullable=True)
    endpoint = db.Column(db.String(2048), nullable=True)
    parameter = db.Column(db.String(255), nullable=True)
    payload = db.Column(db.Text, nullable=True)
    raw_output = db.Column(db.Text, nullable=True)
    metadata_json = db.Column("metadata", db.JSON, nullable=True)
    evidence = db.Column(db.Text, nullable=True)
    reproduction = db.Column(db.Text, nullable=True)
    screenshot_path = db.Column(db.String(255), nullable=True)
    
    # Evidence for Validation
    request = db.Column(db.Text, nullable=True)
    response = db.Column(db.Text, nullable=True)
    repro_command = db.Column(db.Text, nullable=True)
    
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
class KnowledgeNode(db.Model):
    __tablename__ = "knowledge_nodes"
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    node_id = db.Column(db.String(128), nullable=False) # e.g. "service:80", "finding:nuclei:1"
    type = db.Column(db.String(50), nullable=False) # service, endpoint, finding, tech_profile, etc.
    label = db.Column(db.String(255), nullable=True)
    metadata_json = db.Column(db.JSON, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<KnowledgeNode {self.node_id} ({self.type})>"


class KnowledgeEdge(db.Model):
    __tablename__ = "knowledge_edges"
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    source_node = db.Column(db.String(128), nullable=False)
    target_node = db.Column(db.String(128), nullable=False)
    relationship = db.Column(db.String(50), nullable=False) # exposes, has_finding, vulnerable_to, etc.
    metadata_json = db.Column(db.JSON, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<KnowledgeEdge {self.source_node} --[{self.relationship}]--> {self.target_node}>"
