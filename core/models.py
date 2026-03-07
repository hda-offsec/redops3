from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from core.extensions import db


# ------------------------------------------------------------------
# USERS
# ------------------------------------------------------------------

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


# ------------------------------------------------------------------
# MISSIONS
# ------------------------------------------------------------------

class Mission(db.Model):
    __tablename__ = "missions"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(32), default="draft")
    objectives_json = db.Column("objectives", db.JSON, nullable=True)
    scope_summary = db.Column(db.Text, nullable=True)
    priority = db.Column(db.String(20), default="medium")
    tags_json = db.Column("tags", db.JSON, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    targets = db.relationship("Target", backref="mission", lazy=True)
    loots = db.relationship("Loot", backref="mission", lazy=True)
    assets = db.relationship("Asset", backref="mission", lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Mission {self.name}>"


# ------------------------------------------------------------------
# TARGETS
# ------------------------------------------------------------------

class Target(db.Model):
    __tablename__ = "targets"

    id = db.Column(db.Integer, primary_key=True)
    mission_id = db.Column(db.Integer, db.ForeignKey("missions.id"), nullable=True)

    identifier = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    scans = db.relationship("Scan", backref="target", lazy=True)
    asset_links = db.relationship(
        "AssetTargetLink",
        backref="target",
        lazy=True,
        cascade="all, delete-orphan",
    )

    def __repr__(self):
        return f"<Target {self.identifier}>"


class Asset(db.Model):
    __tablename__ = "assets"

    id = db.Column(db.Integer, primary_key=True)
    mission_id = db.Column(db.Integer, db.ForeignKey("missions.id"), nullable=False, index=True)
    type = db.Column(db.String(50), nullable=False, default="domain")
    identifier = db.Column(db.String(255), nullable=False, index=True)
    label = db.Column(db.String(255), nullable=True)
    confidence = db.Column(db.String(20), nullable=False, default="medium")
    source = db.Column(db.String(128), nullable=True)
    provenance = db.Column(db.JSON, nullable=True)
    tags = db.Column(db.JSON, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    target_links = db.relationship(
        "AssetTargetLink",
        backref="asset",
        lazy=True,
        cascade="all, delete-orphan",
    )


class AssetTargetLink(db.Model):
    __tablename__ = "asset_target_links"

    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id"), nullable=False, index=True)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id"), nullable=False, index=True)
    link_type = db.Column(db.String(64), nullable=False, default="observed")
    confidence = db.Column(db.String(20), nullable=False, default="medium")
    source = db.Column(db.String(128), nullable=True)
    metadata_json = db.Column("metadata", db.JSON, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("asset_id", "target_id", name="uq_asset_target_link"),
    )


# ------------------------------------------------------------------
# SCANS
# ------------------------------------------------------------------

class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)

    target_id = db.Column(db.Integer, db.ForeignKey("targets.id"), nullable=False)

    parent_scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=True)

    children = db.relationship(
        "Scan",
        backref=db.backref("parent", remote_side=[id]),
        lazy=True
    )

    scan_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default="pending")

    task_id = db.Column(db.String(50), nullable=True)

    params = db.Column(db.Text, nullable=True)

    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)

    findings = db.relationship(
        "Finding",
        backref="scan",
        lazy=True,
        cascade="all, delete-orphan"
    )

    signals = db.relationship(
        "Signal",
        backref="scan",
        lazy=True,
        cascade="all, delete-orphan"
    )

    logs = db.relationship(
        "ScanLog",
        backref="scan",
        lazy=True,
        cascade="all, delete-orphan"
    )

    suggestions = db.relationship(
        "Suggestion",
        backref="scan",
        lazy=True,
        cascade="all, delete-orphan"
    )

    knowledge_nodes = db.relationship(
        "KnowledgeNode",
        backref="scan",
        lazy=True,
        cascade="all, delete-orphan"
    )

    knowledge_edges = db.relationship(
        "KnowledgeEdge",
        backref="scan",
        lazy=True,
        cascade="all, delete-orphan"
    )

    notes = db.Column(db.Text, nullable=True)
    geolocation_data = db.Column(db.JSON, nullable=True)

    def __repr__(self):
        return f"<Scan {self.id} - {self.scan_type}>"


# ------------------------------------------------------------------
# SIGNALS (RAW DETECTION DATA)
# ------------------------------------------------------------------

class Signal(db.Model):
    __tablename__ = "signals"

    id = db.Column(db.Integer, primary_key=True)

    scan_id = db.Column(
        db.Integer,
        db.ForeignKey("scans.id"),
        nullable=False,
        index=True
    )

    tool = db.Column(db.String(64), nullable=False, default="unknown")
    module = db.Column(db.String(128), nullable=True)
    type = db.Column(db.String(64), nullable=False, default="generic")

    target = db.Column(db.String(1024), nullable=True)
    endpoint = db.Column(db.String(2048), nullable=True)
    parameter = db.Column(db.String(255), nullable=True)

    payload = db.Column(db.Text, nullable=True)
    status_code = db.Column(db.Integer, nullable=True)

    response_headers_json = db.Column("response_headers", db.JSON, nullable=True)

    response_evidence = db.Column(db.Text, nullable=True)

    raw_output = db.Column(db.Text, nullable=True)

    metadata_json = db.Column("metadata", db.JSON, nullable=True)

    timestamp = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        index=True
    )


# ------------------------------------------------------------------
# FINDINGS (CORRELATED VULNERABILITIES)
# ------------------------------------------------------------------

class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)

    scan_id = db.Column(
        db.Integer,
        db.ForeignKey("scans.id"),
        nullable=False
    )

    severity = db.Column(db.String(20), default="info")
    confidence = db.Column(db.String(20), default="medium")

    id_stable = db.Column(db.String(128), index=True, nullable=True)

    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)

    tool_source = db.Column(db.String(50))

    signal_ids = db.Column(db.JSON, nullable=True)

    tool = db.Column(db.String(64), nullable=True)
    module = db.Column(db.String(128), nullable=True)
    category = db.Column(db.String(128), nullable=True)

    target = db.Column(db.String(1024), nullable=True)
    endpoint = db.Column(db.String(2048), nullable=True)
    parameter = db.Column(db.String(255), nullable=True)

    payload = db.Column(db.Text, nullable=True)

    raw_output = db.Column(db.Text, nullable=True)

    metadata_json = db.Column("metadata", db.JSON, nullable=True)

    evidence = db.Column(db.Text, nullable=True)

    reproduction = db.Column(db.Text, nullable=True)

    screenshot_path = db.Column(db.String(255), nullable=True)

    request = db.Column(db.Text, nullable=True)
    response = db.Column(db.Text, nullable=True)
    repro_command = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ------------------------------------------------------------------
# LOOT
# ------------------------------------------------------------------

class Loot(db.Model):
    __tablename__ = "loots"

    id = db.Column(db.Integer, primary_key=True)

    mission_id = db.Column(
        db.Integer,
        db.ForeignKey("missions.id"),
        nullable=True
    )

    scan_id = db.Column(
        db.Integer,
        db.ForeignKey("scans.id"),
        nullable=True
    )

    type = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)

    context = db.Column(db.String(255), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ------------------------------------------------------------------
# SCAN LOGS
# ------------------------------------------------------------------

class ScanLog(db.Model):
    __tablename__ = "scan_logs"

    id = db.Column(db.Integer, primary_key=True)

    scan_id = db.Column(
        db.Integer,
        db.ForeignKey("scans.id"),
        nullable=False
    )

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    message = db.Column(db.Text, nullable=False)

    level = db.Column(db.String(20), default="INFO")


# ------------------------------------------------------------------
# SUGGESTIONS
# ------------------------------------------------------------------

class Suggestion(db.Model):
    __tablename__ = "suggestions"

    id = db.Column(db.Integer, primary_key=True)

    scan_id = db.Column(
        db.Integer,
        db.ForeignKey("scans.id"),
        nullable=False
    )

    tool_name = db.Column(db.String(50), nullable=False)

    command_suggestion = db.Column(db.Text, nullable=False)

    reason = db.Column(db.String(255), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ------------------------------------------------------------------
# KNOWLEDGE GRAPH
# ------------------------------------------------------------------

class KnowledgeNode(db.Model):
    __tablename__ = "knowledge_nodes"

    id = db.Column(db.Integer, primary_key=True)

    scan_id = db.Column(
        db.Integer,
        db.ForeignKey("scans.id"),
        nullable=False
    )

    node_id = db.Column(db.String(128), nullable=False)
    type = db.Column(db.String(50), nullable=False)

    label = db.Column(db.String(255), nullable=True)

    metadata_json = db.Column(db.JSON, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<KnowledgeNode {self.node_id} ({self.type})>"


class KnowledgeEdge(db.Model):
    __tablename__ = "knowledge_edges"

    id = db.Column(db.Integer, primary_key=True)

    scan_id = db.Column(
        db.Integer,
        db.ForeignKey("scans.id"),
        nullable=False
    )

    source_node = db.Column(db.String(128), nullable=False)
    target_node = db.Column(db.String(128), nullable=False)

    relationship = db.Column(db.String(50), nullable=False)

    metadata_json = db.Column(db.JSON, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<KnowledgeEdge {self.source_node} --[{self.relationship}]--> {self.target_node}>"
