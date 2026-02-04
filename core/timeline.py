from datetime import datetime
from core.models import ScanLog, db


class TimelineService:
    @staticmethod
    def add_entry(scan_id, message, level="INFO"):
        log = ScanLog(
            scan_id=scan_id,
            message=message,
            level=level,
            timestamp=datetime.utcnow(),
        )
        db.session.add(log)
        db.session.commit()
        return log

    @staticmethod
    def get_timeline(scan_id):
        return (
            ScanLog.query.filter_by(scan_id=scan_id)
            .order_by(ScanLog.timestamp.asc())
            .all()
        )
