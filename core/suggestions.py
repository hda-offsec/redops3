from core.models import Suggestion, db


class SuggestionEngine:
    @staticmethod
    def generate_suggestion(scan_id, tool_name, command, reason=None):
        suggestion = Suggestion(
            scan_id=scan_id,
            tool_name=tool_name,
            command_suggestion=command,
            reason=reason,
        )
        db.session.add(suggestion)
        db.session.commit()
        return suggestion
