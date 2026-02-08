import pytest
from scan_engine.helpers.process_manager import ProcessManager

class TestProcessManager:
    """Test suite for ProcessManager helper methods."""

    def test_prepare_command_list(self):
        """Test _prepare_command with a list input."""
        command = ["ls", "-la"]
        result, use_shell = ProcessManager._prepare_command(command)
        assert result == command
        assert use_shell is False
        assert isinstance(result, list)

    def test_prepare_command_tuple(self):
        """Test _prepare_command with a tuple input."""
        command = ("ls", "-la")
        result, use_shell = ProcessManager._prepare_command(command)
        assert result == ["ls", "-la"]
        assert use_shell is False
        assert isinstance(result, list)

    def test_prepare_command_string(self):
        """Test _prepare_command with a string input."""
        command = "ls -la"
        result, use_shell = ProcessManager._prepare_command(command)
        assert result == command
        assert use_shell is True
        assert isinstance(result, str)

    def test_prepare_command_empty(self):
        """Test _prepare_command with empty inputs."""
        # Empty list
        result, use_shell = ProcessManager._prepare_command([])
        assert result == []
        assert use_shell is False

        # Empty tuple
        result, use_shell = ProcessManager._prepare_command(())
        assert result == []
        assert use_shell is False

        # Empty string
        result, use_shell = ProcessManager._prepare_command("")
        assert result == ""
        assert use_shell is True
