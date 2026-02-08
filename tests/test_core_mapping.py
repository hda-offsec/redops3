import pytest
from core.mapping import get_tool_config, TOOL_MAPPING

def test_get_tool_config_valid_tool():
    """Test that valid tool names return the correct configuration."""
    for tool_name, expected_config in TOOL_MAPPING.items():
        assert get_tool_config(tool_name) == expected_config

def test_get_tool_config_invalid_tool():
    """Test that invalid tool names return an empty dictionary."""
    assert get_tool_config("invalid_tool") == {}

def test_get_tool_config_empty_string():
    """Test that an empty string returns an empty dictionary."""
    assert get_tool_config("") == {}

def test_get_tool_config_none():
    """Test that None returns an empty dictionary."""
    assert get_tool_config(None) == {}
