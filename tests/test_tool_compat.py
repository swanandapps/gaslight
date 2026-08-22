"""MCP SDK version compatibility: older SDKs expose `input_schema` /
`destructive_hint`, newer ones `inputSchema` / `destructiveHint`. gaslight
normalizes both onto the snake_case names it reads throughout, once, at the
point tools enter (target._normalize_tools). Regression test for a real crash:
scanning an agent whose venv had a newer MCP than gaslight was built against.
"""

from mcp import types

from gaslight.core.target import _normalize_tools


class _NewerSdkAnnotations:
    """Simulates a newer-SDK ToolAnnotations exposing camelCase only."""

    def __init__(self):
        self.destructiveHint = True


class _NewerSdkTool:
    """Simulates a newer-SDK Tool exposing camelCase only — the shape that
    crashed gaslight when it read `.input_schema`."""

    def __init__(self, annotations=None):
        self.name = "x"
        self.inputSchema = {"type": "object", "properties": {"q": {"type": "string"}}}
        self.annotations = annotations


def test_camelcase_input_schema_is_bridged_to_snake_case():
    tool = _NewerSdkTool()
    _normalize_tools([tool])
    assert tool.input_schema == {"type": "object", "properties": {"q": {"type": "string"}}}


def test_camelcase_annotation_hint_is_bridged():
    tool = _NewerSdkTool(annotations=_NewerSdkAnnotations())
    _normalize_tools([tool])
    assert tool.annotations.destructive_hint is True


def test_a_real_mcp_tool_survives_normalization():
    # The dev SDK already exposes input_schema; normalization must be a safe
    # no-op that leaves the tool fully usable.
    tool = types.Tool(name="x", inputSchema={"type": "object", "properties": {}})
    _normalize_tools([tool])
    assert tool.input_schema == {"type": "object", "properties": {}}


def test_missing_schema_defaults_to_empty_dict():
    class _NoSchema:
        name = "x"
        annotations = None

    tool = _NoSchema()
    _normalize_tools([tool])
    assert tool.input_schema == {}
