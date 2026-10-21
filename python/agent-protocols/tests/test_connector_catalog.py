"""Shared MCP contracts; Python intentionally has no connector runtime."""
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[3]
CATALOG = json.loads((ROOT / "docs/mcp/local-connector/1.0.tools.json").read_text())
TOOLS = {tool["name"]: tool for tool in CATALOG}
VECTORS = json.loads((ROOT / "docs/mcp/local-connector/1.0.vectors.json").read_text())


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda case: case["name"])
def test_shared_tool_input_contract(case):
    validator = Draft202012Validator(TOOLS[case["tool"]]["inputSchema"])
    assert validator.is_valid(case["input"]) == case["valid"]


def test_tool_schemas_are_self_contained_and_outputs_describe_fields():
    assert len(TOOLS) == len(CATALOG) == 41
    for tool in CATALOG:
        Draft202012Validator.check_schema(tool["inputSchema"])
        Draft202012Validator.check_schema(tool["outputSchema"])
        assert tool["outputSchema"]["properties"]
        encoded = json.dumps(tool["inputSchema"])
        assert all(f'"{keyword}"' not in encoded for keyword in ("oneOf", "anyOf", "allOf", "$ref"))


def test_bilingual_tool_tables_match():
    def tables(path):
        result = {}
        for line in path.read_text().splitlines():
            if line.startswith("| `agent_protocols_"):
                cells = line.replace(r"\|", "¦").split("|")
                result[cells[1].strip().strip("`")] = " ".join(cells[2].split())
        return result

    folder = ROOT / "docs/mcp/local-connector"
    english = tables(folder / "1.0.md")
    assert english == tables(folder / "1.0.zh-CN.md")
    assert set(english) == set(TOOLS)
