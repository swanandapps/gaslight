"""The blast radius must mean "how far something actually got", not "what tools
exist". A guard that holds has to keep the radius small — otherwise this is a
tool inventory wearing a diagram's clothes.
"""

from mcp import types

from gaslight.core.attacks.base import Finding
from gaslight.core.blast import BREACHED, HELD, NONE, REACH, blast_geometry, blast_headline, compute_blast


def _tool(name, props):
    return types.Tool(name=name, inputSchema={"type": "object", "properties": props})


def _f(key, *, fired=False, attempted=True):
    return Finding(attack_key=key, fired=fired, reason="x", attempted=attempted)


FILE_TOOL = _tool("read_file", {"path": {"type": "string"}})
URL_TOOL = _tool("fetch_page", {"url": {"type": "string"}})
SEND_TOOL = _tool("send_email", {"to": {"type": "string"}, "body": {"type": "string"}})


def _by_key(zones):
    return {z.key: z for z in zones}


def test_a_held_guard_keeps_the_radius_small():
    """The whole point: having a file tool must NOT light the ring. Only an
    attack physically getting through does."""
    zones = _by_key(compute_blast([FILE_TOOL], [_f("path-traversal", fired=False)]))
    assert zones["host"].state == HELD
    geo = blast_geometry(list(zones.values()))
    assert geo["breached"] is False
    assert geo["glow_r"] == 54.0  # unchanged from the core — nothing got out
    assert "Contained" in blast_headline(list(zones.values()))


def test_a_breach_expands_the_radius():
    zones = _by_key(compute_blast([FILE_TOOL], [_f("path-traversal", fired=True)]))
    assert zones["host"].state == BREACHED
    geo = blast_geometry(list(zones.values()))
    assert geo["breached"] is True
    assert geo["glow_r"] > 54.0
    assert geo["furthest"] == "THIS MACHINE"


def test_the_glow_stops_at_the_outermost_breach_not_the_outermost_capability():
    """A target that CAN reach the network but was only breached on the machine
    must show a machine-sized blast, not a network-sized one."""
    zones = compute_blast(
        [FILE_TOOL, URL_TOOL],
        [_f("path-traversal", fired=True), _f("ssrf-probe", fired=False)],
    )
    geo = blast_geometry(zones)
    host_ring = geo["rings"][0]["r"]
    assert geo["glow_r"] == host_ring
    assert _by_key(zones)["net"].state == HELD


def test_no_capability_reads_as_out_of_reach():
    zones = _by_key(compute_blast([FILE_TOOL], [_f("path-traversal")]))
    assert zones["net"].state == NONE
    assert zones["world"].state == NONE


def test_untested_capability_is_reachable_not_held():
    """A tool we never managed to attack is honestly unknown — it must not be
    reported as a guard that held."""
    zones = _by_key(compute_blast([FILE_TOOL], [_f("path-traversal", attempted=False)]))
    assert zones["host"].state == REACH


def test_data_leaving_lights_only_on_a_real_exfil():
    zones = _by_key(compute_blast([SEND_TOOL], [_f("tool-authz-probe", fired=True)]))
    assert zones["world"].state == BREACHED
    assert blast_geometry(list(zones.values()))["furthest"] == "DATA LEAVING"


def test_nothing_testable_says_so():
    zones = compute_blast([], [])
    assert all(z.state == NONE for z in zones)
    assert "Nothing could be tested" in blast_headline(zones)


def test_every_ring_has_geometry_and_a_label():
    zones = compute_blast([FILE_TOOL, URL_TOOL, SEND_TOOL], [])
    geo = blast_geometry(zones)
    assert len(geo["rings"]) == 3
    assert [r["label"] for r in geo["rings"]] == ["THIS MACHINE", "YOUR NETWORK", "DATA LEAVING"]
    assert all(r["r"] > geo["core_r"] for r in geo["rings"])
