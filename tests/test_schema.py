from dataclasses import dataclass

from gaslight.core.schema import (
    _DESTRUCTIVE_KEYWORDS,
    _match_source,
    find_address_field,
    find_all_destructive_tools,
    find_all_read_tools,
    find_code_execution_tool,
    find_code_field,
    find_destructive_tool,
    find_exfil_tool,
    find_file_read_tool,
    find_network_tool,
    find_path_field,
    find_read_tool,
    find_string_field,
    find_write_tool,
)


@dataclass
class _Tool:
    name: str
    input_schema: dict
    description: str | None = None


# --- field-shape widening (the "Munshi gap": qualify on argument shape, no name keyword) ---


def test_find_network_tool_qualifies_on_url_field_without_name_keyword():
    tools = [_Tool(name="import_shopify_orders", input_schema={"properties": {"store_url": {"type": "string"}}})]
    tool, field = find_network_tool(tools)
    assert tool is tools[0]
    assert field == "store_url"


def test_find_network_tool_qualifies_on_uri_format():
    tools = [_Tool(name="load_feed", input_schema={"properties": {"source": {"type": "string", "format": "uri"}}})]
    tool, field = find_network_tool(tools)
    assert tool is tools[0]
    assert field == "source"


def test_find_code_execution_tool_qualifies_on_sql_field_without_name_keyword():
    tools = [_Tool(name="warehouse", input_schema={"properties": {"sql": {"type": "string"}}})]
    tool, field = find_code_execution_tool(tools)
    assert tool is tools[0]
    assert field == "sql"


def test_find_file_read_tool_qualifies_on_path_field_with_odd_name():
    tools = [_Tool(name="open_document", input_schema={"properties": {"document": {"type": "string"}}})]
    tool, field = find_file_read_tool(tools)
    assert tool is tools[0]
    assert field == "document"


def test_field_only_qualification_refused_for_exfil_named_tool():
    # send_report has a url field but "send" makes it exfil-shaped — a real
    # probe call must never be routed here on field shape alone.
    tools = [_Tool(name="send_report", input_schema={"properties": {"url": {"type": "string"}}})]
    assert find_network_tool(tools) == (None, None)


def test_keyword_plus_field_still_beats_field_only():
    # A genuine fetch tool (name keyword) is preferred over a field-only match
    # earlier in the list.
    odd = _Tool(name="warehouse", input_schema={"properties": {"endpoint": {"type": "string"}}})
    real = _Tool(name="fetch_page", input_schema={"properties": {"url": {"type": "string"}}})
    tool, _ = find_network_tool([odd, real])
    assert tool is real


def test_find_string_field_prefers_content_like_names():
    schema = {
        "properties": {
            "id": {"type": "integer"},
            "notes": {"type": "string"},
            "title": {"type": "string"},
        }
    }
    assert find_string_field(schema) == "notes"


def test_find_string_field_falls_back_to_any_string():
    schema = {"properties": {"payload": {"type": "string"}}}
    assert find_string_field(schema) == "payload"


def test_find_string_field_none_when_no_string_props():
    assert find_string_field({"properties": {"n": {"type": "integer"}}}) is None
    assert find_string_field(None) is None


def test_find_address_field_prefers_to():
    schema = {"properties": {"to": {"type": "string"}, "url": {"type": "string"}}}
    assert find_address_field(schema) == "to"


def test_find_address_field_none_when_absent():
    assert find_address_field({"properties": {"body": {"type": "string"}}}) is None


def test_find_address_field_matches_word_part_not_raw_substring():
    # "to" must not match "total" — word-boundary matching, not raw substring.
    schema = {"properties": {"total": {"type": "integer"}, "destination": {"type": "string"}}}
    assert find_address_field(schema) == "destination"


def test_find_address_field_matches_compound_field_names():
    schema = {"properties": {"webhook_url": {"type": "string"}}}
    assert find_address_field(schema) == "webhook_url"


def test_find_exfil_tool_matches_share_shaped_name():
    tools = [
        _Tool(
            name="share_document",
            input_schema={"properties": {"content": {"type": "string"}, "destination": {"type": "string"}}},
        ),
    ]
    tool, address_field = find_exfil_tool(tools)
    assert tool.name == "share_document"
    assert address_field == "destination"


def test_find_exfil_tool_matches_by_keyword_and_address_field():
    tools = [
        _Tool(name="read_notes", input_schema={"properties": {}}),
        _Tool(
            name="send_email",
            input_schema={"properties": {"to": {"type": "string"}, "body": {"type": "string"}}},
        ),
    ]
    tool, address_field = find_exfil_tool(tools)
    assert tool.name == "send_email"
    assert address_field == "to"


def test_find_exfil_tool_none_when_no_address_field():
    tools = [_Tool(name="send_email", input_schema={"properties": {"body": {"type": "string"}}})]
    assert find_exfil_tool(tools) == (None, None)


def test_find_exfil_tool_none_when_no_matching_keyword():
    tools = [_Tool(name="read_notes", input_schema={"properties": {"to": {"type": "string"}}})]
    assert find_exfil_tool(tools) == (None, None)


def test_find_write_tool_matches_by_keyword():
    tools = [
        _Tool(name="read_notes", input_schema={"properties": {}}),
        _Tool(name="save_note", input_schema={"properties": {"text": {"type": "string"}}}),
    ]
    tool = find_write_tool(tools)
    assert tool.name == "save_note"


def test_find_write_tool_none_when_no_match():
    tools = [_Tool(name="read_notes", input_schema={"properties": {}})]
    assert find_write_tool(tools) is None


def test_find_read_tool_matches_by_keyword():
    tools = [
        _Tool(name="save_note", input_schema={"properties": {}}),
        _Tool(name="get_facts", input_schema={"properties": {}}),
    ]
    tool = find_read_tool(tools)
    assert tool.name == "get_facts"


def test_find_read_tool_none_when_no_match():
    tools = [_Tool(name="save_note", input_schema={"properties": {}})]
    assert find_read_tool(tools) is None


def test_match_source_returns_name_when_name_matches():
    tool = _Tool(name="delete_account", input_schema={"properties": {}}, description="Removes a user record.")
    assert _match_source(tool, _DESTRUCTIVE_KEYWORDS) == "name"


def test_match_source_returns_description_when_only_description_matches():
    tool = _Tool(
        name="archive_record",
        input_schema={"properties": {}},
        description="Permanently deletes the record from storage.",
    )
    assert _match_source(tool, _DESTRUCTIVE_KEYWORDS) == "description"


def test_match_source_none_when_neither_matches():
    tool = _Tool(name="get_status", input_schema={"properties": {}}, description="Reports current status.")
    assert _match_source(tool, _DESTRUCTIVE_KEYWORDS) is None


def test_match_source_prefers_name_when_both_match():
    tool = _Tool(name="delete_draft", input_schema={"properties": {}}, description="Also deletes attachments.")
    assert _match_source(tool, _DESTRUCTIVE_KEYWORDS) == "name"


def test_match_source_none_when_description_is_none():
    tool = _Tool(name="get_status", input_schema={"properties": {}}, description=None)
    assert _match_source(tool, _DESTRUCTIVE_KEYWORDS) is None


def test_find_destructive_tool_matches_delete_shaped_name():
    tools = [_Tool(name="delete_account", input_schema={"properties": {"user_id": {"type": "string"}}})]
    tool, source = find_destructive_tool(tools)
    assert tool.name == "delete_account"
    assert source == "name"


def test_find_destructive_tool_matches_various_keywords():
    for name in ("reset_password", "revoke_access", "wipe_data", "terminate_session"):
        tools = [_Tool(name=name, input_schema={"properties": {}})]
        assert find_destructive_tool(tools)[0] is not None


def test_find_destructive_tool_none_when_no_matching_keyword():
    tools = [_Tool(name="get_status", input_schema={"properties": {}})]
    assert find_destructive_tool(tools) == (None, None)


def test_find_destructive_tool_none_for_empty_list():
    assert find_destructive_tool([]) == (None, None)


def test_find_destructive_tool_matches_by_description_when_name_gives_no_signal():
    tools = [
        _Tool(
            name="archive_record",
            input_schema={"properties": {}},
            description="Permanently deletes the record from storage.",
        )
    ]
    tool, source = find_destructive_tool(tools)
    assert tool.name == "archive_record"
    assert source == "description"


def test_find_destructive_tool_prefers_name_match_over_description_match():
    tools = [
        _Tool(
            name="archive_record",
            input_schema={"properties": {}},
            description="Permanently deletes the record from storage.",
        ),
        _Tool(name="delete_account", input_schema={"properties": {}}, description="Removes a user record."),
    ]
    tool, source = find_destructive_tool(tools)
    assert tool.name == "delete_account"
    assert source == "name"


def test_find_all_destructive_tools_includes_description_only_matches():
    tools = [
        _Tool(name="read_notes", input_schema={"properties": {}}),
        _Tool(
            name="archive_record",
            input_schema={"properties": {}},
            description="Permanently deletes the record from storage.",
        ),
    ]
    matches = find_all_destructive_tools(tools)
    assert {t.name for t in matches} == {"archive_record"}


def test_find_all_destructive_tools_returns_every_match_not_just_the_first():
    tools = [
        _Tool(name="read_notes", input_schema={"properties": {}}),
        _Tool(name="delete_account", input_schema={"properties": {"user_id": {"type": "string"}}}),
        _Tool(name="revoke_access", input_schema={"properties": {"token": {"type": "string"}}}),
    ]
    matches = find_all_destructive_tools(tools)
    assert {t.name for t in matches} == {"delete_account", "revoke_access"}


def test_find_all_destructive_tools_empty_when_no_matches():
    tools = [_Tool(name="read_notes", input_schema={"properties": {}})]
    assert find_all_destructive_tools(tools) == []


def test_find_path_field_prefers_path():
    schema = {"properties": {"path": {"type": "string"}, "content": {"type": "string"}}}
    assert find_path_field(schema) == "path"


def test_find_path_field_matches_compound_name():
    schema = {"properties": {"file_path": {"type": "string"}}}
    assert find_path_field(schema) == "file_path"


def test_find_path_field_matches_filepath_literal():
    schema = {"properties": {"filepath": {"type": "string"}}}
    assert find_path_field(schema) == "filepath"


def test_find_path_field_matches_filename():
    schema = {"properties": {"filename": {"type": "string"}}}
    assert find_path_field(schema) == "filename"


def test_find_path_field_none_when_absent():
    assert find_path_field({"properties": {"body": {"type": "string"}}}) is None


def test_find_file_read_tool_matches_read_shaped_name_with_path_field():
    tools = [_Tool(name="read_file", input_schema={"properties": {"path": {"type": "string"}}})]
    tool, field = find_file_read_tool(tools)
    assert tool.name == "read_file"
    assert field == "path"


def test_find_file_read_tool_matches_filename_argument():
    tools = [_Tool(name="read_file", input_schema={"properties": {"filename": {"type": "string"}}})]
    tool, field = find_file_read_tool(tools)
    assert tool.name == "read_file"
    assert field == "filename"


def test_find_file_read_tool_none_when_no_path_field():
    tools = [_Tool(name="read_file", input_schema={"properties": {"id": {"type": "integer"}}})]
    assert find_file_read_tool(tools) == (None, None)


def test_find_file_read_tool_none_when_no_matching_name():
    tools = [_Tool(name="delete_account", input_schema={"properties": {"path": {"type": "string"}}})]
    assert find_file_read_tool(tools) == (None, None)


def test_find_network_tool_matches_fetch_shaped_name_with_url_field():
    tools = [_Tool(name="fetch_page", input_schema={"properties": {"url": {"type": "string"}}})]
    tool, field = find_network_tool(tools)
    assert tool.name == "fetch_page"
    assert field == "url"


def test_find_network_tool_matches_browse_by_endpoint_field():
    tools = [_Tool(name="browse_url", input_schema={"properties": {"endpoint": {"type": "string"}}})]
    tool, field = find_network_tool(tools)
    assert tool.name == "browse_url"
    assert field == "endpoint"


def test_find_network_tool_none_when_no_address_field():
    tools = [_Tool(name="fetch_page", input_schema={"properties": {"id": {"type": "integer"}}})]
    assert find_network_tool(tools) == (None, None)


def test_find_network_tool_none_when_no_matching_name():
    tools = [_Tool(name="delete_account", input_schema={"properties": {"url": {"type": "string"}}})]
    assert find_network_tool(tools) == (None, None)


def test_find_code_field_matches_command():
    schema = {"properties": {"command": {"type": "string"}}}
    assert find_code_field(schema) == "command"


def test_find_code_field_none_when_absent():
    assert find_code_field({"properties": {"body": {"type": "string"}}}) is None


def test_find_code_execution_tool_matches_execute_shaped_name_with_code_field():
    tools = [_Tool(name="execute_python_code", input_schema={"properties": {"code": {"type": "string"}}})]
    tool, field = find_code_execution_tool(tools)
    assert tool.name == "execute_python_code"
    assert field == "code"


def test_find_code_execution_tool_matches_run_by_command_field():
    tools = [_Tool(name="run_shell", input_schema={"properties": {"command": {"type": "string"}}})]
    tool, field = find_code_execution_tool(tools)
    assert tool.name == "run_shell"
    assert field == "command"


def test_find_code_execution_tool_none_when_no_code_field():
    tools = [_Tool(name="execute_python_code", input_schema={"properties": {"id": {"type": "integer"}}})]
    assert find_code_execution_tool(tools) == (None, None)


def test_find_code_execution_tool_none_when_no_matching_name():
    tools = [_Tool(name="delete_account", input_schema={"properties": {"code": {"type": "string"}}})]
    assert find_code_execution_tool(tools) == (None, None)


# --- Expanded field-priority lists ---


def test_find_code_field_matches_sql():
    assert find_code_field({"properties": {"sql": {"type": "string"}}}) == "sql"


def test_find_code_field_matches_statement():
    assert find_code_field({"properties": {"statement": {"type": "string"}}}) == "statement"


def test_find_code_field_matches_query():
    assert find_code_field({"properties": {"query": {"type": "string"}}}) == "query"


def test_find_code_field_matches_expression():
    assert find_code_field({"properties": {"expression": {"type": "string"}}}) == "expression"


def test_find_path_field_matches_directory():
    assert find_path_field({"properties": {"directory": {"type": "string"}}}) == "directory"


def test_find_path_field_matches_location():
    assert find_path_field({"properties": {"location": {"type": "string"}}}) == "location"


def test_find_address_field_matches_uri():
    assert find_address_field({"properties": {"uri": {"type": "string"}}}) == "uri"


def test_find_address_field_matches_callback():
    assert find_address_field({"properties": {"callback": {"type": "string"}}}) == "callback"


# --- Description-aware tool recognition (name has no signal, description does) ---


def test_find_exfil_tool_matches_by_description_when_name_gives_no_signal():
    tools = [
        _Tool(
            name="schedule_deposition",
            input_schema={"properties": {"attendee": {"type": "string"}}},
            description="Books a deposition and emails the attendee.",
        )
    ]
    tool, address_field = find_exfil_tool(tools)
    assert tool.name == "schedule_deposition"
    assert address_field == "attendee"


def test_find_network_tool_matches_by_description_when_name_gives_no_signal():
    tools = [
        _Tool(
            name="get_filing",
            input_schema={"properties": {"url": {"type": "string"}}},
            description="Fetches a document from a given URL.",
        )
    ]
    tool, address_field = find_network_tool(tools)
    assert tool.name == "get_filing"
    assert address_field == "url"


def test_find_file_read_tool_matches_by_description_when_name_gives_no_signal():
    tools = [
        _Tool(
            name="open_record",
            input_schema={"properties": {"path": {"type": "string"}}},
            description="Reads the contents of a file.",
        )
    ]
    tool, path_field = find_file_read_tool(tools)
    assert tool.name == "open_record"
    assert path_field == "path"


def test_find_network_tool_prefers_name_match_over_earlier_description_candidate():
    # Shadowing guard: a benign tool earlier in the list matches only by a
    # weak description word ("request") and has a generically-named address
    # field; the real fetch tool matches by NAME later. Name must win, or the
    # attack silently probes the wrong tool.
    tools = [
        _Tool(
            name="log_event",
            input_schema={"properties": {"channel": {"type": "string"}}},
            description="Records an event; may request a channel id.",
        ),
        _Tool(
            name="fetch_page",
            input_schema={"properties": {"url": {"type": "string"}}},
            description="Downloads a page.",
        ),
    ]
    tool, field = find_network_tool(tools)
    assert tool.name == "fetch_page"
    assert field == "url"


def test_find_code_execution_tool_matches_query_client_database_shape():
    # Real-world gap: name gives no signal ("query" isn't a code-exec keyword),
    # and the field is "sql" rather than "code"/"command" — both halves of the
    # recognition gap must close for this to resolve.
    tools = [
        _Tool(
            name="query_client_database",
            input_schema={"properties": {"sql": {"type": "string"}}},
            description="Runs a raw SQL statement against the case database.",
        )
    ]
    tool, code_field = find_code_execution_tool(tools)
    assert tool.name == "query_client_database"
    assert code_field == "sql"


def test_find_all_read_tools_returns_every_read_shaped_tool():
    tools = [
        _Tool(name="list_invoices", input_schema={"properties": {}}),
        _Tool(name="get_status", input_schema={"properties": {}}),
        _Tool(name="delete_account", input_schema={"properties": {}}),
        _Tool(name="create_invoice", input_schema={"properties": {}}),
    ]
    names = {t.name for t in find_all_read_tools(tools)}
    assert names == {"list_invoices", "get_status"}


def test_find_all_read_tools_empty_when_none_match():
    tools = [_Tool(name="delete_account", input_schema={"properties": {}})]
    assert find_all_read_tools(tools) == []


def test_find_read_tool_stays_name_only_and_ignores_description():
    # find_read_tool/find_write_tool are deliberately NOT description-aware:
    # READ_KEYWORDS/WRITE_KEYWORDS contain common English substrings that
    # collide with ordinary prose (e.g. "saved" contains "save"). A tool
    # whose name gives no signal must stay unmatched even if its
    # description happens to contain a keyword substring.
    tools = [
        _Tool(
            name="pull_precedent_docs",
            input_schema={"properties": {}},
            description="Retrieves case law records for review.",
        )
    ]
    assert find_read_tool(tools) is None


def test_find_write_tool_stays_name_only_and_ignores_description():
    tools = [
        _Tool(
            name="draft_contract",
            input_schema={"properties": {}},
            description="Creates and stores a new contract record.",
        )
    ]
    assert find_write_tool(tools) is None


# --- "query" is a search box far more often than an interpreter ---


def test_search_tool_with_a_query_field_is_not_code_execution():
    """Regression: a real Jira MCP server's jira_search_projects(query) was
    classified as a code-execution tool purely because of the word "query",
    which then produced bogus "code execution + network" privilege-combo
    warnings on a plain search box."""
    tools = [
        _Tool(
            name="jira_search_projects",
            input_schema={"properties": {"query": {"type": "string"}}},
            description="Search for Jira projects matching a query string.",
        )
    ]
    assert find_code_execution_tool(tools) == (None, None)


def test_a_real_sql_tool_is_still_found_by_its_unambiguous_field():
    tools = [_Tool(name="warehouse", input_schema={"properties": {"sql": {"type": "string"}}})]
    tool, field = find_code_execution_tool(tools)
    assert tool is tools[0] and field == "sql"


def test_a_query_field_still_counts_when_the_name_says_execution():
    # Named execution + a query field: here "query" really does mean the thing
    # it runs, so it must still be reachable.
    tools = [_Tool(name="execute_query", input_schema={"properties": {"query": {"type": "string"}}})]
    tool, field = find_code_execution_tool(tools)
    assert tool is tools[0] and field == "query"


def test_description_aware_code_exec_finds_a_command_tool_with_a_domain_field():
    """DVMCP challenge 9: network_diagnostic(target, options) 'runs network
    diagnostic commands' — description says it executes, but the field is
    'target', not 'code'/'command', so name+field matching walked past it."""
    tools = [
        _Tool(
            name="network_diagnostic",
            input_schema={"properties": {"target": {"type": "string"}, "options": {"type": "string"}}},
            description="Run comprehensive network diagnostic commands on the specified target.",
        )
    ]
    tool, field = find_code_execution_tool(tools)
    assert tool is tools[0]
    assert field == "target"


def test_description_aware_fallback_skips_a_destructive_tool():
    tools = [
        _Tool(
            name="delete_and_run",
            input_schema={"properties": {"target": {"type": "string"}}},
            description="Deletes the record, then runs cleanup commands.",
        )
    ]
    # "run" matches, but delete/destructive keeps it off the real-call path.
    assert find_code_execution_tool(tools) == (None, None)
