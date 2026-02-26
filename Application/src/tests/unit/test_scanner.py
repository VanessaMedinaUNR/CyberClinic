from scan_handler import execute_scans
from tests.unit.test_storage import setup_storage
import pytest
import os
    
def ensure_tools(expected_tools) -> dict[str, tuple[int, bool]]:
    from scan_handler import check_tools
    tools = check_tools()
    for tool in expected_tools:
        assert tool in tools, f"Expected '{tool}' in tools, but got {tools}"
    return {tool: (idx, tool, tools[tool]) for idx, tool in enumerate(expected_tools)}

@pytest.mark.order(after="tests/unit/test_storage.py::TestCStorageHandler::test_fetch_ext")
class TestScans:
    tool_list = ['nmap', 'nikto']

    def test_tool(self, tool, setup_storage):
        storage = setup_storage
        if not tool[2]:  # tool[2] is the boolean indicating if the tool is available
            pytest.skip(f'Tool {tool[1]} is not installed or not supported in this environment. Skipping test.')
        scan_data = {tool[0]: {'scan_type': tool[1], 'report_id': 'test_report', 'target_value': '127.0.0.1'}}
        result = execute_scans(scan_data, storage)
        expected_dir = os.path.join(storage.ext_path, 'scans', 'test_report')
        match tool[1]:
            case 'nmap':
                expected_path = os.path.join(expected_dir, f'{tool[0]}.xml')
            case 'nikto':
                expected_path = os.path.join(expected_dir, f'{tool[0]}.json')
        assert storage.fetch_ext(result) == expected_path, f"{tool[1]} Scan Did not save successfully, expected to find it at {expected_path}, but got {storage.fetch_ext(result)}'"
        assert os.path.getsize(storage.fetch_ext(result)) > 0, f"{tool[1]} Scan report is empty, expected to find a non-empty file at {expected_path}, but got an empty file"