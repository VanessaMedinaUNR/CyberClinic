import os.path
import sys

# Expand sys.path with PyInstaller source.
_ROOT_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
sys.path.append(_ROOT_DIR)

def pytest_addoption(parser):
    parser.addoption(
        "--server-host",
        type=str,
        action="store",
        default="localhost",
        help="Cyberclinic server address"
    )

    parser.addoption(
        "--auth-port",
        type=int,
        action="store",
        default=6666,
        help="Server authenication port"
    )

    parser.addoption(
        "--authed-port",
        type=int,
        action="store",
        default=9999,
        help="Server authenticated communication port"
    )

    parser.addoption(
        "--username",
        type=str,
        action="store",
        default="dev@cyberclinic.com",
        help="Username for authentication"
    )

    parser.addoption(
        "--password",
        type=str,
        action="store",
        default="dev_pass",
        help="Password for authentication"
    )

def pytest_generate_tests(metafunc):
        if "tool" in metafunc.fixturenames:
            from tests.unit.test_scanner import ensure_tools
            idlist = []
            argvalues = []
            tool_info = (ensure_tools(metafunc.cls.tool_list))
            for tool in metafunc.cls.tool_list:
                idlist.append(tool)
                argnames = ['tool']
                argvalues.append([tool_info[tool]])
            metafunc.parametrize(argnames, argvalues, ids=idlist, scope="class")