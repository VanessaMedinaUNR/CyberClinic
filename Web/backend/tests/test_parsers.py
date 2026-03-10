"""
Cyber Clinic - Unit tests for scan result parsers

Run from inside the backend-dev container:
    docker exec -u root cyberclinic-backend-dev pytest tests/test_parsers.py -v
"""

import os
import sys
import shutil
from pathlib import Path
import textwrap
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from app.parsers.nmap_parser import NmapParser


#minimal Nmap XML fixture with one host and one open port
NMAP_XML = textwrap.dedent("""\
    <?xml version="1.0"?>
    <nmaprun scanner="nmap" version="7.94" args="nmap -sV -p 80">
      <host>
        <status state="up" reason="echo-reply"/>
        <address addr="45.33.32.156" addrtype="ipv4"/>
        <hostnames>
          <hostname name="scanme.nmap.org" type="user"/>
        </hostnames>
        <ports>
          <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="Apache httpd" version="2.4.7"/>
          </port>
        </ports>
      </host>
    </nmaprun>
""")

#session level fixture with temp directory shared across all tests
@pytest.fixture(scope='session')
def setup_parsers(request):
    temp_dir = os.path.join('tests', 'temp')
    Path(temp_dir).mkdir(parents=True, exist_ok=True)

    nmap_file = os.path.join(temp_dir, 'nmap_fixture.xml')
    with open(nmap_file, 'w') as f: f.write(NMAP_XML)

    def teardown():
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass
    request.addfinalizer(teardown)

    return {
        'nmap_file':   nmap_file,
        'nmap_parser': NmapParser(),
    }


#nmap parser unit tests
class TestNmapParser:

    def testParseReturnsSuccess(self, setup_parsers):
        result = setup_parsers['nmap_parser'].parse_xml(setup_parsers['nmap_file'])
        assert result['success'] == True, \
            f"Expected success=True, got {result['success']}"

    def testHostCount(self, setup_parsers):
        result = setup_parsers['nmap_parser'].parse_xml(setup_parsers['nmap_file'])
        assert result['total_hosts'] == 1, \
            f"Expected 1 host, got {result['total_hosts']}"

    def testOpenPortCount(self, setup_parsers):
        result = setup_parsers['nmap_parser'].parse_xml(setup_parsers['nmap_file'])
        assert result['total_open_ports'] == 1, \
            f"Expected 1 open port, got {result['total_open_ports']}"

    def testHostIpExtracted(self, setup_parsers):
        result = setup_parsers['nmap_parser'].parse_xml(setup_parsers['nmap_file'])
        ip = result['hosts'][0]['ip']
        assert ip == '45.33.32.156', \
            f"Expected IP '45.33.32.156', got '{ip}'"

    def testFindingsListPresent(self, setup_parsers):
        result = setup_parsers['nmap_parser'].parse_xml(setup_parsers['nmap_file'])
        assert isinstance(result['findings'], list), \
            f"Expected findings to be a list, got {type(result['findings'])}"


# Done by Manuel Morales-Marroquin