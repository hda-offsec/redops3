import pytest
from scan_engine.helpers.output_parsers import parse_nmap_open_ports

def test_parse_nmap_open_ports_standard():
    nmap_output = """
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-27 10:00 UTC
Nmap scan report for 127.0.0.1
Host is up (0.000052s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
443/tcp open  ssl/http Apache httpd 2.4.41 ((Ubuntu))

Nmap done: 1 IP address (1 host up) scanned in 0.22 seconds
"""
    expected = [
        {"port": 80, "service_name": "http", "version": "Apache httpd 2.4.41 ((Ubuntu))"},
        {"port": 443, "service_name": "ssl/http", "version": "Apache httpd 2.4.41 ((Ubuntu))"}
    ]
    assert parse_nmap_open_ports(nmap_output) == expected

def test_parse_nmap_open_ports_no_version():
    nmap_output = """
PORT   STATE SERVICE
22/tcp open  ssh
"""
    expected = [
        {"port": 22, "service_name": "ssh", "version": None}
    ]
    assert parse_nmap_open_ports(nmap_output) == expected

def test_parse_nmap_open_ports_udp():
    nmap_output = """
PORT    STATE SERVICE VERSION
53/udp  open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
67/udp  open  dhcps   ISC DHCP 4.4.1
"""
    expected = [
        {"port": 53, "service_name": "domain", "version": "ISC BIND 9.16.1 (Ubuntu Linux)"},
        {"port": 67, "service_name": "dhcps", "version": "ISC DHCP 4.4.1"}
    ]
    assert parse_nmap_open_ports(nmap_output) == expected

def test_parse_nmap_open_ports_no_open_ports():
    nmap_output = """
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-27 10:00 UTC
Nmap scan report for 127.0.0.1
Host is up (0.000052s latency).
All 1000 scanned ports on 127.0.0.1 are in ignored states.
Not shown: 1000 closed ports

Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds
"""
    expected = []
    assert parse_nmap_open_ports(nmap_output) == expected

def test_parse_nmap_open_ports_mixed_states():
    nmap_output = """
PORT     STATE    SERVICE
21/tcp   closed   ftp
22/tcp   open     ssh
23/tcp   filtered telnet
80/tcp   open     http
"""
    expected = [
        {"port": 22, "service_name": "ssh", "version": None},
        {"port": 80, "service_name": "http", "version": None}
    ]
    assert parse_nmap_open_ports(nmap_output) == expected

def test_parse_nmap_open_ports_empty_input():
    assert parse_nmap_open_ports("") == []

def test_parse_nmap_open_ports_malformed_input():
    nmap_output = """
This is not a valid nmap output
Some random text 123/tcp open service
But maybe it still matches?
1234/tcp open service version info
"""
    expected = [
        {"port": 123, "service_name": "service", "version": None},
        {"port": 1234, "service_name": "service", "version": "version info"}
    ]
    assert parse_nmap_open_ports(nmap_output) == expected
