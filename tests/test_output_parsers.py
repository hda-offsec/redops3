import pytest
from scan_engine.helpers.output_parsers import parse_nmap_open_ports

def test_parse_nmap_open_ports_single_port():
    nmap_output = """
Starting Nmap 7.92 ( https://nmap.org ) at 2024-05-15 10:00 UTC
Nmap scan report for 192.168.1.10
Host is up (0.0010s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
MAC Address: 00:11:22:33:44:55 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.52 seconds
"""
    expected = [
        {"port": 80, "service_name": "http", "version": "Apache httpd 2.4.41 ((Ubuntu))"}
    ]
    assert parse_nmap_open_ports(nmap_output) == expected

def test_parse_nmap_open_ports_multiple_ports():
    nmap_output = """
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
443/tcp  open  ssl/http Apache httpd 2.4.41 ((Ubuntu))
"""
    expected = [
        {"port": 22, "service_name": "ssh", "version": "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)"},
        {"port": 80, "service_name": "http", "version": "Apache httpd 2.4.41 ((Ubuntu))"},
        {"port": 443, "service_name": "ssl/http", "version": "Apache httpd 2.4.41 ((Ubuntu))"},
    ]
    assert parse_nmap_open_ports(nmap_output) == expected

def test_parse_nmap_open_ports_mixed_states():
    nmap_output = """
PORT     STATE    SERVICE    VERSION
21/tcp   closed   ftp
22/tcp   open     ssh        OpenSSH 7.6p1
80/tcp   filtered http
"""
    expected = [
        {"port": 22, "service_name": "ssh", "version": "OpenSSH 7.6p1"}
    ]
    assert parse_nmap_open_ports(nmap_output) == expected

def test_parse_nmap_open_ports_udp():
    nmap_output = """
PORT     STATE SERVICE VERSION
53/udp   open  domain  dnsmasq 2.78
"""
    expected = [
        {"port": 53, "service_name": "domain", "version": "dnsmasq 2.78"}
    ]
    assert parse_nmap_open_ports(nmap_output) == expected

def test_parse_nmap_open_ports_empty():
    nmap_output = ""
    assert parse_nmap_open_ports(nmap_output) == []

def test_parse_nmap_open_ports_malformed():
    nmap_output = """
Invalid line
Another invalid line
80/tcp closed http
"""
    assert parse_nmap_open_ports(nmap_output) == []

def test_parse_nmap_open_ports_no_version():
    nmap_output = """
PORT     STATE SERVICE VERSION
8080/tcp open  http-proxy
"""
    expected = [
        {"port": 8080, "service_name": "http-proxy", "version": None}
    ]
    assert parse_nmap_open_ports(nmap_output) == expected
