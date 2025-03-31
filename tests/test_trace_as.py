import pytest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'tasks')))

from trace_as import resolve_host, extract_ips, whois_lookup

def test_resolve_host_valid():
    ip = resolve_host("example.com")
    assert isinstance(ip, str)
    assert ip.count('.') == 3

def test_resolve_host_invalid(monkeypatch):
    with pytest.raises(SystemExit):
        resolve_host("nonexistent.domain.test")

def test_extract_ips():
    sample_output = [
        " 1  192.168.0.1",
        " 2  203.0.113.1",
        " 3  *** Request timed out."
    ]
    ips = extract_ips(sample_output)
    assert ips == ["192.168.0.1", "203.0.113.1"]

def test_whois_lookup_format():
    asn, country, provider = whois_lookup("8.8.8.8")
    assert isinstance(asn, str)
    assert isinstance(country, str)
    assert isinstance(provider, str)
