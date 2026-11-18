import pytest
from backend.app.analyzers.c2_analyzer import (
    analyze_c2_infrastructure, is_potential_dga
)
from backend.app.analyzers.reverseshell_analyzer import analyze_reverse_shell_indicators

def test_dga_heuristic():
    assert is_potential_dga("x7q89amzxclqp1982b.biz") is True
    assert is_potential_dga("google.com") is False
    assert is_potential_dga("microsoft.com") is False

def test_c2_classification_and_reconstruction():
    urls = [
        {"url": "http://trojan-beacon.duckdns.org:4444/gate.php", "source": "classes.dex"},
        {"url": "https://www.google.com/search", "source": "classes.dex"}
    ]
    ips = [
        {"ip": "198.51.100.45", "is_private": False, "source": "classes.dex"}
    ]
    domains = [
        {"domain": "trojan-beacon.duckdns.org", "source": "classes.dex", "is_ddns": True}
    ]
    decoded = [
        {"original": "aHR0cDovL2JhY2t1cC1jMi5kdWNrZG5zLm9yZw==", "decoded": "http://backup-c2.duckdns.org", "transformation": "Base64", "source": "classes.dex"}
    ]
    dex_methods = [
        "com/malware/BeaconManager->sendPost()V",
        "trojan-beacon.duckdns.org in HTTP connection"
    ]

    indicators = analyze_c2_infrastructure(urls, ips, domains, decoded, dex_methods)
    classifications = [ind.classification for ind in indicators]

    # Duckdns URL with non-standard port 4444 should be potential_c2
    assert "potential_c2" in classifications
    # Google should be classified as third_party
    assert "third_party" in classifications

def test_reverse_shell_chain_detection():
    # Complete interactive reverse shell chain
    methods = [
        "Lcom/shell/ReverseShell;->connectSocket(Ljava/lang/String;I)V",
        "java/net/Socket->getInputStream",
        "java/net/Socket->getOutputStream",
        "Runtime;->exec",
        "ProcessBuilder",
        "Process->getInputStream",
        "Process->getOutputStream"
    ]
    strings = [
        "/system/bin/sh",
        "4444",
        "java/net/Socket"
    ]

    findings = analyze_reverse_shell_indicators(methods, strings, [])
    assert len(findings) > 0
    assert any("Reverse-Shell" in f.title for f in findings)
    assert any(f.severity == "Critical" for f in findings)
