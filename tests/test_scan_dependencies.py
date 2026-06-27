from tools.scan_dependencies import scan_dependencies


def test_scan_dependencies_finds_fixture_cves():
    result = scan_dependencies(["dummy-infra/deps"], strict=True)
    high_plus = [f for f in result.findings if f.severity in {"CRITICAL", "HIGH"}]
    assert len(high_plus) >= 1
    assert all(f.resource.startswith("dummy-infra/deps/") for f in high_plus)


def test_scan_dependencies_clean_app_manifest():
    result = scan_dependencies(["requirements.txt"], strict=False)
    high_plus = [f for f in result.findings if f.severity in {"CRITICAL", "HIGH"}]
    assert high_plus == []
