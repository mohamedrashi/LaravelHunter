import socket

import pytest

from laravelhunter.waf_lab import assert_private_lab_target, build_benign_variants


def test_loopback_allowed():
    assert_private_lab_target("http://127.0.0.1:8000/")


def test_private_ip_allowed():
    assert_private_lab_target("http://192.168.56.10/")


def test_public_ip_rejected():
    with pytest.raises(ValueError, match="refuses public Internet targets"):
        assert_private_lab_target("https://1.1.1.1/")


def test_variants_are_get_safe_and_benign():
    variants = build_benign_variants("http://127.0.0.1:8000/admin")
    assert len(variants) >= 5
    names = {x[0] for x in variants}
    assert "baseline" in names
    for _, url, headers in variants:
        assert url.startswith("http://127.0.0.1:8000/admin")
        assert all("lh" in k.lower() for k in headers.keys()) or not headers
