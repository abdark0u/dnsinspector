import pytest

from dnsinspector.validation import (
    ValidationError,
    normalize_domain,
    normalize_selector,
    parse_public_ip,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM", "example.com"),
        ("  example.com.  ", "example.com"),
        ("sub.domain.co.uk", "sub.domain.co.uk"),
        ("münchen.de", "xn--mnchen-3ya.de"),
        ("xn--mnchen-3ya.de", "xn--mnchen-3ya.de"),
    ],
)
def test_valid_domains(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "localhost",
        "example",
        "https://example.com",
        "example.com/path",
        "user@example.com",
        "-bad.com",
        "bad-.com",
        "exa mple.com",
        "ex;ample.com",
        "1.2.3.4",
        "a" * 64 + ".com",
        ".".join(["abcdefghi"] * 30) + ".com",
        "printer.local",
        "server.internal",
        "router.home.arpa",
        "$(whoami).com",
    ],
)
def test_invalid_domains(raw):
    with pytest.raises(ValidationError):
        normalize_domain(raw)


@pytest.mark.parametrize("raw", ["google", "s1", "selector_2024", "k1.mail", "Default"])
def test_valid_selectors(raw):
    assert normalize_selector(raw) == raw.lower()


@pytest.mark.parametrize("raw", ["", "bad selector", "sel;rm", "a/b", "x" * 200])
def test_invalid_selectors(raw):
    with pytest.raises(ValidationError):
        normalize_selector(raw)


def test_public_ip():
    assert parse_public_ip("8.8.8.8") == "8.8.8.8"
    assert parse_public_ip("2606:4700:4700::1111") == "2606:4700:4700::1111"
    assert parse_public_ip("example.com") is None


@pytest.mark.parametrize("raw", ["10.0.0.1", "192.168.1.1", "127.0.0.1", "::1", "169.254.1.1"])
def test_private_ip_rejected(raw):
    with pytest.raises(ValidationError):
        parse_public_ip(raw)
