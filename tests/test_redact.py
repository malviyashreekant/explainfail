from explainfail.redact import PLACEHOLDER, redact


def test_key_value_secret_is_hidden_but_key_kept():
    out, n = redact("connecting with password=Sup3rS3cret! now")
    assert "Sup3rS3cret" not in out
    assert "password=" in out and PLACEHOLDER in out
    assert n == 1


def test_url_credentials_keep_user_and_host():
    out, n = redact("postgresql://etl:hunter2@db.internal:5432/sales")
    assert "hunter2" not in out
    assert "etl:***@db.internal:5432" in out
    assert n == 1


def test_bearer_token():
    out, _ = redact("Authorization: Bearer abcdefghijklmnop1234")
    assert "abcdefghijklmnop1234" not in out


def test_quoted_secret():
    out, _ = redact('api_key: "abc 123 def"')
    assert "abc 123" not in out


def test_provider_tokens():
    samples = [
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_" + "a" * 36,
        "xoxb-1234567890-abcdefghij",
        "sk-" + "A1b2C3d4" * 4,
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk",
    ]
    for s in samples:
        out, n = redact(f"token was {s} ok")
        assert s not in out, s
        assert n >= 1


def test_email_and_private_key():
    out, _ = redact("contact bob@example.com")
    assert "bob@example.com" not in out and "<email>" in out
    key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEabcDEF\n-----END RSA PRIVATE KEY-----"
    out, _ = redact(f"x\n{key}\ny")
    assert "MIIEabcDEF" not in out


def test_ips_only_hidden_when_asked():
    text = "connect to 10.2.3.4 failed"
    assert redact(text)[0] == text
    out, n = redact(text, redact_ips=True)
    assert "10.2.3.4" not in out and n == 1


def test_ordinary_error_text_is_untouched():
    for text in (
        "Connection refused to db.internal:5432",
        'FATAL:  password authentication failed for user "etl"',
        "NoCredentialsError: Unable to locate credentials",
        "ExpiredToken when calling PutObject",
    ):
        out, n = redact(text)
        assert out == text and n == 0, text


def test_empty_input():
    assert redact("") == ("", 0)
