"""Redaction of sensitive values (passwords, tokens, keys, ...) from config file text."""

import re

REDACTED = "***REDACTED***"

_SENSITIVE_KEYWORD = (
    r"(?:password|passwd|pwd|secret|token|api[_.-]?key|"
    r"access[_.-]?key|private[_.-]?key|credential(?:s)?)"
)

# key=value / key: value lines, e.g. properties files, server.env, jvm.options (-Dkey=value)
_KV_RE = re.compile(
    rf"(?im)^(?P<prefix>[ \t]*(?:-D)?[\w.\-]*{_SENSITIVE_KEYWORD}[\w.\-]*[ \t]*[:=][ \t]*)(?P<value>.*)$"
)

# One XML/HTML-style start or self-closing tag, e.g. <variable name="db.password" value="x"/>
_TAG_RE = re.compile(r"<[^/!?][^>]*>")

# Individual attr="value" pairs inside a tag.
_ATTR_RE = re.compile(r'([\w.\-:]+)\s*=\s*"([^"]*)"')


def _redact_tag(tag: str) -> str:
    attrs = _ATTR_RE.findall(tag)
    if not attrs:
        return tag

    # Redact when either the attribute's own name is sensitive (password="x"), or another
    # attribute on the same tag names a sensitive setting (Liberty's name="x.password" value="y").
    tag_is_sensitive = any(
        re.search(_SENSITIVE_KEYWORD, name, re.IGNORECASE) or re.search(_SENSITIVE_KEYWORD, value, re.IGNORECASE)
        for name, value in attrs
    )
    if not tag_is_sensitive:
        return tag

    redacted = tag
    for name, value in attrs:
        if not value:
            continue
        if name.lower() == "value" or re.search(_SENSITIVE_KEYWORD, name, re.IGNORECASE):
            redacted = re.sub(
                rf'({re.escape(name)}\s*=\s*"){re.escape(value)}(")',
                rf"\1{REDACTED}\2",
                redacted,
                count=1,
            )
    return redacted


def sanitize(text: str) -> str:
    """Redact values on lines/attributes whose key looks security-sensitive."""
    text = _TAG_RE.sub(lambda m: _redact_tag(m.group(0)), text)
    text = _KV_RE.sub(
        lambda m: f"{m.group('prefix')}{REDACTED}" if m.group("value").strip() else m.group(0),
        text,
    )
    return text
