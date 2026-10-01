"""Rule: weak-crypto — broken algorithms and misused cipher parameters."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from ..findings import Severity
from .base import LANGUAGES, Match, Rule, RuleOptions, TextDetector, TreeDetector
from .textutils import LinePattern, iter_matches

__all__ = ["weak_crypto"]

_RULE_ID = "weak-crypto"

#: Hashes that are broken for security use, with the reason shown to users.
WEAK_HASHES = {
    "md5": "MD5 has known collision attacks",
    "md4": "MD4 has known collision attacks",
    "sha1": "SHA-1 has known collision attacks",
    "sha": "the legacy SHA family has known collision attacks",
    "ripemd160": "RIPEMD-160 is no longer considered collision resistant",
}

#: Ciphers with broken structure or key length.
WEAK_CIPHERS = {
    "des": "DES has a 56-bit key that can be brute-forced",
    "des-ede3": "3DES is slow and weaker than modern ciphers",
    "3des": "3DES is slow and weaker than modern ciphers",
    "rc2": "RC2 is obsolete",
    "rc4": "RC4 has known biases and is broken",
    "blowfish": "Blowfish has a 64-bit block size and short keys",
    "idea": "IDEA is obsolete",
}

MESSAGE_HASH = "This code hashes data with {name}, and {reason}."
MESSAGE_CIPHER = "This code encrypts with {name}, and {reason}."
MESSAGE_ECB = "This code uses ECB mode, which encrypts identical blocks into identical ciphertext."
MESSAGE_IV = (
    "This code hardcodes an initialization vector (IV), which must be random and "
    "unique per message."
)
MESSAGE_FAST_HASH = "This code hashes a password with {name}, which is far too fast for passwords."

FIX_HASH = (
    'Use a password KDF instead: hashlib.pbkdf2_hmac("sha256", password, salt, 600_000), '
    "argon2-cffi's PasswordHasher, or bcrypt.hashpw(password, bcrypt.gensalt()). "
    "For non-password data use SHA-256 or better."
)
FIX_CIPHER = "Switch to AES-GCM or ChaCha20-Poly1305 via the cryptography package."
FIX_ECB = "Use an authenticated mode such as AESGCM(key).encrypt(nonce, data, aad)."
FIX_IV = (
    "Generate a fresh random IV per message: iv = os.urandom(16) and store it with the ciphertext."
)

#: Names that indicate a password is being hashed rather than ordinary data.
PASSWORD_CONTEXT = re.compile(r"(?i)(password|passwd|pwd|secret|credential)")


def _attribute_or_name(node: ast.AST) -> str:
    """``hashlib.md5`` -> ``md5``; ``md5(...)`` -> ``md5``."""
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _detect_python(tree: ast.AST, source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    lines = source.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _attribute_or_name(node.func).lower()
            if not name:
                continue
            argument = _plain_string_argument(node)
            if name in WEAK_HASHES:
                context = _line_context(lines, node.lineno)
                on_password = PASSWORD_CONTEXT.search(argument or "") or PASSWORD_CONTEXT.search(
                    context
                )
                if on_password:
                    message = (
                        MESSAGE_HASH.format(name=name.upper(), reason=WEAK_HASHES[name])
                        + " It also appears to be used on a password."
                    )
                    yield _match(node, message, FIX_HASH)
                else:
                    message = MESSAGE_HASH.format(name=name.upper(), reason=WEAK_HASHES[name])
                    yield _match(node, message, FIX_HASH)
            elif name in WEAK_CIPHERS:
                message = MESSAGE_CIPHER.format(name=name.upper(), reason=WEAK_CIPHERS[name])
                yield _match(node, message, FIX_CIPHER)
            elif name.lower().endswith("ecb") or name == "MODE_ECB":
                yield _match(node, MESSAGE_ECB, FIX_ECB)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value.strip()
            if re.fullmatch(r"(?i)(aes|des|3des)-ecb", text):
                yield _match(node, MESSAGE_ECB, FIX_ECB)
        elif isinstance(node, ast.Assign):
            yield from _detect_iv(node)


def _detect_iv(node: ast.Assign) -> Iterator[Match]:
    """``iv = b"0123456789abcdef"`` — a fixed initialization vector."""
    if not (isinstance(node.value, ast.Constant) and isinstance(node.value.value, (str, bytes))):
        return
    raw = node.value.value
    if isinstance(raw, str):
        try:
            raw = raw.encode("latin-1")
        except UnicodeEncodeError:
            return
    names = [target.id for target in getattr(node, "targets", []) if isinstance(target, ast.Name)]
    for name in names:
        if name.lower() not in {"iv", "init_vector", "initialization_vector", "nonce", "salt"}:
            continue
        if len(raw) < 8:
            continue
        if raw in _KNOWN_CONSTANTS:
            continue
        yield _match(node, MESSAGE_IV, FIX_IV)


#: Byte strings that are not real IVs (repeated filler, ASCII runs, test data).
_KNOWN_CONSTANTS = frozenset(
    {
        b"0000000000000000",
        b"aaaaaaaaaaaaaaaa",
        b"0123456789abcdef",
        b"fedcba9876543210",
        b"\x00" * 16,
    }
)


def _plain_string_argument(node: ast.Call) -> str | None:
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
    return None


def _line_context(lines: list[str], lineno: int) -> str:
    return lines[lineno - 1] if 0 < lineno <= len(lines) else ""


def _match(node: ast.AST, message: str, fix: str) -> Match:
    return Match(
        line=getattr(node, "lineno", 1),
        col=getattr(node, "col_offset", 0) + 1,
        message=message,
        fix=fix,
    )


_JS_WEAK = re.compile(
    r"(?i)\b(?:createHash|createHmac)\s*\(\s*['\"](?P<algo>md5|md4|sha1|sha)['\"]|"
    r"\b(?:des|des-ede3|3des|rc4|blowfish|idea)[-_]?(?:cbc|ecb)?\b|"
    r"(?P<mode>aes-\d+-ecb|MODE_ECB)"
)
_JS_IV = re.compile(
    r"(?i)\b(?P<name>iv|nonce|initVector|initializationVector)\s*[:=]\s*['\"](?P<value>[0-9a-f]{16,})['\"]"
)


def _detect_javascript(source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    patterns = [
        LinePattern(
            _JS_WEAK,
            "JavaScript uses {match}, a weak or obsolete cryptographic primitive.",
            FIX_HASH,
        ),
        LinePattern(
            _JS_IV,
            "JavaScript hardcodes an initialization vector named '{name}', which must "
            "be random per message.",
            FIX_IV,
        ),
    ]
    seen: set[int] = set()
    for spec in iter_matches(source, patterns):
        if spec.line in seen:
            continue
        seen.add(spec.line)
        yield Match(
            line=spec.line,
            col=spec.col,
            message=spec.message,
            fix=spec.fix,
            data=dict(spec.data),
        )


def _detect_config(source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    weak_setting = re.compile(
        r"(?i)\b(?P<key>[a-z_]*(?:hash|cipher|algorithm|algo)[a-z_]*)\s*[:=]\s*"
        r"[\"']?(?P<value>md5|sha1|des|3des|rc4|ecb)"
    )
    patterns = [
        LinePattern(
            weak_setting,
            "Configuration sets {key} to {value}, a weak or obsolete algorithm.",
            FIX_HASH,
        ),
    ]
    for spec in iter_matches(source, patterns):
        yield Match(
            line=spec.line,
            col=spec.col,
            message=spec.message,
            fix=spec.fix,
            data=dict(spec.data),
        )


weak_crypto = Rule(
    id=_RULE_ID,
    title="Weak cryptographic algorithm or parameter",
    severity=Severity.MEDIUM,
    languages=LANGUAGES,
    summary=(
        "An obsolete cipher or hash is used, or a cipher parameter must be random but is fixed."
    ),
    detectors={
        "python": TreeDetector(_detect_python),
        "javascript": TextDetector(_detect_javascript),
        "config": TextDetector(_detect_config),
    },
    cwe="CWE-327",
    references=(
        "https://cwe.mitre.org/data/definitions/327.html",
        "https://owasp.org/www-project-top-ten/A02-2021-Cryptographic-Failures/",
    ),
)
