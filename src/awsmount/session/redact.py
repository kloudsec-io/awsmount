"""Secret redaction applied at render time (ARCHITECTURE: Masking)."""

from __future__ import annotations

import copy
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from awsmount.vfs.render import JSONValue

__all__ = [
    "ENV_KEY_RE",
    "REDACTED",
    "RULES",
    "SAFE_KEYS",
    "SAFE_SUFFIXES",
    "SECRET_KEY_RE",
    "SECRET_NAME_RE",
    "TAG_KEYS",
    "WHOLE_RULES",
    "RedactionPolicy",
    "is_secret_key",
    "is_secret_name",
]

REDACTED = "<hidden>"

SECRET_KEY_RE = re.compile(
    r"(?i)(password|passwd|secret|token|private_?key|credential|api_?key)")
"""Generic heuristic: dict keys whose string values look secret."""

SECRET_NAME_RE = re.compile(
    r"(?i)(password|passwd|pass|pwd|psk|secret|token|private_?key"
    r"|credential|api_?key|webhook|signing|salt|keys?$)")
"""Wider heuristic for user-chosen names (CloudFormation parameter and
output keys such as ``DBPass``, ``AdminPwd`` or ``SlackWebhookKey``).

It is used by ``[?K~SECRET_NAME]`` filters only. Over-redacting a value
under a user-chosen name is cheap; leaking a secret is not."""

SAFE_SUFFIXES: tuple[str, ...] = (
    "Arn", "ARN", "Id", "Ids", "Name", "Type", "Status", "Enabled", "Date",
    "Time", "Version", "Policy", "Required", "Length", "Count", "Age",
    "Used", "Rotation", "Configuration")
"""Key suffixes exempted from the generic heuristic."""

SAFE_KEYS: frozenset[str] = frozenset({
    # EC2 IMDS setting ("required" or "optional"): security-relevant
    # configuration that users need to see, not a credential.
    "httptokens",
    # Pagination cursors are not secrets. (Client/idempotency tokens stay
    # hidden: over-hiding one costs users nothing, a leak costs a lot.)
    "nexttoken", "nextcontinuationtoken", "continuationtoken",
    "paginationtoken",
})
"""Exact keys (lowercased) that look secret by name but are not."""

ENV_KEY_RE = re.compile(r"(?i)^environment(variables)?$")
"""Keys holding ``[{Name, Value}]`` environment lists."""

TAG_KEYS = frozenset({"Tags", "tags", "TagList", "TagSet", "tagSet"})
"""Tag containers; tag values are never redacted (ARCHITECTURE: Masking)."""

RULES: Mapping[str, tuple[str, ...]] = {
    "lambda": ("Environment.Variables.*",),
    "ecs-taskdef": (
        "taskDefinition.containerDefinitions[].environment[].value",),
    "rds": ("MasterUserPassword",),
    "iam": ("[].SecretAccessKey",),
    "cfn-params": (
        "Parameters[?ParameterKey~SECRET_NAME].ParameterValue",
        "[?ParameterKey~SECRET_NAME].ParameterValue",
        "Outputs[?OutputKey~SECRET_NAME].OutputValue",
        "[?OutputKey~SECRET_NAME].OutputValue",
    ),
    "apigw-stages": ("item[].variables.*",),
    "sns": ("[?Protocol=http].Endpoint", "[?Protocol=https].Endpoint"),
    "cloudfront": ("**.CustomHeaders.Items[].HeaderValue",),
    "elbv2-listeners": (
        "[].DefaultActions[].AuthenticateOidcConfig.ClientSecret",),
    "secrets": ("SecretString", "SecretBinary"),
    "ssm": ("Value",),
    "eks": ("cluster.connectorConfig.activationCode",),
    "eks-addon": ("addon.configurationValues",),
    "elbv2-listener": (
        "DefaultActions[].AuthenticateOidcConfig.ClientSecret",),
    "elbv2-rule": ("Actions[].AuthenticateOidcConfig.ClientSecret",),
    "sfn": ("definition",),
    "eventbridge-targets": (
        "[].Input",
        "[].HttpParameters.HeaderParameters.*",
        "[].HttpParameters.QueryStringParameters.*",
    ),
}
"""JSON rule sets: rule id -> path patterns."""

WHOLE_RULES = frozenset({"user-data", "template"})
"""Whole-file rules: the file is replaced and never fetched."""

_TOKEN_RE = re.compile(r"\[\]|\[\?[^\]]*\]|[^.\[\]]+")

_CONDITION_RES: Mapping[str, re.Pattern[str]] = {
    "SECRET": SECRET_KEY_RE,
    "SECRET_NAME": SECRET_NAME_RE,
}


def _tokens(pattern: str) -> tuple[str, ...]:
    """Split a rule pattern into path tokens."""
    return tuple(_TOKEN_RE.findall(pattern))


_COMPILED: dict[str, tuple[tuple[str, ...], ...]] = {
    rule: tuple(_tokens(p) for p in patterns)
    for rule, patterns in RULES.items()
}


def is_secret_key(key: str) -> bool:
    """True when ``key`` matches the generic secret heuristic."""
    if key.endswith(SAFE_SUFFIXES) or key.lower() in SAFE_KEYS:
        return False
    return SECRET_KEY_RE.search(key) is not None


def is_secret_name(name: str) -> bool:
    """True when a user-chosen name (CFN parameter/output) looks secret."""
    return SECRET_NAME_RE.search(name) is not None


def _condition(token: str) -> Callable[[dict[str, Any]], bool]:
    """Compile a ``[?K=V]``, ``[?K~SECRET]`` or ``[?K~SECRET_NAME]``.

    An unknown ``~KIND`` fails closed: every string value matches.
    """
    body = token[2:-1]
    if "~" in body:
        field, _, kind = body.partition("~")
        regex = _CONDITION_RES.get(kind.strip())

        def regex_match(item: dict[str, Any]) -> bool:
            value = item.get(field)
            if not isinstance(value, str):
                return False
            if regex is None:
                return True
            return regex.search(value) is not None
        return regex_match
    field, _, expected = body.partition("=")

    def equals(item: dict[str, Any]) -> bool:
        value = item.get(field)
        return value is not None and str(value) == expected
    return equals


def _apply(obj: Any, tokens: tuple[str, ...]) -> Any:
    """Redact, in place, every value of ``obj`` matched by ``tokens``."""
    if not tokens:
        return REDACTED
    tok, rest = tokens[0], tokens[1:]
    if tok == "**":
        obj = _apply(obj, rest)
        if isinstance(obj, dict):
            for k in list(obj):
                obj[k] = _apply(obj[k], tokens)
        elif isinstance(obj, list):
            for idx, value in enumerate(obj):
                obj[idx] = _apply(value, tokens)
        return obj
    if tok == "[]":
        if isinstance(obj, list):
            for idx, value in enumerate(obj):
                obj[idx] = _apply(value, rest)
        return obj
    if tok.startswith("[?"):
        if isinstance(obj, list):
            cond = _condition(tok)
            for idx, value in enumerate(obj):
                if isinstance(value, dict) and cond(value):
                    obj[idx] = _apply(value, rest)
        return obj
    if not isinstance(obj, dict):
        return obj
    if tok == "*":
        for k in list(obj):
            obj[k] = _apply(obj[k], rest)
    elif tok in obj:
        obj[tok] = _apply(obj[tok], rest)
    return obj


def _redact_env_list(items: list[Any]) -> None:
    """Replace values of ``[{Name, Value}]`` style elements."""
    for element in items:
        if not isinstance(element, dict):
            continue
        for name, value in (("Name", "Value"), ("name", "value")):
            if name in element and value in element:
                element[value] = REDACTED


def _generic(obj: Any) -> None:
    """Apply the always-on heuristics in place (tags are skipped)."""
    if isinstance(obj, dict):
        for key in list(obj):
            value = obj[key]
            if not isinstance(key, str):
                _generic(value)
                continue
            if key in TAG_KEYS:
                continue
            if isinstance(value, str):
                if (value and not value.startswith("arn:")
                        and is_secret_key(key)):
                    obj[key] = REDACTED
                continue
            if isinstance(value, list) and ENV_KEY_RE.match(key):
                _redact_env_list(value)
            _generic(value)
    elif isinstance(obj, list):
        for value in obj:
            _generic(value)


@dataclass(frozen=True)
class RedactionPolicy:
    """Render-time redaction; ``reveal=True`` disables everything."""

    reveal: bool

    def json(self, rule_set: str | None, data: JSONValue) -> JSONValue:
        """Return a redacted deep copy of ``data`` (input untouched)."""
        if self.reveal:
            return data
        out: Any = copy.deepcopy(data)
        if rule_set is not None:
            for tokens in _COMPILED.get(rule_set, ()):
                out = _apply(out, tokens)
        _generic(out)
        result: JSONValue = out
        return result

    def whole_file(self, rule_id: str) -> bool:
        """True => emit REDACTED and make no API call.

        Unknown rule ids fail closed (treated as whole-file rules).
        """
        if self.reveal:
            return False
        return rule_id in WHOLE_RULES or rule_id not in RULES

    def text(self, rule_id: str, value: str | bytes) -> str | bytes:
        """Redact a text value under a whole-file rule."""
        if self.whole_file(rule_id):
            return REDACTED
        return value
