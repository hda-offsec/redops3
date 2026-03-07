import hashlib
import json
import re
from datetime import datetime
from urllib.parse import parse_qsl, urlparse

SENSITIVE_HEADER_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "proxy-authorization",
}

AUTH_ROUTE_HINTS = (
    "login",
    "logout",
    "register",
    "signup",
    "reset",
    "forgot",
    "refresh",
    "session",
    "auth",
    "token",
)

JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


def _normalize_str(value):
    if value is None:
        return ""
    return str(value)


def _truncate_text(value, max_len=2048):
    text = _normalize_str(value)
    if len(text) <= max_len:
        return text
    return text[:max_len]


def _stable_json(value):
    if value is None:
        return ""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except Exception:
        return _normalize_str(value)


def _sha256_text(value):
    return hashlib.sha256(_normalize_str(value).encode("utf-8")).hexdigest()


def _sanitize_headers(headers):
    if not isinstance(headers, dict):
        return {}
    sanitized = {}
    for key in sorted(headers.keys()):
        val = headers.get(key)
        k = _normalize_str(key)
        if not k:
            continue
        if k.lower() in SENSITIVE_HEADER_KEYS:
            sanitized[k] = "[redacted]"
        else:
            sanitized[k] = _truncate_text(val, 512)
    return sanitized


def _sanitize_cookies(cookies):
    if not isinstance(cookies, dict):
        return {}
    sanitized = {}
    for key in sorted(cookies.keys()):
        name = _normalize_str(key)
        if not name:
            continue
        sanitized[name] = "[present]"
    return sanitized


def _extract_params(url, explicit_params=None, limit=20):
    out = {}
    if isinstance(explicit_params, dict):
        for key in sorted(explicit_params.keys()):
            if len(out) >= limit:
                break
            k = _normalize_str(key)
            if not k:
                continue
            out[k] = _truncate_text(explicit_params.get(key), 256)
    try:
        parsed = urlparse(_normalize_str(url))
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            if len(out) >= limit:
                break
            if key not in out:
                out[key] = _truncate_text(value, 256)
    except Exception:
        return out
    return out


def _response_body_summary(body, max_len=2048):
    if isinstance(body, dict) or isinstance(body, list):
        serialized = _stable_json(body)
        return {
            "kind": "json",
            "preview": _truncate_text(serialized, max_len),
            "sha256": _sha256_text(serialized),
            "length": len(serialized),
        }
    text = _normalize_str(body)
    return {
        "kind": "text",
        "preview": _truncate_text(text, max_len),
        "sha256": _sha256_text(text),
        "length": len(text),
    }


def _request_body_summary(body, max_len=1024):
    if body is None:
        return {"kind": "none", "preview": "", "sha256": _sha256_text(""), "length": 0}
    if isinstance(body, (dict, list)):
        serialized = _stable_json(body)
        return {
            "kind": "json",
            "preview": _truncate_text(serialized, max_len),
            "sha256": _sha256_text(serialized),
            "length": len(serialized),
        }
    text = _normalize_str(body)
    return {
        "kind": "text",
        "preview": _truncate_text(text, max_len),
        "sha256": _sha256_text(text),
        "length": len(text),
    }


def normalize_replay_artifact(payload):
    raw = payload if isinstance(payload, dict) else {}

    method = _normalize_str(raw.get("method") or "GET").upper()[:12]
    url = _normalize_str(raw.get("url") or raw.get("endpoint"))
    content_type = _normalize_str(raw.get("content_type") or raw.get("response_content_type"))[:255]

    request_headers = _sanitize_headers(raw.get("request_headers"))
    response_headers = _sanitize_headers(raw.get("response_headers"))
    request_cookies = _sanitize_cookies(raw.get("request_cookies") or raw.get("cookies"))

    request_body = _request_body_summary(raw.get("request_body"))
    response_body = _response_body_summary(raw.get("response_body"))

    redirect_chain = raw.get("redirect_chain") if isinstance(raw.get("redirect_chain"), list) else []
    normalized_redirects = [_truncate_text(step, 1024) for step in redirect_chain[:10]]

    status_code = raw.get("status_code")
    try:
        status_code = int(status_code) if status_code is not None else None
    except (TypeError, ValueError):
        status_code = None

    now = datetime.utcnow()
    observed_at = raw.get("observed_at")
    if isinstance(observed_at, datetime):
        ts = observed_at
    else:
        ts = now

    return {
        "method": method,
        "url": url,
        "endpoint": _truncate_text(urlparse(url).path if url else "", 2048),
        "query_params": _extract_params(url, raw.get("query_params")),
        "request_headers": request_headers,
        "request_cookies": request_cookies,
        "request_body_summary": request_body,
        "status_code": status_code,
        "response_headers": response_headers,
        "response_body_summary": response_body,
        "content_type": content_type or _normalize_str(response_headers.get("Content-Type", ""))[:255],
        "redirect_chain": normalized_redirects,
        "identity_context": raw.get("identity_context") if isinstance(raw.get("identity_context"), dict) else {},
        "provenance": raw.get("provenance") if isinstance(raw.get("provenance"), dict) else {},
        "observed_at": ts,
    }


def _json_shape(obj):
    if isinstance(obj, dict):
        out = {}
        for key in sorted(obj.keys()):
            out[key] = _json_shape(obj[key])
        return out
    if isinstance(obj, list):
        if not obj:
            return []
        return [_json_shape(obj[0])]
    return type(obj).__name__


def _json_top_level_keys(preview_text):
    try:
        parsed = json.loads(preview_text)
    except Exception:
        return set(), None
    if isinstance(parsed, dict):
        return set(parsed.keys()), _json_shape(parsed)
    return set(), _json_shape(parsed)


def _header_differences(left_headers, right_headers):
    left = left_headers if isinstance(left_headers, dict) else {}
    right = right_headers if isinstance(right_headers, dict) else {}
    keys = sorted(set(left.keys()) | set(right.keys()))
    diffs = {}
    for key in keys:
        if left.get(key) != right.get(key):
            diffs[key] = {"left": left.get(key), "right": right.get(key)}
    return diffs


def compare_replay_artifacts(left, right):
    l = normalize_replay_artifact(left)
    r = normalize_replay_artifact(right)

    l_body = l.get("response_body_summary") if isinstance(l.get("response_body_summary"), dict) else {}
    r_body = r.get("response_body_summary") if isinstance(r.get("response_body_summary"), dict) else {}

    l_preview = l_body.get("preview", "")
    r_preview = r_body.get("preview", "")

    l_keys, l_shape = _json_top_level_keys(l_preview)
    r_keys, r_shape = _json_top_level_keys(r_preview)

    added_fields = sorted(r_keys - l_keys)
    removed_fields = sorted(l_keys - r_keys)

    header_differences = _header_differences(l.get("response_headers"), r.get("response_headers"))

    same_status = l.get("status_code") == r.get("status_code")
    same_shape = l_shape == r_shape
    same_body_hash = l_body.get("sha256") == r_body.get("sha256")
    same_content_type = l.get("content_type") == r.get("content_type")

    significance = 0
    rationale_parts = []

    if not same_status:
        significance += 4
        rationale_parts.append("status_code_changed")
    if not same_content_type:
        significance += 2
        rationale_parts.append("content_type_changed")
    if not same_shape:
        significance += 2
        rationale_parts.append("body_shape_changed")
    if added_fields or removed_fields:
        significance += 1
        rationale_parts.append("json_keys_changed")
    if header_differences:
        significance += 1
        rationale_parts.append("response_headers_changed")
    if not same_body_hash:
        significance += 1
        rationale_parts.append("body_hash_changed")

    if same_body_hash:
        similarity_hint = "identical"
    elif same_shape:
        similarity_hint = "same_shape_different_values"
    else:
        similarity_hint = "different_shape"

    return {
        "same_status": same_status,
        "different_status": not same_status,
        "same_shape": same_shape,
        "different_shape": not same_shape,
        "same_content_type": same_content_type,
        "same_body_hash": same_body_hash,
        "added_fields": added_fields,
        "removed_fields": removed_fields,
        "header_differences": header_differences,
        "body_similarity_hint": similarity_hint,
        "significance_score": significance,
        "rationale": ",".join(rationale_parts) if rationale_parts else "no_significant_difference",
    }


def extract_auth_identity_observations(replay_artifact):
    normalized = normalize_replay_artifact(replay_artifact)
    endpoint = (normalized.get("endpoint") or "").lower()
    raw_headers = replay_artifact.get("request_headers") if isinstance(replay_artifact, dict) else {}
    request_headers = raw_headers if isinstance(raw_headers, dict) else (normalized.get("request_headers") if isinstance(normalized.get("request_headers"), dict) else {})
    response_headers = normalized.get("response_headers") if isinstance(normalized.get("response_headers"), dict) else {}
    cookies = normalized.get("request_cookies") if isinstance(normalized.get("request_cookies"), dict) else {}

    route_hints = sorted([hint for hint in AUTH_ROUTE_HINTS if hint in endpoint])

    bearer_present = False
    bearer_token_preview = ""
    jwt_like = False

    auth_header = _normalize_str(request_headers.get("Authorization", ""))
    if auth_header.lower().startswith("bearer "):
        bearer_present = True
        token = auth_header.split(" ", 1)[1].strip()
        bearer_token_preview = _truncate_text(token[:20], 20)
        jwt_like = bool(JWT_RE.match(token))

    set_cookie_value = _normalize_str(response_headers.get("Set-Cookie", ""))
    response_session_cookie = "session" in set_cookie_value.lower() or "jwt" in set_cookie_value.lower()

    role_scope_hints = []
    body_preview = (normalized.get("response_body_summary") or {}).get("preview", "")
    lower_preview = _normalize_str(body_preview).lower()
    for marker in ("role", "roles", "scope", "scopes", "claim", "claims", "permissions"):
        if marker in lower_preview:
            role_scope_hints.append(marker)

    return {
        "route_auth_hints": route_hints,
        "session_cookie_names": sorted(cookies.keys()),
        "bearer_token_present": bearer_present,
        "bearer_token_preview": bearer_token_preview,
        "jwt_like_token": jwt_like,
        "response_session_cookie_hint": response_session_cookie,
        "role_scope_claim_hints": sorted(set(role_scope_hints)),
        "observation_only": True,
        "notes": "Structured auth/session/identity observations only; no exploitability claim.",
    }
