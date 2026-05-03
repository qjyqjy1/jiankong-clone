#!/usr/bin/env python3
"""Monitoring panel server: static files + API proxy + SSE bridge."""

from __future__ import annotations

import json
import base64
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
UPSTREAM = os.environ.get("JIAN_KONG_UPSTREAM", "http://jiankong.xiaozhu.work:8082")
UPSTREAM_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT", "8"))
SSE_INTERVAL = float(os.environ.get("SSE_INTERVAL", "3"))
SSE_UPSTREAM_TIMEOUT = float(os.environ.get("SSE_UPSTREAM_TIMEOUT", "1.5"))
LOCAL_MODEL_TIMEOUT = float(os.environ.get("LOCAL_MODEL_TIMEOUT", "4"))
LOCAL_MODEL_CACHE_SECONDS = float(os.environ.get("LOCAL_MODEL_CACHE_SECONDS", "45"))
CODEX_CONFIG_PATH = Path("/root/.codex/config.toml")
CODEX_AUTH_PATH = Path("/root/.codex/auth.json")
CODEX_SESSIONS_DIR = Path("/root/.codex/sessions")
CODEX_SKILLS_DIR = Path("/root/.codex/skills")
HERMES_CONFIG_PATH = Path("/root/.hermes/config.yaml")
HERMES_SKILLS_DIR = Path("/root/.hermes/skills")
CODEX_LOGS_DB = Path("/root/.codex/logs_2.sqlite")
_MODEL_CACHE: dict[str, Any] = {"expires_at": 0.0, "payload": None}
AUTH_USER = os.environ.get("PANEL_AUTH_USER", "qjyqjy").strip()
AUTH_PASSWORD = os.environ.get("PANEL_AUTH_PASSWORD", "")
AUTH_SESSION_SECONDS = int(os.environ.get("PANEL_AUTH_SESSION_SECONDS", str(24 * 60 * 60)))
AUTH_COOKIE_NAME = "panel_auth"
AUTH_SECRET = os.environ.get("PANEL_AUTH_SECRET") or secrets.token_urlsafe(32)
PROTECTED_GET_PATHS = {
    "/api/switch_model",
    "/api/skills/install",
    "/api/skills/uninstall",
}
PROTECTED_PREFIXES = ("/api/service/",)


# ─── auth helpers ─────────────────────────────────────────────────────────────

def _auth_configured() -> bool:
    return bool(AUTH_USER and AUTH_PASSWORD)


def _b64_json(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64_json(value: str) -> dict[str, Any]:
    padded = value + "=" * (-len(value) % 4)
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    decoded = json.loads(raw.decode("utf-8"))
    return decoded if isinstance(decoded, dict) else {}


def _sign(value: str) -> str:
    return hmac.new(AUTH_SECRET.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def _make_auth_token(username: str) -> str:
    now = int(time.time())
    body = _b64_json({
        "u": username,
        "iat": now,
        "exp": now + AUTH_SESSION_SECONDS,
        "n": secrets.token_urlsafe(12),
    })
    return f"{body}.{_sign(body)}"


def _verify_auth_token(token: str) -> bool:
    if not token or "." not in token:
        return False
    body, sig = token.rsplit(".", 1)
    if not hmac.compare_digest(_sign(body), sig):
        return False
    try:
        payload = _unb64_json(body)
    except Exception:
        return False
    if payload.get("u") != AUTH_USER:
        return False
    try:
        return int(payload.get("exp", 0)) >= int(time.time())
    except Exception:
        return False


def _make_cookie_header(token: str) -> str:
    return (
        f"{AUTH_COOKIE_NAME}={token}; Path=/; Max-Age={AUTH_SESSION_SECONDS}; "
        "HttpOnly; SameSite=Strict"
    )


def _clear_cookie_header() -> str:
    return f"{AUTH_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"


def _requires_auth(path: str, method: str) -> bool:
    if method == "DELETE":
        return True
    if method in {"GET", "POST"} and (path in PROTECTED_GET_PATHS or path.startswith(PROTECTED_PREFIXES)):
        return True
    return False


# ─── helpers ──────────────────────────────────────────────────────────────────

def _replace_terms(obj: Any) -> Any:
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        has_codex = "codex" in obj
        for key, value in obj.items():
            if key == "openclaw" and has_codex:
                continue
            new_key = "codex" if key == "openclaw" else key
            out[new_key] = _replace_terms(value)
        return out
    if isinstance(obj, list):
        return [_replace_terms(v) for v in obj]
    if isinstance(obj, str):
        return obj.replace("OpenClaw", "Codex").replace("openclaw", "codex")
    return obj


def _normalize_agent_name(name: str) -> str:
    alias = (name or "").strip().lower()
    if alias in {"codex", "openclaw", "oc"}:
        return "codex"
    if alias in {"hermes", "he"}:
        return "hermes"
    return alias


def _safe_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def _short_provider_name(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        return "unknown"
    if text.startswith("http://") or text.startswith("https://"):
        try:
            return urllib.parse.urlparse(text).hostname or text
        except Exception:
            return text
    return text


def _pick_model_id(item: Any) -> str:
    if not isinstance(item, dict):
        return ""
    for key in ("id", "name", "model", "slug"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _pick_context_window(item: Any) -> int:
    if not isinstance(item, dict):
        return 0
    for key in ("contextWindow", "context_window", "contextLength", "context_length", "max_tokens"):
        value = item.get(key)
        if isinstance(value, (int, float)) and value > 0:
            return int(value)
        if isinstance(value, str):
            digits = re.sub(r"[^\d]", "", value)
            if digits.isdigit():
                parsed = int(digits)
                if parsed > 0:
                    return parsed
    return 0


def _pick_reasoning(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    for key in ("reasoning", "supports_reasoning", "thinking", "reasoning_enabled"):
        value = item.get(key)
        if isinstance(value, bool):
            return value
    return False


def _extract_model_entries(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        if isinstance(payload.get("data"), list):
            items = payload["data"]
        elif isinstance(payload.get("models"), list):
            items = payload["models"]
        elif isinstance(payload.get("available_models"), list):
            items = payload["available_models"]
        else:
            items = []
    else:
        items = []
    out: list[dict[str, Any]] = []
    for item in items:
        model_id = _pick_model_id(item)
        if not model_id:
            continue
        out.append({
            "id": model_id,
            "name": model_id,
            "contextWindow": _pick_context_window(item),
            "reasoning": _pick_reasoning(item),
        })
    return out


# ─── real system data via psutil ──────────────────────────────────────────────

def _read_cpu_percent_linux() -> float:
    """Read instant CPU usage from /proc/stat (Linux, two reads with sleep)."""
    try:
        def read_cpu():
            with open("/proc/stat", "r") as f:
                parts = f.readline().split()
                vals = [int(x) for x in parts[1:]]
                idle = vals[3]
                total = sum(vals)
                return idle, total
        i1, t1 = read_cpu()
        time.sleep(0.3)
        i2, t2 = read_cpu()
        delta_idle = i2 - i1
        delta_total = t2 - t1
        if delta_total == 0:
            return 0.0
        return round((1 - delta_idle / delta_total) * 100, 1)
    except Exception:
        return 0.0


def _get_system_info() -> dict[str, Any]:
    """Return real CPU / memory / disk / network stats via psutil."""
    try:
        import psutil
    except ImportError:
        return _fallback_system_info()

    # CPU: psutil.cpu_percent(interval=None) returns 0 on first call, accurate after
    cpu_percent = psutil.cpu_percent(interval=None)
    load_avg = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)

    # Memory
    mem = psutil.virtual_memory()
    mem_used_gb = round(mem.used / (1024 ** 3), 1)
    mem_total_gb = round(mem.total / (1024 ** 3), 1)
    mem_percent = mem.percent

    # Disk
    disk = psutil.disk_usage("/")
    disk_used_gb = round(disk.used / (1024 ** 3), 1)
    disk_total_gb = round(disk.total / (1024 ** 3), 1)
    disk_percent = disk.percent

    # Network (bytes/sec since boot → compute delta is hard, so show totals)
    net = psutil.net_io_counters()
    net_in = net.bytes_recv
    net_out = net.bytes_sent

    # Server uptime
    try:
        server_uptime_seconds = int(time.time() - psutil.boot_time())
    except Exception:
        server_uptime_seconds = 0

    return {
        "total_cpu": cpu_percent,
        "total_memory": mem_percent,
        "total_disk": disk_percent,
        "total_network_in": net_in,
        "total_network_out": net_out,
        "mem_used_gb": mem_used_gb,
        "mem_total_gb": mem_total_gb,
        "disk_used_gb": disk_used_gb,
        "disk_total_gb": disk_total_gb,
        "timestamp": time.time(),
        "data_source": "psutil",
        "server_uptime_seconds": server_uptime_seconds,
        "load_avg": ",".join(f"{x:.2f}" for x in load_avg),
    }


def _fallback_system_info() -> dict[str, Any]:
    now = time.time()
    load_avg = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)
    return {
        "total_cpu": 0,
        "total_memory": 0,
        "total_disk": 0,
        "total_network_in": 0,
        "total_network_out": 0,
        "mem_used_gb": 0,
        "mem_total_gb": 0,
        "disk_used_gb": 0,
        "disk_total_gb": 0,
        "timestamp": now,
        "data_source": "fallback",
        "server_uptime_seconds": 0,
        "load_avg": ",".join(f"{x:.2f}" for x in load_avg),
    }


# ─── agent process detection ──────────────────────────────────────────────────

def _detect_agent_running(agent: str) -> dict[str, Any]:
    """Detect if an agent process is running by scanning /proc or ps."""
    import subprocess
    result = {
        "running": False,
        "pid": None,
        "cpu_usage": 0.0,
        "memory_usage": 0.0,
        "mem_kb": 0,
        "mem_mb": 0,
        "uptime_seconds": 0,
        "uptime": 0,
    }
    try:
        if agent == "codex":
            patterns = ["codex", "openclaw"]
        elif agent == "hermes":
            patterns = ["hermes", "hermes-gateway"]
        else:
            patterns = [agent]

        cmd = ["ps", "aux"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        lines = proc.stdout.strip().split("\n")
        for line in lines[1:]:
            lower = line.lower()
            if any(p in lower for p in patterns) and "grep" not in lower and "ps aux" not in lower:
                parts = line.split()
                if len(parts) >= 11:
                    try:
                        pid = int(parts[1])
                        cpu = float(parts[2])
                        mem_pct = float(parts[3])
                        mem_kb = int(parts[5])
                        result["running"] = True
                        result["pid"] = pid
                        result["cpu_usage"] = cpu
                        result["memory_usage"] = mem_pct
                        result["mem_kb"] = mem_kb
                        result["mem_mb"] = round(mem_kb / 1024)
                        # try to get process start time for uptime
                        try:
                            import psutil
                            p = psutil.Process(pid)
                            result["uptime_seconds"] = int(time.time() - p.create_time())
                            result["uptime"] = result["uptime_seconds"]
                        except Exception:
                            pass
                        break
                    except (ValueError, IndexError):
                        continue
    except Exception:
        pass
    return result


# ─── codex / hermes config ────────────────────────────────────────────────────

def _read_codex_runtime() -> dict[str, Any]:
    result: dict[str, Any] = {"model": "", "provider": "", "base_url": "", "api_key": "", "providers": []}
    raw = _safe_text(CODEX_CONFIG_PATH)
    if not raw:
        return result
    try:
        config = tomllib.loads(raw)
    except Exception:
        return result

    model = str(config.get("model", "") or "").strip()
    provider = str(config.get("model_provider", "") or "").strip()
    providers_cfg = config.get("model_providers", {})
    provider_cfg = providers_cfg.get(provider, {}) if isinstance(providers_cfg, dict) else {}
    base_url = str(provider_cfg.get("base_url", "") or "").strip()

    api_key = ""
    try:
        auth = json.loads(_safe_text(CODEX_AUTH_PATH) or "{}")
        if isinstance(auth, dict):
            api_key = str(auth.get("OPENAI_API_KEY") or auth.get("openai_api_key") or auth.get("api_key") or "").strip()
    except Exception:
        api_key = ""

    providers: list[dict[str, Any]] = []
    if isinstance(providers_cfg, dict):
        for provider_name, cfg in providers_cfg.items():
            if not isinstance(cfg, dict):
                continue
            p_base = str(cfg.get("base_url", "") or "").strip()
            if not p_base:
                continue
            providers.append({
                "agent": "codex",
                "name": str(provider_name),
                "base_url": p_base,
                "api_key": api_key,
            })

    result.update({"model": model, "provider": provider, "base_url": base_url, "api_key": api_key, "providers": providers})
    return result


def _read_hermes_runtime() -> dict[str, Any]:
    result: dict[str, Any] = {"model": "", "provider": "", "base_url": "", "api_key": "", "providers": []}
    raw = _safe_text(HERMES_CONFIG_PATH)
    if not raw:
        return result

    config: dict[str, Any] = {}
    try:
        import yaml  # type: ignore[import-not-found]
        parsed = yaml.safe_load(raw)
        if isinstance(parsed, dict):
            config = parsed
    except Exception:
        config = {}

    if not config:
        model_match = re.search(r"(?m)^\s*default:\s*([^\n#]+)", raw)
        base_url_match = re.search(r"(?m)^\s*base_url:\s*([^\n#]+)", raw)
        api_key_match = re.search(r"(?m)^\s*api_key:\s*([^\n#]+)", raw)
        if model_match:
            result["model"] = model_match.group(1).strip().strip("'\"")
        if base_url_match:
            result["base_url"] = base_url_match.group(1).strip().strip("'\"")
        if api_key_match:
            result["api_key"] = api_key_match.group(1).strip().strip("'\"")
        return result

    model_cfg = config.get("model", {}) if isinstance(config.get("model"), dict) else {}
    providers_cfg = config.get("custom_providers", [])
    providers: list[dict[str, Any]] = []
    if isinstance(providers_cfg, list):
        for cfg in providers_cfg:
            if not isinstance(cfg, dict):
                continue
            p_base = str(cfg.get("base_url", "") or "").strip()
            if not p_base:
                continue
            providers.append({
                "agent": "hermes",
                "name": str(cfg.get("name", "") or "Hermes"),
                "base_url": p_base,
                "api_key": str(cfg.get("api_key", "") or "").strip(),
                "model": str(cfg.get("model", "") or "").strip(),
            })

    result.update({
        "model": str(model_cfg.get("default", "") or "").strip(),
        "provider": str(model_cfg.get("provider", "") or "").strip(),
        "base_url": str(model_cfg.get("base_url", "") or "").strip(),
        "api_key": str(model_cfg.get("api_key", "") or "").strip(),
        "providers": providers,
    })
    return result


def _provider_models(base_url: str, api_key: str) -> list[dict[str, Any]]:
    if not base_url:
        return []
    url = base_url.rstrip("/") + "/models"
    req = urllib.request.Request(url=url, method="GET")
    req.add_header("Accept", "application/json")
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")
    with urllib.request.urlopen(req, timeout=LOCAL_MODEL_TIMEOUT) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    if not body:
        return []
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return []
    return _extract_model_entries(payload)


def _build_local_models_payload() -> dict[str, Any]:
    now = time.time()
    codex = _read_codex_runtime()
    hermes = _read_hermes_runtime()

    agent_models = {
        "codex": codex.get("model") or "",
        "hermes": hermes.get("model") or "",
    }
    agent_model_lists: dict[str, list[str]] = {"codex": [], "hermes": []}

    available_models: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add_model(agent: str, model_id: str, provider_name: str, context_window: int = 0, reasoning: bool = False) -> None:
        clean_id = (model_id or "").strip()
        if not clean_id:
            return
        clean_agent = _normalize_agent_name(agent)
        if clean_agent in agent_model_lists and clean_id not in agent_model_lists[clean_agent]:
            agent_model_lists[clean_agent].append(clean_id)
        if clean_id in seen:
            return
        seen.add(clean_id)
        available_models.append({
            "id": clean_id,
            "name": clean_id,
            "provider": _short_provider_name(provider_name),
            "contextWindow": int(context_window) if context_window else 0,
            "reasoning": bool(reasoning),
        })

    # Only add models that are actually configured in agent configs.
    # Do NOT pull full model list from providers — that surfaces unrelated models
    # (e.g. TTS, omni) that the agent never uses.

    # Codex: add its configured model
    codex_model = str(agent_models["codex"]).strip()
    if codex_model:
        codex_provider_name = str(codex.get("provider") or _short_provider_name(str(codex.get("base_url") or "")) or "Codex")
        add_model("codex", codex_model, codex_provider_name)

    # Hermes: add its configured model from primary provider
    hermes_model = str(agent_models["hermes"]).strip()
    if hermes_model:
        hermes_provider_name = str(hermes.get("provider") or _short_provider_name(str(hermes.get("base_url") or "")) or "Hermes")
        add_model("hermes", hermes_model, hermes_provider_name)

    # Hermes custom_providers: add the model field from each extra provider
    for item in hermes.get("providers", []):
        if not isinstance(item, dict):
            continue
        p_name = str(item.get("name") or "Hermes")
        p_model = str(item.get("model") or "").strip()
        if p_model:
            add_model("hermes", p_model, p_name)

    payload: dict[str, Any] = {
        "available_models": available_models,
        "agent_models": agent_models,
        "agent_model_lists": agent_model_lists,
        "current_time": now,
        "data_source": "local_dynamic",
    }
    return payload


def _local_models_payload() -> dict[str, Any]:
    now = time.time()
    cached_payload = _MODEL_CACHE.get("payload")
    expires_at = float(_MODEL_CACHE.get("expires_at", 0) or 0)
    if cached_payload and now < expires_at:
        return json.loads(json.dumps(cached_payload, ensure_ascii=False))

    payload = _build_local_models_payload()
    _MODEL_CACHE["payload"] = payload
    _MODEL_CACHE["expires_at"] = now + LOCAL_MODEL_CACHE_SECONDS
    return json.loads(json.dumps(payload, ensure_ascii=False))


# ─── call stats from SQLite ───────────────────────────────────────────────────

def _read_call_stats(period: str = "all") -> dict[str, Any]:
    """Read real call statistics from codex logs_2.sqlite and hermes state.db."""
    def period_cutoff(value: str) -> float | None:
        normalized = (value or "all").strip().lower()
        seconds_by_period = {
            "1h": 3600,
            "24h": 24 * 3600,
            "1d": 24 * 3600,
            "7d": 7 * 24 * 3600,
            "30d": 30 * 24 * 3600,
        }
        seconds = seconds_by_period.get(normalized)
        return time.time() - seconds if seconds else None

    cutoff = period_cutoff(period)
    result = {
        "period": period,
        "total_calls": 0,
        "total_input": 0,
        "total_output": 0,
        "total_cache": 0,
        "total_tokens": 0,
        "avg_response_time": 0,
        "total_response_time": 0,
        "by_source": {
            "codex": {"calls": 0, "input": 0, "output": 0, "cache": 0, "total": 0, "response_time": 0},
            "hermes": {"calls": 0, "input": 0, "output": 0, "cache": 0, "total": 0, "response_time": 0},
        },
        "by_model": {},
        "scan_time": time.time(),
        "all_time_calls": 0,
    }

    # ── Read Codex logs_2.sqlite ──────────────────────────────────────────────
    try:
        import sqlite3 as _sq
        if CODEX_LOGS_DB.exists():
            conn = _sq.connect(f"file:{CODEX_LOGS_DB}?mode=ro", uri=True, timeout=5)
            conn.row_factory = _sq.Row
            tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            table_names = {r[0].lower() for r in tables}

            # Count codex calls from logs table
            if "logs" in table_names:
                all_row = conn.execute("SELECT COUNT(*) as cnt FROM logs").fetchone()
                if all_row and all_row["cnt"]:
                    result["all_time_calls"] += all_row["cnt"]
                if cutoff is None:
                    row = all_row
                else:
                    row = conn.execute("SELECT COUNT(*) as cnt FROM logs WHERE ts >= ?", (int(cutoff),)).fetchone()
                if row and row["cnt"]:
                    codex_calls = row["cnt"]
                    result["by_source"]["codex"]["calls"] = codex_calls
                    result["total_calls"] += codex_calls

            conn.close()
    except Exception:
        pass

    # ── Read Hermes state.db ──────────────────────────────────────────────────
    HERMES_STATE_DB = Path("/root/.hermes/state.db")
    try:
        import sqlite3 as _sq
        if HERMES_STATE_DB.exists():
            conn = _sq.connect(f"file:{HERMES_STATE_DB}?mode=ro", uri=True, timeout=5)
            conn.row_factory = _sq.Row

            # Total hermes sessions as call count
            all_row = conn.execute("SELECT COUNT(*) as cnt FROM sessions").fetchone()
            if all_row and all_row["cnt"]:
                result["all_time_calls"] += all_row["cnt"]
            if cutoff is None:
                row = all_row
            else:
                row = conn.execute("SELECT COUNT(*) as cnt FROM sessions WHERE started_at >= ?", (cutoff,)).fetchone()
            hermes_calls = row["cnt"] if row else 0

            # Token stats per model
            stats_sql = (
                "SELECT model, "
                "COUNT(*) as calls, "
                "COALESCE(SUM(input_tokens),0) as inp, "
                "COALESCE(SUM(output_tokens),0) as out, "
                "COALESCE(SUM(cache_read_tokens),0) as cache, "
                "COALESCE(SUM(input_tokens),0) + COALESCE(SUM(output_tokens),0) + COALESCE(SUM(cache_read_tokens),0) as total "
                "FROM sessions"
            )
            if cutoff is None:
                rows = conn.execute(stats_sql + " GROUP BY model").fetchall()
            else:
                rows = conn.execute(stats_sql + " WHERE started_at >= ? GROUP BY model", (cutoff,)).fetchall()

            hermes_total_input = 0
            hermes_total_output = 0
            hermes_total_cache = 0
            hermes_total_tokens = 0

            for r in rows:
                model = r["model"] or "unknown"
                inp = r["inp"] or 0
                out = r["out"] or 0
                cache = r["cache"] or 0
                total = r["total"] or 0

                hermes_total_input += inp
                hermes_total_output += out
                hermes_total_cache += cache
                hermes_total_tokens += total

                # Merge into by_model
                if model not in result["by_model"]:
                    result["by_model"][model] = {"calls": 0, "input": 0, "output": 0, "cache": 0, "total": 0}
                result["by_model"][model]["calls"] += r["calls"] or 0
                result["by_model"][model]["input"] += inp
                result["by_model"][model]["output"] += out
                result["by_model"][model]["cache"] += cache
                result["by_model"][model]["total"] += total

            result["by_source"]["hermes"]["calls"] = hermes_calls
            result["by_source"]["hermes"]["input"] = hermes_total_input
            result["by_source"]["hermes"]["output"] = hermes_total_output
            result["by_source"]["hermes"]["cache"] = hermes_total_cache
            result["by_source"]["hermes"]["total"] = hermes_total_tokens

            result["total_calls"] += hermes_calls
            result["total_input"] += hermes_total_input
            result["total_output"] += hermes_total_output
            result["total_cache"] += hermes_total_cache
            result["total_tokens"] += hermes_total_tokens

            conn.close()
    except Exception:
        pass

    return result
# ─── sessions from filesystem ─────────────────────────────────────────────────

def _scan_sessions() -> list[dict[str, Any]]:
    """Scan /root/.codex/sessions for rollout files and build session list."""
    sessions: list[dict[str, Any]]
    sessions = []
    if not CODEX_SESSIONS_DIR.exists():
        return sessions

    import glob
    pattern = str(CODEX_SESSIONS_DIR / "**" / "*.jsonl")
    files = sorted(glob.glob(pattern, recursive=True), reverse=True)

    for fpath in files[:100]:  # cap at 100 most recent
        try:
            p = Path(fpath)
            stat = p.stat()
            size = stat.st_size
            mtime = stat.st_mtime

            # Determine date from path
            rel = p.relative_to(CODEX_SESSIONS_DIR)
            parts = rel.parts
            date_str = "/".join(parts[:3]) if len(parts) >= 3 else ""

            # Count lines (messages)
            msg_count = 0
            first_line = ""
            last_line = ""
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    for i, line in enumerate(f):
                        line = line.strip()
                        if not line:
                            continue
                        msg_count += 1
                        if i == 0:
                            first_line = line[:200]
                        last_line = line[:200]
            except Exception:
                pass

            # Parse first line for session info
            session_id = p.stem
            channel = "unknown"
            agent = "codex"
            status_str = "活跃"
            model_name = ""
            try:
                if first_line:
                    data = json.loads(first_line)
                    channel = data.get("channel", data.get("source", "unknown"))
                    agent = data.get("agent", "codex")
                    model_name = data.get("model", "")
            except Exception:
                pass

            # Determine status from file age
            age_hours = (time.time() - mtime) / 3600
            if age_hours > 24:
                status_str = "空闲"

            # Session type detection
            session_type = "normal"
            fpath_lower = fpath.lower()
            if "dream" in fpath_lower:
                session_type = "dreaming"
            elif "sub" in fpath_lower:
                session_type = "subagent"

            sessions.append({
                "key": session_id,
                "id": session_id,
                "session_id": session_id,
                "channel": channel,
                "agent": agent,
                "agent_id": agent,
                "model": model_name,
                "model_name": model_name,
                "status": status_str,
                "session_type": session_type,
                "chat_type": "direct",
                "user_id": "",
                "msg_count": msg_count,
                "last_usage_tokens": 0,
                "total_tokens": 0,
                "context_tokens": 0,
                "compaction_count": 0,
                "aborted": False,
                "file_size": size,
                "file_size_human": _format_bytes(size),
                "file_size_fmt": _format_bytes(size),
                "last_active": time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime)),
                "created": date_str,
                "modified": time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime)),
                "path": str(p),
                "age_hours": round(age_hours, 1),
            })
        except Exception:
            continue

    return sessions


def _delete_session_file(session_key: str) -> dict[str, Any]:
    clean_key = urllib.parse.unquote(session_key or "").strip()
    if not clean_key:
        return {"status": "error", "success": False, "error": "缺少会话标识"}
    if "/" in clean_key or "\\" in clean_key or clean_key in {".", ".."}:
        return {"status": "error", "success": False, "error": "非法会话标识"}
    if not CODEX_SESSIONS_DIR.exists():
        return {"status": "error", "success": False, "error": "会话目录不存在"}

    matches = [p for p in CODEX_SESSIONS_DIR.rglob("*.jsonl") if p.stem == clean_key]
    if not matches:
        return {"status": "error", "success": False, "error": "未找到会话文件"}
    if len(matches) > 1:
        return {"status": "error", "success": False, "error": "匹配到多个会话文件，拒绝删除"}

    target = matches[0].resolve()
    try:
        target.relative_to(CODEX_SESSIONS_DIR.resolve())
    except ValueError:
        return {"status": "error", "success": False, "error": "会话路径越界"}

    try:
        target.unlink()
    except Exception as exc:
        return {"status": "error", "success": False, "error": f"删除失败：{exc}"}

    return {"status": "success", "success": True, "message": "会话文件已删除", "deleted": str(target)}


def _format_bytes(n: int) -> str:
    if n < 1024:
        return f"{n}B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f}KB"
    return f"{n / (1024 * 1024):.1f}MB"


# ─── skills from filesystem ───────────────────────────────────────────────────

def _scan_skills() -> list[dict[str, Any]]:
    """Scan hermes and codex skill directories for SKILL.md files."""
    skills: list[dict[str, Any]] = []

    skill_dirs = [
        (HERMES_SKILLS_DIR, "hermes", False),
        (CODEX_SKILLS_DIR, "codex", False),
    ]

    for sdir, source, bundled_override in skill_dirs:
        if not sdir.exists():
            continue
        for item in sorted(sdir.iterdir()):
            if not item.is_dir():
                continue
            if item.name.startswith(".") or item.name.startswith("__"):
                continue

            skill_md = item / "SKILL.md"
            name = item.name
            description = ""
            bundled = source == "hermes"  # hermes skills are bundled
            eligible = True
            disabled = False
            icon = "fa-puzzle-piece"
            category = ""

            if skill_md.exists():
                try:
                    content = skill_md.read_text(encoding="utf-8", errors="replace")
                    # Parse frontmatter
                    fm_match = re.match(r"^---\s*\n(.*?)\n---", content, re.DOTALL)
                    if fm_match:
                        fm_text = fm_match.group(1)
                        # Extract description
                        desc_m = re.search(r"(?m)^\s*description:\s*['\"]?(.+?)['\"]?\s*$", fm_text)
                        if desc_m:
                            description = desc_m.group(1).strip().strip("'\"")
                        # Extract name
                        name_m = re.search(r"(?m)^\s*name:\s*['\"]?(.+?)['\"]?\s*$", fm_text)
                        if name_m:
                            name = name_m.group(1).strip().strip("'\"")
                        # Extract icon
                        icon_m = re.search(r"(?m)^\s*icon:\s*['\"]?(.+?)['\"]?\s*$", fm_text)
                        if icon_m:
                            icon = icon_m.group(1).strip().strip("'\"")
                        # Extract category
                        cat_m = re.search(r"(?m)^\s*(category|tags):\s*['\"]?(.+?)['\"]?\s*$", fm_text)
                        if cat_m:
                            category = cat_m.group(2).strip().strip("'\"")

                    # First non-empty non-header line as description fallback
                    if not description:
                        for line in content.split("\n"):
                            line = line.strip()
                            if line and not line.startswith("#") and not line.startswith("---"):
                                description = line[:120]
                                break
                except Exception:
                    pass

            # Check eligibility: skill has content
            eligible = skill_md.exists() and skill_md.stat().st_size > 50

            skills.append({
                "name": name,
                "slug": item.name,
                "description": description or f"{source} 技能",
                "bundled": bundled,
                "eligible": eligible,
                "disabled": disabled,
                "icon": icon,
                "source": source,
                "category": category,
                "path": str(item),
            })

    return skills


# ─── system services ──────────────────────────────────────────────────────────

def _scan_services() -> list[dict[str, Any]]:
    """Return list of running systemd services relevant to the panel."""
    services: list[dict[str, Any]] = []
    known_services = {
        "codex-standalone-webui.service": {"name": "Codex WebUI", "icon": "🤖", "ports": [9009]},
        "hermes-gateway.service": {"name": "Hermes 网关", "icon": "🧠", "ports": [9119]},
        "hermes-web-ui.service": {"name": "Hermes WebUI", "icon": "🌐", "ports": [8648]},
        "nginx.service": {"name": "Nginx", "icon": "⚡", "ports": [80]},
        "ssh.service": {"name": "SSH 服务", "icon": "🔑", "ports": [22]},
        "football-web.service": {"name": "足球预测面板", "icon": "⚽", "ports": [8080]},
        "plotpilot.service": {"name": "PlotPilot", "icon": "📊", "ports": [8005]},
        "metapi.service": {"name": "Metapi 服务", "icon": "🔮", "ports": [80, 8085]},
        "uniagentd.service": {"name": "UniAgent 守护进程", "icon": "🛡️", "ports": [29338, 29339]},
        "ces-uniagent.service": {"name": "CES UniAgent", "icon": "🎯", "ports": []},
        "cron.service": {"name": "Cron 定时任务", "icon": "⏰", "ports": []},
        "docker.service": {"name": "Docker", "icon": "🐳", "ports": []},
    }

    # Always add panel itself
    services.append({
        "id": "panel-server",
        "name": "智能体面板",
        "description": "监控面板后端 API 服务",
        "status": "online",
        "pid": str(os.getpid()),
        "memory": "--",
        "icon": "📊",
        "port": 1234,
    })

    def _listen_ports_for_pid(pid_value: str | None) -> list[int]:
        try:
            pid_int = int(str(pid_value or "").strip())
        except Exception:
            return []
        if pid_int <= 0:
            return []

        try:
            import psutil
        except ImportError:
            return []

        ports: set[int] = set()
        try:
            root_proc = psutil.Process(pid_int)
            proc_list = [root_proc] + root_proc.children(recursive=True)
        except Exception:
            return []

        for proc in proc_list:
            try:
                for conn in proc.net_connections(kind="inet"):
                    status = str(getattr(conn, "status", "") or "").upper()
                    laddr = getattr(conn, "laddr", None)
                    port = getattr(laddr, "port", None) if laddr else None
                    if status == "LISTEN" and isinstance(port, int) and port > 0:
                        ports.add(port)
            except Exception:
                continue

        return sorted(ports)

    import subprocess
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--plain"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split("\n"):
            parts = line.split()
            if not parts:
                continue
            unit = parts[0]
            if unit in known_services:
                info = known_services[unit]
                # Try to get PID
                pid = None
                try:
                    pid_result = subprocess.run(
                        ["systemctl", "show", unit, "--property=MainPID", "--value"],
                        capture_output=True, text=True, timeout=3
                    )
                    pid = pid_result.stdout.strip()
                    if pid == "0":
                        pid = None
                except Exception:
                    pass

                hints = [int(p) for p in (info.get("ports") or []) if isinstance(p, int) and p > 0]
                detected_ports = _listen_ports_for_pid(pid)
                filtered_detected = [p for p in detected_ports if p <= 49151]
                if hints and filtered_detected:
                    display_ports = [p for p in hints if p in filtered_detected]
                    if not display_ports:
                        display_ports = filtered_detected
                elif filtered_detected:
                    display_ports = filtered_detected
                elif hints:
                    display_ports = hints
                else:
                    display_ports = detected_ports[:1]
                port_value = ", ".join(str(p) for p in display_ports) if display_ports else None

                services.append({
                    "id": unit.replace(".service", ""),
                    "name": info["name"],
                    "description": f"systemd 托管服务 ({unit})",
                    "status": "online",
                    "pid": pid,
                    "memory": "--",
                    "icon": info["icon"],
                    "port": port_value,
                })
    except Exception:
        pass

    return services


# ─── changelog ────────────────────────────────────────────────────────────────

def _load_changelog_entries() -> list[dict[str, Any]]:
    html = _safe_text(BASE_DIR / "changelog.html")
    if not html:
        return []
    try:
        idx = html.index('CHANGELOG_DATA')
        start = html.index('{', idx)
        decoder = json.JSONDecoder()
        payload, _ = decoder.raw_decode(html[start:])
    except (ValueError, json.JSONDecodeError):
        return []
    entries = payload.get("entries", [])
    if not isinstance(entries, list):
        return []
    return entries


def _fallback_changelog() -> dict[str, Any]:
    entries = _load_changelog_entries()
    return {
        "entries": entries,
        "total_versions": len(entries),
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())),
    }


def _current_panel_version() -> str:
    entries = _load_changelog_entries()
    if entries and isinstance(entries[0], dict):
        version = str(entries[0].get("version") or "").strip()
        if version:
            return version
    return "v3.15.0"


# ─── projects (workspace scan) ───────────────────────────────────────────────

def _scan_projects() -> list[dict[str, Any]]:
    """Scan known project directories and attach service port hints."""
    projects = []
    interesting = {
        "/root/.codex": {"name": "Codex 配置", "icon": "⚙️", "tags": ["配置", "Codex"], "ports": [9009]},
        "/root/.hermes": {"name": "Hermes 配置", "icon": "🧩", "tags": ["配置", "Hermes"], "ports": [8648]},
        "/root/football-prediction": {"name": "足球预测系统", "icon": "⚽", "tags": ["ML", "足球", "预测"], "ports": [8080]},
        "/opt/PlotPilot": {"name": "PlotPilot 小说创作", "icon": "📚", "tags": ["AI", "小说", "创作"], "ports": [8005]},
    }

    def _first_open_port(candidates: list[int]) -> int | None:
        import socket
        for port in candidates:
            try:
                with socket.create_connection(("127.0.0.1", int(port)), timeout=0.2):
                    return int(port)
            except Exception:
                continue
        return None

    for project_path, meta in interesting.items():
        d = Path(project_path)
        if d.exists() and d.is_dir():
            try:
                candidates = [int(p) for p in (meta.get("ports") or []) if isinstance(p, int) and p > 0]
                detected_port = _first_open_port(candidates)
                port = detected_port if detected_port is not None else (candidates[0] if candidates else None)
                total_size = sum(f.stat().st_size for f in d.rglob("*") if f.is_file())
                projects.append({
                    "name": meta["name"],
                    "path": str(d),
                    "description": f"项目位于 {d}",
                    "icon": meta["icon"],
                    "tags": meta["tags"],
                    "size": _format_bytes(total_size),
                    "port": port,
                    "url": f"http://127.0.0.1:{port}" if port else None,
                })
            except Exception:
                pass

    return projects


# ─── fallback status with real data ───────────────────────────────────────────

def _fallback_status() -> dict[str, Any]:
    now = time.time()
    sys_info = _get_system_info()
    local_models = _local_models_payload()
    codex_model = str((local_models.get("agent_models") or {}).get("codex") or "unknown")
    hermes_model = str((local_models.get("agent_models") or {}).get("hermes") or "unknown")

    # Detect real agent processes
    codex_proc = _detect_agent_running("codex")
    hermes_proc = _detect_agent_running("hermes")

    # Read call stats for real counts
    call_stats = _read_call_stats()

    return {
        "agents": {
            "codex": {
                "name": "Codex",
                "status": "online" if codex_proc["running"] else "stopped",
                "cpu_usage": round(codex_proc["cpu_usage"], 1),
                "memory_usage": round(codex_proc["memory_usage"], 1),
                "disk_usage": 0,
                "network_in": 0,
                "network_out": 0,
                "uptime": codex_proc["uptime_seconds"],
                "tasks": [],
                "last_update": now,
                "api_calls": call_stats.get("by_source", {}).get("codex", {}).get("calls", 0),
                "total_response_time": call_stats.get("total_response_time", 0),
                "successful_calls": call_stats.get("by_source", {}).get("codex", {}).get("calls", 0),
                "uptime_seconds": codex_proc["uptime_seconds"],
                "start_time": time.strftime("%a %b %d %H:%M:%S %Y", time.localtime(now - codex_proc["uptime_seconds"])),
                "mem_kb": codex_proc["mem_kb"],
                "mem_mb": codex_proc["mem_mb"],
                "version": "0.125.0",
                "disk_size": "--",
                "model": codex_model,
                "running": codex_proc["running"],
                "pid": codex_proc["pid"],
            },
            "hermes": {
                "name": "Hermes",
                "status": "online" if hermes_proc["running"] else "stopped",
                "cpu_usage": round(hermes_proc["cpu_usage"], 1),
                "memory_usage": round(hermes_proc["memory_usage"], 1),
                "disk_usage": 0,
                "network_in": 0,
                "network_out": 0,
                "uptime": hermes_proc["uptime_seconds"],
                "tasks": [],
                "last_update": now,
                "api_calls": call_stats.get("by_source", {}).get("hermes", {}).get("calls", 0),
                "total_response_time": 0,
                "successful_calls": call_stats.get("by_source", {}).get("hermes", {}).get("calls", 0),
                "uptime_seconds": hermes_proc["uptime_seconds"],
                "start_time": time.strftime("%a %b %d %H:%M:%S %Y", time.localtime(now - hermes_proc["uptime_seconds"])),
                "mem_kb": hermes_proc["mem_kb"],
                "mem_mb": hermes_proc["mem_mb"],
                "version": "unknown",
                "disk_size": "unknown",
                "model": hermes_model,
                "running": hermes_proc["running"],
                "pid": hermes_proc["pid"],
            },
        },
        "system_info": sys_info,
        "model_stats": {
            "total_calls": call_stats.get("total_calls", 0),
            "avg_response_time": call_stats.get("avg_response_time", 0),
            "success_rate": 100,
            "active_connections": 0,
            "model_status": "running",
            "model_id": codex_model,
            "model_name": codex_model,
        },
        "panel_info": {
            "panel_version": _current_panel_version(),
            "dir_size": _du_dir(BASE_DIR),
            "panel_mem": "--",
            "update_date": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
        },
    }


def _du_dir(d: Path) -> str:
    try:
        total = sum(f.stat().st_size for f in d.rglob("*") if f.is_file())
        return _format_bytes(total)
    except Exception:
        return "--"


# ─── fallback payload router ──────────────────────────────────────────────────

def _fallback_payload(api_path: str, query: str = "") -> Any:
    q = urllib.parse.parse_qs(query, keep_blank_values=True)
    service_id = (q.get("id") or ["服务"])[0]
    model_id = (q.get("model_id") or ["未知模型"])[0]
    skill_slug = (q.get("slug") or ["未知技能"])[0]
    period = (q.get("period") or ["all"])[0]

    if api_path == "/api/status":
        return _fallback_status()
    if api_path == "/api/models":
        return _local_models_payload()
    if api_path == "/api/call_stats":
        return _read_call_stats(period)
    if api_path == "/api/sessions":
        return {"sessions": _scan_sessions()}
    if api_path == "/api/skills":
        return {
            "workspaceDir": str(BASE_DIR),
            "managedSkillsDir": str(HERMES_SKILLS_DIR),
            "skills": _scan_skills(),
        }
    if api_path == "/api/systems":
        return {
            "services": _scan_services(),
            "projects": _scan_projects(),
            "skills": _scan_skills(),
            "uptime": _format_uptime(_get_system_info().get("server_uptime_seconds", 0)),
        }
    if api_path == "/api/changelog":
        return _fallback_changelog()
    if api_path == "/api/switch_model":
        return {
            "status": "error",
            "success": False,
            "message": f"模型 {model_id} 未切换：本地没有安全的模型切换实现，上游接口也不可用。",
        }
    if api_path == "/api/skills/install":
        return {"success": False, "message": f"技能 {skill_slug} 未安装：本地安装接口尚未接入。"}
    if api_path == "/api/skills/uninstall":
        return {"success": False, "message": f"技能 {skill_slug} 未卸载：本地卸载接口尚未接入。"}
    if api_path.startswith("/api/service/"):
        action = api_path.rsplit("/", 1)[-1]
        allowed_actions = {"start", "stop", "restart", "status"}
        if action not in allowed_actions:
            return {"success": False, "message": f"不支持的服务操作：{action}"}
        action_map = {
            "start": "已启动",
            "stop": "已停止",
            "restart": "已重启",
            "status": "运行中",
        }
        msg = action_map.get(action, "操作完成")

        # Map service id to systemd unit name
        service_to_unit = {
            "codex-standalone-webui": "codex-standalone-webui.service",
            "hermes-gateway": "hermes-gateway.service",
            "hermes-web-ui": "hermes-web-ui.service",
            "nginx": "nginx.service",
            "ssh": "ssh.service",
            "football-web": "football-web.service",
            "plotpilot": "plotpilot.service",
            "ai-goofish-monitor": "ai-goofish-monitor.service",
            "monitoring-panel": "ai-goofish-monitor.service",
            "metapi": "metapi.service",
            "uniagentd": "uniagentd.service",
            "ces-uniagent": "ces-uniagent.service",
            "cron": "cron.service",
            "docker": "docker.service",
        }

        # Panel server itself — just return info, don't actually kill it
        if service_id == "panel-server":
            return {"success": True, "message": "面板服务运行中（PID: {}）".format(os.getpid())}

        unit = service_to_unit.get(service_id)
        if unit is None:
            return {"success": False, "message": f"拒绝操作未知服务：{service_id}"}

        if action == "status":
            import subprocess
            try:
                r = subprocess.run(
                    ["systemctl", "is-active", unit],
                    capture_output=True, text=True, timeout=5
                )
                active = r.stdout.strip() == "active"
                return {"success": True, "message": f"{service_id} 状态: {'运行中' if active else '已停止'}", "active": active}
            except Exception as e:
                return {"success": False, "message": f"查询状态失败: {e}"}

        import subprocess
        try:
            r = subprocess.run(
                ["systemctl", action, unit],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode == 0:
                return {"success": True, "message": f"{service_id} {msg}"}
            else:
                err = r.stderr.strip() or r.stdout.strip() or f"退出码 {r.returncode}"
                return {"success": False, "message": f"{service_id} {msg}失败: {err}"}
        except FileNotFoundError:
            return {"success": False, "message": "systemctl 不可用"}
        except subprocess.TimeoutExpired:
            return {"success": False, "message": "操作超时"}
        except Exception as e:
            return {"success": False, "message": f"操作失败: {e}"}

    # Catch-all: return success with empty data instead of upstream_unavailable
    return {"success": True, "data": [], "message": "ok"}


def _format_uptime(seconds: int) -> str:
    d = seconds // 86400
    h = (seconds % 86400) // 3600
    m = (seconds % 3600) // 60
    parts = []
    if d:
        parts.append(f"{d}天")
    if h:
        parts.append(f"{h}小时")
    if m:
        parts.append(f"{m}分钟")
    return "".join(parts) if parts else "0分钟"


# ─── upstream proxy ───────────────────────────────────────────────────────────

def _http_json(path_with_query: str, method: str = "GET", timeout: float | None = None) -> tuple[int, Any]:
    url = UPSTREAM.rstrip("/") + path_with_query
    req = urllib.request.Request(url=url, method=method)
    req.add_header("Accept", "application/json")
    request_timeout = UPSTREAM_TIMEOUT if timeout is None else timeout
    with urllib.request.urlopen(req, timeout=request_timeout) as resp:
        status = int(resp.getcode() or 200)
        body = resp.read()
        text = body.decode("utf-8", errors="replace") if body else ""
    if not text:
        return status, {}
    try:
        return status, json.loads(text)
    except json.JSONDecodeError:
        return status, {"raw": text}


def _normalize_response(path: str, payload: Any) -> Any:
    data = _replace_terms(payload)

    if path == "/api/status" and isinstance(data, dict):
        agents = data.setdefault("agents", {})
        if isinstance(agents, dict):
            normalized_agents: dict[str, Any] = {}
            for key, value in list(agents.items()):
                normalized_agents[_normalize_agent_name(str(key))] = value
            agents.clear()
            agents.update(normalized_agents)

        codex = agents.get("codex", {})
        if isinstance(codex, dict):
            codex["name"] = "Codex"
        hermes = agents.get("hermes", {})
        if isinstance(hermes, dict):
            hermes["name"] = "Hermes"

        if "model_stats" in data and isinstance(data["model_stats"], dict):
            model_stats = data["model_stats"]
            if "model_name" in model_stats and isinstance(model_stats["model_name"], str):
                model_stats["model_name"] = model_stats["model_name"].replace("OpenClaw", "Codex")
            if not model_stats.get("model_id") and isinstance(codex, dict):
                model_stats["model_id"] = codex.get("model")

    if path == "/api/models" and isinstance(data, dict):
        available = data.get("available_models")
        if not isinstance(available, list):
            if isinstance(data.get("models"), list):
                data["available_models"] = data.get("models")
            else:
                data["available_models"] = []

        agent_models = data.setdefault("agent_models", {})
        if isinstance(agent_models, dict):
            normalized_agent_models: dict[str, Any] = {}
            for key, value in list(agent_models.items()):
                normalized_agent_models[_normalize_agent_name(str(key))] = value
            agent_models.clear()
            agent_models.update(normalized_agent_models)

        agent_model_lists = data.setdefault("agent_model_lists", {})
        if isinstance(agent_model_lists, dict):
            normalized_lists: dict[str, list[str]] = {}
            for key, value in list(agent_model_lists.items()):
                if isinstance(value, list):
                    normalized_lists[_normalize_agent_name(str(key))] = [str(v) for v in value]
            agent_model_lists.clear()
            agent_model_lists.update(normalized_lists)

        if "codex" not in agent_models:
            status_agents = (((data.get("status") or {}) if isinstance(data.get("status"), dict) else {}).get("agents") or {})
            if isinstance(status_agents, dict):
                codex_status = status_agents.get("codex")
                if isinstance(codex_status, dict) and codex_status.get("model"):
                    agent_models["codex"] = codex_status["model"]

        if "hermes" not in agent_models:
            status_agents = (((data.get("status") or {}) if isinstance(data.get("status"), dict) else {}).get("agents") or {})
            if isinstance(status_agents, dict):
                hermes_status = status_agents.get("hermes")
                if isinstance(hermes_status, dict) and hermes_status.get("model"):
                    agent_models["hermes"] = hermes_status["model"]

    if path == "/api/call_stats" and isinstance(data, dict):
        by_source = data.setdefault("by_source", {})
        if isinstance(by_source, dict):
            normalized_source: dict[str, Any] = {}
            for key, value in list(by_source.items()):
                normalized_source[_normalize_agent_name(str(key))] = value
            by_source.clear()
            by_source.update(normalized_source)

    if path == "/api/changelog" and isinstance(data, dict):
        entries = data.get("entries")
        if not isinstance(entries, list):
            data["entries"] = []

    return data


def _map_query_for_upstream(path: str, query: str) -> str:
    if not query:
        return ""
    q = urllib.parse.parse_qs(query, keep_blank_values=True)

    if path == "/api/switch_model":
        agent = q.get("agent", [])
        if agent:
            normalized = _normalize_agent_name(agent[0])
            if normalized == "codex":
                q["agent"] = ["openclaw"]
            elif normalized == "hermes":
                q["agent"] = ["he"]

    if path.startswith("/api/service/"):
        service_id = q.get("id", [])
        if service_id:
            mapped = service_id[0].replace("codex", "openclaw").replace("hermes", "he")
            q["id"] = [mapped]

    if path.startswith("/api/sessions/"):
        pass

    return urllib.parse.urlencode(q, doseq=True)


def _build_upstream_paths(path: str, query: str) -> list[str]:
    original = path + (f"?{query}" if query else "")
    mapped_query = _map_query_for_upstream(path, query)
    mapped = path + (f"?{mapped_query}" if mapped_query else "")
    if mapped == original:
        return [original]
    return [original, mapped]


def _should_try_next_alias(path: str, payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False

    if path == "/api/switch_model":
        if payload.get("success") is True:
            return False
        status = str(payload.get("status", "")).lower()
        return status not in {"success", "ok", "done"}

    if path.startswith("/api/service/") or path.startswith("/api/skills/"):
        return payload.get("success") is False

    return False


# ─── HTTP handler ──────────────────────────────────────────────────────────────

class PanelHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def log_message(self, format: str, *args: Any) -> None:
        super().log_message(format, *args)

    def _send_json(self, status_code: int, payload: Any, extra_headers: dict[str, str] | None = None) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _read_json_body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = 0
        if length <= 0 or length > 16 * 1024:
            return {}
        try:
            raw = self.rfile.read(length)
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            return {}
        return payload if isinstance(payload, dict) else {}

    def _auth_token_from_cookie(self) -> str:
        cookie_header = self.headers.get("Cookie", "")
        if not cookie_header:
            return ""
        try:
            cookie = SimpleCookie()
            cookie.load(cookie_header)
            morsel = cookie.get(AUTH_COOKIE_NAME)
            return morsel.value if morsel else ""
        except Exception:
            return ""

    def _is_authenticated(self) -> bool:
        return _auth_configured() and _verify_auth_token(self._auth_token_from_cookie())

    def _send_unauthorized(self) -> None:
        message = "需要登录后才能执行此操作" if _auth_configured() else "服务端未配置 PANEL_AUTH_PASSWORD，危险操作已禁用"
        self._send_json(401, {"success": False, "status": "unauthorized", "error": message})

    def _handle_auth_api(self, path: str, method: str) -> bool:
        if path == "/api/auth/status" and method == "GET":
            self._send_json(200, {"authenticated": self._is_authenticated(), "configured": _auth_configured()})
            return True

        if path == "/api/auth/logout" and method in {"GET", "POST"}:
            self._send_json(
                200,
                {"success": True, "authenticated": False},
                {"Set-Cookie": _clear_cookie_header()},
            )
            return True

        if path == "/api/auth/login" and method == "POST":
            payload = self._read_json_body()
            username = str(payload.get("username") or "").strip()
            password = str(payload.get("password") or "")
            if not _auth_configured():
                self._send_json(503, {"success": False, "error": "服务端未配置 PANEL_AUTH_PASSWORD"})
                return True
            if hmac.compare_digest(username, AUTH_USER) and hmac.compare_digest(password, AUTH_PASSWORD):
                token = _make_auth_token(username)
                self._send_json(
                    200,
                    {"success": True, "authenticated": True, "expires_in": AUTH_SESSION_SECONDS},
                    {"Set-Cookie": _make_cookie_header(token)},
                )
            else:
                self._send_json(401, {"success": False, "error": "用户名或密码错误"})
            return True

        return False

    def _proxy_json(self, path: str, query: str, method: str = "GET") -> None:
        errors: list[str] = []
        candidates = _build_upstream_paths(path, query)

        for idx, full_path in enumerate(candidates):
            try:
                upstream_status, upstream_payload = _http_json(full_path, method=method)
                if upstream_status >= 400 and idx < len(candidates) - 1:
                    errors.append(f"{full_path}: http_{upstream_status}")
                    continue
                if _should_try_next_alias(path, upstream_payload):
                    errors.append(f"{full_path}: logical_failure")
                    if idx < len(candidates) - 1:
                        continue
                    break
                payload = _normalize_response(path, upstream_payload)
                self._send_json(upstream_status, payload)
                return
            except Exception as exc:
                errors.append(f"{full_path}: {exc}")

        fallback = _fallback_payload(path, query)
        if isinstance(fallback, dict) and errors:
            fallback.setdefault("warning", "upstream_error: " + " | ".join(errors))
        payload = _normalize_response(path, fallback)
        self._send_json(200, payload)

    def _handle_events(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        init_message = {
            "type": "init",
            "data": _normalize_response("/api/status", _fallback_status()),
            "changes": [],
        }
        try:
            frame = f"data: {json.dumps(init_message, ensure_ascii=False)}\n\n".encode("utf-8")
            self.wfile.write(frame)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return

        while True:
            try:
                status, payload = _http_json("/api/status", method="GET", timeout=SSE_UPSTREAM_TIMEOUT)
                if status >= 400 or not isinstance(payload, dict):
                    payload = _fallback_status()
            except Exception:
                payload = _fallback_status()

            message = {
                "type": "update",
                "data": _normalize_response("/api/status", payload),
                "changes": [],
            }

            try:
                frame = f"data: {json.dumps(message, ensure_ascii=False)}\n\n".encode("utf-8")
                self.wfile.write(frame)
                self.wfile.write(b": ping\n\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return

            time.sleep(SSE_INTERVAL)

    def _handle_api(self, method: str) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = parsed.query

        if self._handle_auth_api(path, method):
            return

        if path == "/api/events" and method == "GET":
            self._handle_events()
            return

        if _requires_auth(path, method) and not self._is_authenticated():
            self._send_unauthorized()
            return

        if method == "DELETE" and path.startswith("/api/sessions/"):
            encoded = path[len("/api/sessions/"):]
            self._send_json(200, _delete_session_file(encoded))
            return

        # Force local data for endpoints where upstream lacks our agent data
        _force_local = {"/api/status", "/api/call_stats", "/api/sessions", "/api/skills", "/api/systems", "/api/changelog", "/api/models"}
        # Service control must always hit local fallback (real systemctl), never upstream
        if method == "GET" and (path in _force_local or path.startswith("/api/service/")):
            fallback = _fallback_payload(path, query)
            payload = _normalize_response(path, fallback)
            self._send_json(200, payload)
            return

        if method == "GET" and path.startswith("/api/"):
            self._proxy_json(path, query, method="GET")
            return

        if method == "POST" and path.startswith("/api/"):
            self._proxy_json(path, query, method="POST")
            return

        self.send_error(404, "Not Found")

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith("/api/"):
            self._handle_api("GET")
            return
        if parsed.path in {"/", ""}:
            self.path = "/index.html"
            super().do_GET()
            return
        static_exts = (
            ".html", ".css", ".js", ".mjs", ".json", ".png", ".jpg", ".jpeg", ".gif",
            ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".map"
        )
        if parsed.path.lower().endswith(static_exts):
            super().do_GET()
            return
        self.path = "/index.html"
        super().do_GET()

    def do_DELETE(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith("/api/"):
            self._handle_api("DELETE")
            return
        self.send_error(405, "Method Not Allowed")

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith("/api/"):
            self._handle_api("POST")
            return
        self.send_error(405, "Method Not Allowed")


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "1234"))
    server = ThreadingHTTPServer((host, port), PanelHandler)
    print(f"Panel server listening on http://{host}:{port}")
    server.serve_forever()
