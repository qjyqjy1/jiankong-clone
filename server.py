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
import subprocess
import time
try:
    import tomllib
except ImportError:
    import tomli as tomllib
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
    "/api/agent_config",
}
PROTECTED_PREFIXES = ("/api/service/",)
PROTECTED_POST_PATHS = {"/api/agent_config/update"}


# ─── agent discovery configuration ────────────────────────────────────────────

AGENT_DISCOVERY: dict[str, dict[str, Any]] = {
    "openclaw": {
        "label": "OpenClaw",
        "process_patterns": ["openclaw"],
        "systemd_service": "openclaw-gateway.service",
        "listen_ports": [18789, 18791],
        "config_path": Path("/root/.openclaw/openclaw.json"),
        "icon": "🦞",
    },
    "codex": {
        "label": "Codex",
        "process_patterns": ["codex", "codex-webui"],
        "systemd_service": "codex-webui.service",
        "listen_ports": [9009],
        "config_path": Path("/root/.codex/config.toml"),
        "icon": "🤖",
    },
    "hermes": {
        "label": "Hermes",
        "process_patterns": ["hermes", "hermes-agent"],
        "systemd_service": None,
        "listen_ports": [],
        "config_path": Path("/root/.hermes/config.yaml"),
        "icon": "⚕️",
    },
}

# Dynamic skill directory scanning (only existing directories are scanned)
SKILL_SCAN_DIRS = [
    (Path("/root/.openclaw/workspace/skills"), "openclaw"),
    (Path("/root/.codex/skills"), "codex"),
    (Path("/root/.hermes/skills"), "hermes"),
]

# Agent-specific extra paths (sessions, logs, etc.)
AGENT_EXTRA_PATHS: dict[str, dict[str, Any]] = {
    "openclaw": {
        "sessions_dir": Path("/root/.openclaw/agents/main/sessions"),
        "logs_db": None,
        "auth_path": None,
    },
    "codex": {
        "sessions_dir": Path("/root/.codex/sessions"),
        "logs_db": Path("/root/.codex/logs_2.sqlite"),
        "auth_path": Path("/root/.codex/auth.json"),
    },
}


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
    if method == "GET" and (path in PROTECTED_GET_PATHS or path.startswith(PROTECTED_PREFIXES)):
        return True
    if method == "POST" and (path in PROTECTED_GET_PATHS or path in PROTECTED_POST_PATHS or path.startswith(PROTECTED_PREFIXES)):
        return True
    return False


# ─── helpers ──────────────────────────────────────────────────────────────────

def _replace_terms(obj: Any) -> Any:
    """Pass-through: no longer replaces openclaw with codex."""
    if isinstance(obj, dict):
        return {key: _replace_terms(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [_replace_terms(v) for v in obj]
    return obj


def _normalize_agent_name(name: str) -> str:
    """Normalize agent name aliases to canonical IDs from AGENT_DISCOVERY."""
    alias = (name or "").strip().lower()
    # Map aliases to discovered agent IDs
    for agent_id, cfg in AGENT_DISCOVERY.items():
        if alias == agent_id:
            return agent_id
        if alias == cfg.get("label", "").lower():
            return agent_id
    # Legacy aliases
    if alias in {"oc"}:
        return "openclaw"

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

    cpu_percent = psutil.cpu_percent(interval=None)
    load_avg = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)

    mem = psutil.virtual_memory()
    mem_used_gb = round(mem.used / (1024 ** 3), 1)
    mem_total_gb = round(mem.total / (1024 ** 3), 1)
    mem_percent = mem.percent

    disk = psutil.disk_usage("/")
    disk_used_gb = round(disk.used / (1024 ** 3), 1)
    disk_total_gb = round(disk.total / (1024 ** 3), 1)
    disk_percent = disk.percent

    net = psutil.net_io_counters()
    net_in = net.bytes_recv
    net_out = net.bytes_sent

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


# ─── agent discovery ──────────────────────────────────────────────────────────

def _discover_agents() -> list[dict[str, Any]]:
    """Scan all known agents in AGENT_DISCOVERY and return those that are actually present.

    Discovery checks:
    1. Process scan via ps aux
    2. systemd service active state
    3. Port listening check
    4. Config path existence

    Returns list of dicts with keys: id, label, icon, process_patterns,
    systemd_service, listen_ports, config_path, discovered
    """
    discovered: list[dict[str, Any]] = []

    # Read full process list once for efficiency
    ps_output = ""
    try:
        proc = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5)
        ps_output = proc.stdout.lower()
    except Exception:
        ps_output = ""

    for agent_id, cfg in AGENT_DISCOVERY.items():
        found = False

        # Check 1: process patterns
        for pattern in cfg.get("process_patterns", []):
            if pattern.lower() in ps_output:
                found = True
                break

        # Check 2: systemd service
        svc = cfg.get("systemd_service")
        if svc and not found:
            try:
                r = subprocess.run(
                    ["systemctl", "is-active", svc],
                    capture_output=True, text=True, timeout=3
                )
                if r.stdout.strip() == "active":
                    found = True
            except Exception:
                pass

        # Check 3: port listening
        if not found:
            for port in cfg.get("listen_ports", []):
                try:
                    import socket
                    with socket.create_connection(("127.0.0.1", int(port)), timeout=0.3):
                        found = True
                        break
                except Exception:
                    continue

        # Check 4: config path exists
        config_path = cfg.get("config_path")
        if config_path and Path(config_path).exists():
            found = True

        if found:
            discovered.append({
                "id": agent_id,
                "label": cfg["label"],
                "icon": cfg.get("icon", "🤖"),
                "process_patterns": cfg.get("process_patterns", []),
                "systemd_service": cfg.get("systemd_service"),
                "listen_ports": cfg.get("listen_ports", []),
                "config_path": str(config_path) if config_path else None,
                "discovered": True,
            })

    return discovered


def _detect_agent_running(agent_id: str) -> dict[str, Any]:
    """Detect if an agent process is running by scanning ps output using AGENT_DISCOVERY patterns."""
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
    cfg = AGENT_DISCOVERY.get(agent_id)
    if not cfg:
        return result

    patterns = cfg.get("process_patterns", [agent_id])

    try:
        cmd = ["ps", "aux"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        lines = proc.stdout.strip().split("\n")
        for line in lines[1:]:
            lower = line.lower()
            if any(p.lower() in lower for p in patterns) and "grep" not in lower and "ps aux" not in lower:
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


# ─── agent config reading ──────────────────────────────────────────────────────

def _read_agent_config(agent_id: str) -> dict[str, Any]:
    """Generic agent config reader. Dispatches to format-specific parsers.

    Returns dict with: model, provider, base_url, api_key, providers
    """
    cfg = AGENT_DISCOVERY.get(agent_id)
    if not cfg or not cfg.get("config_path"):
        return {"model": "", "provider": "", "base_url": "", "api_key": "", "providers": []}

    config_path = Path(cfg["config_path"])
    if not config_path.exists():
        return {"model": "", "provider": "", "base_url": "", "api_key": "", "providers": []}

    if agent_id == "codex":
        return _read_codex_config(config_path)
    if agent_id == "openclaw":
        return _read_openclaw_config(config_path)

    return {"model": "", "provider": "", "base_url": "", "api_key": "", "providers": []}


def _read_codex_config(config_path: Path) -> dict[str, Any]:
    """Read Codex config.toml."""
    result: dict[str, Any] = {"model": "", "provider": "", "base_url": "", "api_key": "", "providers": []}
    raw = _safe_text(config_path)
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
    extra = AGENT_EXTRA_PATHS.get("codex", {})
    auth_path = extra.get("auth_path")
    if auth_path and Path(auth_path).exists():
        try:
            auth = json.loads(_safe_text(Path(auth_path)) or "{}")
            if isinstance(auth, dict):
                api_key = str(auth.get("OPENAI_API_KEY") or auth.get("openai_api_key") or auth.get("api_key") or "").strip()
        except Exception:
            api_key = ""

    providers: list[dict[str, Any]] = []
    if isinstance(providers_cfg, dict):
        for provider_name, pcfg in providers_cfg.items():
            if not isinstance(pcfg, dict):
                continue
            p_base = str(pcfg.get("base_url", "") or "").strip()
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


def _read_openclaw_config(config_path: Path) -> dict[str, Any]:
    """Read OpenClaw config.json."""
    result: dict[str, Any] = {"model": "", "provider": "", "base_url": "", "api_key": "", "providers": []}
    raw = _safe_text(config_path)
    if not raw:
        return result

    config: dict[str, Any] = {}
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            config = parsed
    except Exception:
        return result

    # Extract model from agents.defaults.model.primary
    agents_cfg = config.get("agents", {})
    defaults = agents_cfg.get("defaults", {}) if isinstance(agents_cfg, dict) else {}
    model_cfg = defaults.get("model", {}) if isinstance(defaults, dict) else {}
    primary = model_cfg.get("primary", "") if isinstance(model_cfg, dict) else ""
    model = str(primary).strip()

    # Extract provider info from models.providers
    models_cfg = config.get("models", {})
    providers_cfg = models_cfg.get("providers", {}) if isinstance(models_cfg, dict) else {}
    providers_list: list[dict[str, Any]] = []
    if isinstance(providers_cfg, dict):
        for pname, pcfg in providers_cfg.items():
            if not isinstance(pcfg, dict):
                continue
            p_base = str(pcfg.get("baseUrl", "") or pcfg.get("base_url", "") or "").strip()
            p_key = str(pcfg.get("apiKey", "") or pcfg.get("api_key", "") or "").strip()
            p_models = pcfg.get("models", [])
            if isinstance(p_models, list):
                p_model_ids = [str(m.get("id", "")) for m in p_models if isinstance(m, dict)]
            else:
                p_model_ids = []
            providers_list.append({
                "name": pname,
                "base_url": p_base,
                "api_key": p_key,
                "models": p_model_ids,
            })

    # Use first provider as the "current" one
    if providers_list:
        result["provider"] = providers_list[0]["name"]
        result["base_url"] = providers_list[0]["base_url"]
        result["api_key"] = providers_list[0]["api_key"]

    result["model"] = model
    result["providers"] = providers_list
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
    """Build models payload by iterating over discovered agents."""
    now = time.time()
    agents = _discover_agents()

    agent_models: dict[str, str] = {}
    agent_model_lists: dict[str, list[str]] = {}
    available_models: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add_model(agent: str, model_id: str, provider_name: str, context_window: int = 0, reasoning: bool = False) -> None:
        clean_id = (model_id or "").strip()
        if not clean_id:
            return
        if clean_id not in agent_model_lists.get(agent, []):
            agent_model_lists.setdefault(agent, []).append(clean_id)
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

    for agent_info in agents:
        agent_id = agent_info["id"]
        agent_config = _read_agent_config(agent_id)

        model = str(agent_config.get("model") or "").strip()
        provider = str(agent_config.get("provider") or _short_provider_name(str(agent_config.get("base_url") or "")) or agent_info["label"])

        agent_models[agent_id] = model

        if model:
            add_model(agent_id, model, provider)

        # Custom providers
        for item in agent_config.get("providers", []):
            if not isinstance(item, dict):
                continue
            p_name = str(item.get("name") or agent_info["label"])
            p_model = str(item.get("model") or "").strip()
            if p_model:
                add_model(agent_id, p_model, p_name)

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
    """Read call statistics from agent trajectory files (OpenClaw) and session logs (Codex)."""
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
    agents = _discover_agents()

    by_source: dict[str, dict[str, int]] = {}
    for a in agents:
        by_source[a["id"]] = {"calls": 0, "input": 0, "output": 0, "cache": 0, "total": 0, "response_time": 0}

    result = {
        "period": period,
        "total_calls": 0,
        "total_input": 0,
        "total_output": 0,
        "total_cache": 0,
        "total_tokens": 0,
        "avg_response_time": 0,
        "total_response_time": 0,
        "by_source": by_source,
        "by_model": {},
        "scan_time": time.time(),
        "all_time_calls": 0,
    }

    for agent_info in agents:
        agent_id = agent_info["id"]
        extra = AGENT_EXTRA_PATHS.get(agent_id, {})
        sessions_dir = extra.get("sessions_dir")

        if not sessions_dir or not Path(sessions_dir).exists():
            continue

        # Read token usage from trajectory files (*.trajectory.jsonl)
        for traj_file in Path(sessions_dir).glob("*.trajectory.jsonl"):
            try:
                with open(traj_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except Exception:
                            continue
                        if entry.get("type") != "trace.artifacts":
                            continue

                        # Time filtering
                        if cutoff is not None:
                            ts_str = entry.get("ts", "")
                            if ts_str:
                                try:
                                    from datetime import datetime, timezone
                                    ts_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                                    ts_unix = ts_dt.timestamp()
                                    if ts_unix < cutoff:
                                        continue
                                except Exception:
                                    pass

                        usage = entry.get("data", {}).get("usage", {})
                        if not usage:
                            continue

                        inp = usage.get("input", 0)
                        out = usage.get("output", 0)
                        cache = usage.get("cacheRead", 0)
                        total = usage.get("total", 0)

                        # Get model info
                        model_id = entry.get("modelId", "unknown")

                        result["by_source"][agent_id]["calls"] += 1
                        result["by_source"][agent_id]["input"] += inp
                        result["by_source"][agent_id]["output"] += out
                        result["by_source"][agent_id]["cache"] += cache
                        result["by_source"][agent_id]["total"] += total

                        # By model
                        if model_id not in result["by_model"]:
                            result["by_model"][model_id] = {"calls": 0, "input": 0, "output": 0, "cache": 0, "total": 0}
                        result["by_model"][model_id]["calls"] += 1
                        result["by_model"][model_id]["input"] += inp
                        result["by_model"][model_id]["output"] += out
                        result["by_model"][model_id]["cache"] += cache
                        result["by_model"][model_id]["total"] += total

                        result["total_calls"] += 1
                        result["total_input"] += inp
                        result["total_output"] += out
                        result["total_cache"] += cache
                        result["total_tokens"] += total
                        result["all_time_calls"] += 1
            except Exception:
                pass

        # Also try SQLite logs_db if available (Codex legacy)
        logs_db = extra.get("logs_db")
        if logs_db and Path(logs_db).exists():
            try:
                conn = sqlite3.connect(f"file:{logs_db}?mode=ro", uri=True, timeout=5)
                conn.row_factory = sqlite3.Row
                try:
                    all_row = conn.execute("SELECT COUNT(*) as cnt FROM logs").fetchone()
                    if all_row and all_row["cnt"]:
                        result["all_time_calls"] += all_row["cnt"]
                except Exception:
                    pass
                conn.close()
            except Exception:
                pass

    return result

# ─── sessions from filesystem ─────────────────────────────────────────────────

def _scan_sessions() -> list[dict[str, Any]]:
    """Scan session directories from discovered agents."""
    sessions: list[dict[str, Any]] = []

    for agent_id, extra in AGENT_EXTRA_PATHS.items():
        sessions_dir = extra.get("sessions_dir")
        if not sessions_dir or not Path(sessions_dir).exists():
            continue

        import glob
        pattern = str(Path(sessions_dir) / "**" / "*.jsonl")
        files = sorted(glob.glob(pattern, recursive=True), reverse=True)

        for fpath in files[:100]:
            try:
                p = Path(fpath)
                stat = p.stat()
                size = stat.st_size
                mtime = stat.st_mtime

                rel = p.relative_to(Path(sessions_dir))
                parts = rel.parts
                date_str = "/".join(parts[:3]) if len(parts) >= 3 else ""

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

                session_id = p.stem
                channel = "unknown"
                status_str = "活跃"
                model_name = ""
                try:
                    if first_line:
                        data = json.loads(first_line)
                        channel = data.get("channel", data.get("source", "unknown"))
                        model_name = data.get("model", "")
                except Exception:
                    pass

                age_hours = (time.time() - mtime) / 3600
                if age_hours > 24:
                    status_str = "空闲"

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
                    "agent": agent_id,
                    "agent_id": agent_id,
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

    # Search across all agent session dirs
    for agent_id, extra in AGENT_EXTRA_PATHS.items():
        sessions_dir = extra.get("sessions_dir")
        if not sessions_dir or not Path(sessions_dir).exists():
            continue

        matches = [p for p in Path(sessions_dir).rglob("*.jsonl") if p.stem == clean_key]
        if not matches:
            continue
        if len(matches) > 1:
            return {"status": "error", "success": False, "error": "匹配到多个会话文件，拒绝删除"}

        target = matches[0].resolve()
        try:
            target.relative_to(Path(sessions_dir).resolve())
        except ValueError:
            return {"status": "error", "success": False, "error": "会话路径越界"}

        try:
            target.unlink()
        except Exception as exc:
            return {"status": "error", "success": False, "error": f"删除失败：{exc}"}

        return {"status": "success", "success": True, "message": "会话文件已删除", "deleted": str(target)}

    return {"status": "error", "success": False, "error": "未找到会话文件"}


def _format_bytes(n: int) -> str:
    if n < 1024:
        return f"{n}B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f}KB"
    return f"{n / (1024 * 1024):.1f}MB"


# ─── skills from filesystem ───────────────────────────────────────────────────

def _scan_skills() -> list[dict[str, Any]]:
    """Scan skill directories from SKILL_SCAN_DIRS for existing directories."""
    skills: list[dict[str, Any]] = []

    for sdir, source in SKILL_SCAN_DIRS:
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
            bundled = False
            eligible = True
            disabled = False
            icon = "fa-puzzle-piece"
            category = ""

            if skill_md.exists():
                try:
                    content = skill_md.read_text(encoding="utf-8", errors="replace")
                    fm_match = re.match(r"^---\s*\n(.*?)\n---", content, re.DOTALL)
                    if fm_match:
                        fm_text = fm_match.group(1)
                        desc_m = re.search(r"(?m)^\s*description:\s*['\"]?(.+?)['\"]?\s*$", fm_text)
                        if desc_m:
                            description = desc_m.group(1).strip().strip("'\"")
                        name_m = re.search(r"(?m)^\s*name:\s*['\"]?(.+?)['\"]?\s*$", fm_text)
                        if name_m:
                            name = name_m.group(1).strip().strip("'\"")
                        icon_m = re.search(r"(?m)^\s*icon:\s*['\"]?(.+?)['\"]?\s*$", fm_text)
                        if icon_m:
                            icon = icon_m.group(1).strip().strip("'\"")
                        cat_m = re.search(r"(?m)^\s*(category|tags):\s*['\"]?(.+?)['\"]?\s*$", fm_text)
                        if cat_m:
                            category = cat_m.group(2).strip().strip("'\"")

                    if not description:
                        for line in content.split("\n"):
                            line = line.strip()
                            if line and not line.startswith("#") and not line.startswith("---"):
                                description = line[:120]
                                break
                except Exception:
                    pass

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
    """Return list of running systemd services relevant to the panel.

    Automatically includes services from discovered agents + panel itself.
    """
    services: list[dict[str, Any]] = []

    # Build known_services from discovered agents
    known_services: dict[str, dict[str, Any]] = {}

    # Add discovered agents' systemd services
    agents = _discover_agents()
    for agent_info in agents:
        svc = agent_info.get("systemd_service")
        if svc:
            known_services[svc] = {
                "name": f"{agent_info['label']} 服务",
                "icon": agent_info.get("icon", "🤖"),
                "ports": agent_info.get("listen_ports", []),
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



def _current_panel_version() -> str:
    return "v1.5.0"


# ─── projects (workspace scan) ───────────────────────────────────────────────

def _scan_projects() -> list[dict[str, Any]]:
    """Scan known project directories and attach service port hints."""
    projects = []

    # Build project list from discovered agents
    interesting: dict[str, dict[str, Any]] = {}
    agents = _discover_agents()
    for agent_info in agents:
        agent_id = agent_info["id"]
        cfg = AGENT_DISCOVERY.get(agent_id, {})
        config_path = cfg.get("config_path")
        if config_path:
            config_dir = str(Path(config_path).parent)
            interesting[config_dir] = {
                "name": f"{agent_info['label']} 配置",
                "icon": cfg.get("icon", "⚙️"),
                "tags": ["配置", agent_info["label"]],
                "ports": cfg.get("listen_ports", []),
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
    agents = _discover_agents()
    local_models = _local_models_payload()
    call_stats = _read_call_stats()

    agents_status: dict[str, Any] = {}
    for agent_info in agents:
        agent_id = agent_info["id"]
        proc = _detect_agent_running(agent_id)
        agent_model = str((local_models.get("agent_models") or {}).get(agent_id) or "unknown")
        agent_call_stats = call_stats.get("by_source", {}).get(agent_id, {})

        agents_status[agent_id] = {
            "name": agent_info["label"],
            "status": "online" if proc["running"] else "stopped",
            "cpu_usage": round(proc["cpu_usage"], 1),
            "memory_usage": round(proc["memory_usage"], 1),
            "disk_usage": 0,
            "network_in": 0,
            "network_out": 0,
            "uptime": proc["uptime_seconds"],
            "tasks": [],
            "last_update": now,
            "api_calls": agent_call_stats.get("calls", 0),
            "total_response_time": agent_call_stats.get("response_time", 0),
            "successful_calls": agent_call_stats.get("calls", 0),
            "uptime_seconds": proc["uptime_seconds"],
            "start_time": time.strftime("%a %b %d %H:%M:%S %Y", time.localtime(now - proc["uptime_seconds"])),
            "mem_kb": proc["mem_kb"],
            "mem_mb": proc["mem_mb"],
            "version": "unknown",
            "disk_size": "--",
            "model": agent_model,
            "running": proc["running"],
            "pid": proc["pid"],
        }

    # Use first discovered agent's model as primary
    primary_model = "unknown"
    for agent_info in agents:
        m = str((local_models.get("agent_models") or {}).get(agent_info["id"]) or "").strip()
        if m:
            primary_model = m
            break

    return {
        "agents": agents_status,
        "system_info": sys_info,
        "model_stats": {
            "total_calls": call_stats.get("total_calls", 0),
            "avg_response_time": call_stats.get("avg_response_time", 0),
            "success_rate": 100,
            "active_connections": 0,
            "model_status": "running",
            "model_id": primary_model,
            "model_name": primary_model,
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


# ─── agent config read/write ──────────────────────────────────────────────────

def _get_agent_config(agent_id: str) -> dict[str, Any]:
    """Get full config for an agent, including sensitive fields."""
    agent_cfg = AGENT_DISCOVERY.get(agent_id)
    if not agent_cfg:
        return {"error": f"未知智能体: {agent_id}"}

    config_path = agent_cfg.get("config_path")
    if not config_path or not Path(config_path).exists():
        return {
            "agent_id": agent_id,
            "label": agent_cfg.get("label", agent_id),
            "config_path": str(config_path) if config_path else None,
            "config_exists": False,
            "model": "",
            "provider": "",
            "base_url": "",
            "api_key": "",
            "message": "配置文件不存在，请手动配置",
        }

    runtime = _read_agent_config(agent_id)
    return {
        "agent_id": agent_id,
        "label": agent_cfg.get("label", agent_id),
        "config_path": str(config_path),
        "config_exists": True,
        "model": runtime.get("model", ""),
        "provider": runtime.get("provider", ""),
        "base_url": runtime.get("base_url", ""),
        "api_key": runtime.get("api_key", ""),
        "systemd_service": agent_cfg.get("systemd_service", ""),
        "listen_ports": agent_cfg.get("listen_ports", []),
    }


def _update_agent_config(agent_id: str, updates: dict[str, Any]) -> dict[str, Any]:
    """Update agent config file. Supports codex (toml) and openclaw (yaml)."""
    agent_cfg = AGENT_DISCOVERY.get(agent_id)
    if not agent_cfg:
        return {"success": False, "error": f"未知智能体: {agent_id}"}

    config_path = agent_cfg.get("config_path")
    if not config_path:
        return {"success": False, "error": "该智能体不支持本地配置修改"}

    config_path = Path(config_path)

    if agent_id == "codex":
        return _update_codex_config(config_path, updates)
    elif agent_id == "openclaw":
        return _update_openclaw_config(config_path, updates)
    else:
        return {"success": False, "error": f"不支持的智能体类型: {agent_id}"}


def _update_codex_config(config_path: Path, updates: dict[str, Any]) -> dict[str, Any]:
    """Update Codex config.toml."""
    import shutil

    raw = _safe_text(config_path) if config_path.exists() else ""
    try:
        config = tomllib.loads(raw) if raw else {}
    except Exception:
        config = {}
    if not isinstance(config, dict):
        config = {}

    # Update top-level fields
    if "model" in updates:
        config["model"] = updates["model"]
    if "model_provider" in updates:
        config["model_provider"] = updates["model_provider"]

    # Update model_providers
    provider_name = updates.get("model_provider") or config.get("model_provider", "")
    if provider_name and ("base_url" in updates or "model_provider" in updates):
        providers_cfg = config.get("model_providers", {})
        if not isinstance(providers_cfg, dict):
            providers_cfg = {}
        provider_cfg = providers_cfg.get(provider_name, {}) if isinstance(providers_cfg.get(provider_name), dict) else {}
        if "base_url" in updates:
            provider_cfg["base_url"] = updates["base_url"]
        providers_cfg[provider_name] = provider_cfg
        config["model_providers"] = providers_cfg

    # Update auth.json if api_key provided
    if "api_key" in updates and updates["api_key"]:
        extra = AGENT_EXTRA_PATHS.get("codex", {})
        auth_path = extra.get("auth_path")
        if auth_path:
            auth_path = Path(auth_path)
            auth_data = {}
            if auth_path.exists():
                try:
                    auth_data = json.loads(_safe_text(auth_path) or "{}")
                except Exception:
                    auth_data = {}
            auth_data["OPENAI_API_KEY"] = updates["api_key"]
            auth_path.parent.mkdir(parents=True, exist_ok=True)
            auth_path.write_text(json.dumps(auth_data, indent=2, ensure_ascii=False), encoding="utf-8")

    # Write TOML (tomllib has no dump, use manual write)
    toml_str = _dict_to_toml(config)

    # Backup
    if config_path.exists():
        backup_path = config_path.with_suffix(".toml.bak")
        shutil.copy2(str(config_path), str(backup_path))

    config_path.write_text(toml_str, encoding="utf-8")
    return {"success": True, "message": f"Codex 配置已更新: {config_path}"}


def _update_openclaw_config(config_path: Path, updates: dict[str, Any]) -> dict[str, Any]:
    """Update OpenClaw config.json."""
    import shutil

    raw = _safe_text(config_path) if config_path.exists() else ""
    config: dict[str, Any] = {}
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            config = parsed
    except Exception:
        config = {}

    # Update model at agents.defaults.model.primary
    if "model" in updates:
        agents_cfg = config.setdefault("agents", {})
        defaults = agents_cfg.setdefault("defaults", {})
        model_cfg = defaults.setdefault("model", {})
        model_cfg["primary"] = updates["model"]

    # Update provider info at models.providers.<name>
    provider_name = updates.get("model_provider", "")
    if provider_name and ("base_url" in updates or "api_key" in updates):
        models_cfg = config.setdefault("models", {})
        providers_cfg = models_cfg.setdefault("providers", {})
        p_cfg = providers_cfg.get(provider_name, {}) if isinstance(providers_cfg.get(provider_name), dict) else {}
        if "base_url" in updates:
            p_cfg["baseUrl"] = updates["base_url"]
        if "api_key" in updates:
            p_cfg["apiKey"] = updates["api_key"]
        providers_cfg[provider_name] = p_cfg

    # Backup
    if config_path.exists():
        backup_path = config_path.with_suffix(".json.bak")
        shutil.copy2(str(config_path), str(backup_path))

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"success": True, "message": f"OpenClaw 配置已更新: {config_path}"}


def _dict_to_toml(d: dict[str, Any], prefix: str = "") -> str:
    """Simple TOML serializer."""
    lines: list[str] = []
    # First pass: simple key-value pairs
    for key, value in d.items():
        if isinstance(value, dict):
            # Check if it's a nested table or inline table
            is_table = any(isinstance(v, dict) for v in value.values())
            if is_table:
                lines.append(f"\n[{key}]")
                for k2, v2 in value.items():
                    if isinstance(v2, dict):
                        lines.append(f"\n[{key}.{k2}]")
                        for k3, v3 in v2.items():
                            lines.append(f"{k3} = {_toml_value(v3)}")
                    else:
                        lines.append(f"{k2} = {_toml_value(v2)}")
            else:
                # Inline table
                inner = ", ".join('%s = %s' % (k2, _toml_value(v2)) for k2, v2 in value.items())
                lines.append("%s = { %s }" % (key, inner))
        elif isinstance(value, list):
            lines.append(f"{key} = {_toml_value(value)}")
        else:
            lines.append(f"{key} = {_toml_value(value)}")
    return "\n".join(lines) + "\n"


def _toml_value(v: Any) -> str:
    """Convert Python value to TOML literal."""
    if isinstance(v, str):
        return f'"{v}"'
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    return f'"{str(v)}"'


def _fetch_provider_models(base_url: str, api_key: str = "") -> dict[str, Any]:
    """Fetch available models from a provider URL."""
    if not base_url:
        return {"success": False, "error": "base_url 不能为空"}
    url = base_url.rstrip("/") + "/models"
    req = urllib.request.Request(url=url, method="GET")
    req.add_header("Accept", "application/json")
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")
    try:
        with urllib.request.urlopen(req, timeout=LOCAL_MODEL_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        payload = json.loads(body) if body else {}
        models = _extract_model_entries(payload)
        return {"success": True, "models": models, "count": len(models)}
    except urllib.error.URLError as e:
        return {"success": False, "error": f"连接失败: {e.reason}"}
    except json.JSONDecodeError as e:
        return {"success": False, "error": f"JSON 解析失败: {e}"}
    except Exception as e:
        return {"success": False, "error": f"未知错误: {e}"}


# ─── fallback payload router ──────────────────────────────────────────────────

def _fallback_payload(api_path: str, query: str = "", post_body: dict[str, Any] | None = None) -> Any:
    q = urllib.parse.parse_qs(query, keep_blank_values=True)
    service_id = (q.get("id") or ["服务"])[0]
    model_id = (q.get("model_id") or ["未知模型"])[0]
    skill_slug = (q.get("slug") or ["未知技能"])[0]
    period = (q.get("period") or ["all"])[0]
    agent_id = (q.get("agent_id") or [""])[0]
    base_url = (q.get("base_url") or [""])[0]
    api_key = (q.get("api_key") or [""])[0]

    # ── Agent Config API ──
    if api_path == "/api/agent_config":
        # GET: read config
        if not agent_id:
            # Return all agents' configs
            return {aid: _get_agent_config(aid) for aid in AGENT_DISCOVERY}
        return _get_agent_config(agent_id)

    if api_path == "/api/agent_config/update":
        if not post_body:
            return {"success": False, "error": "需要 POST body"}
        aid = post_body.get("agent_id", "")
        if not aid:
            return {"success": False, "error": "缺少 agent_id"}
        updates = {k: v for k, v in post_body.items() if k != "agent_id"}
        result = _update_agent_config(aid, updates)
        # Clear model cache after config change
        _MODEL_CACHE["expires_at"] = 0
        return result

    if api_path == "/api/agent_config/fetch_models":
        return _fetch_provider_models(base_url, api_key)


    # ── File Manager API ──
    # Security: protected paths that cannot be deleted
    _PROTECTED_PATHS = {
        "/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64",
        "/proc", "/root", "/run", "/sbin", "/sys", "/usr", "/var",
        "/home", "/opt", "/mnt", "/media", "/srv",
        "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/fstab",
        "/etc/ssh", "/etc/nginx", "/etc/systemd",
        "/var/log", "/var/lib", "/var/spool",
        "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/local",
    }

    def _is_protected_delete(path_str: str) -> bool:
        """Check if a path is protected from deletion."""
        p = Path(path_str).resolve()
        # Always protect the panel directory itself
        if str(p) == str(BASE_DIR) or str(p).startswith(str(BASE_DIR) + "/"):
            return True
        # Protect system-critical paths
        for protected in _PROTECTED_PATHS:
            pp = Path(protected).resolve()
            if p == pp or str(p).startswith(str(pp) + "/"):
                return True
        return False

    if api_path == "/api/files":
        # GET: list files, POST: write/delete
        from pathlib import Path as _P
        rel_path = (q.get("path") or [""])[0]
        # Security: only allow /root/.openclaw/workspace/
        base = Path("/")
        target = (base / rel_path.lstrip("/")).resolve()
        if not str(target).startswith(str(base)):
            return {"success": False, "error": "路径不在允许范围内"}
        if not target.exists():
            return {"success": False, "error": "路径不存在"}
        if target.is_dir():
            items = []
            for item in sorted(target.iterdir()):
                try:
                    st = item.stat()
                    items.append({
                        "name": item.name,
                        "is_dir": item.is_dir(),
                        "size": st.st_size,
                        "size_human": _format_bytes(st.st_size),
                        "modified": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),
                        "path": str(item.relative_to(base)),
                    })
                except Exception:
                    continue
            return {"success": True, "items": items, "path": str(target.relative_to(base))}
        else:
            try:
                content = target.read_text(encoding="utf-8", errors="replace")
                return {"success": True, "content": content, "path": str(target.relative_to(base))}
            except Exception as e:
                return {"success": False, "error": str(e)}

    if api_path == "/api/files/write":
        if not post_body:
            return {"success": False, "error": "需要 POST body"}
        rel_path = post_body.get("path", "")
        file_content = post_body.get("content", "")
        base = Path("/")
        target = (base / rel_path.lstrip("/")).resolve()
        if not str(target).startswith(str(base)):
            return {"success": False, "error": "路径不在允许范围内"}
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(file_content, encoding="utf-8")
            return {"success": True, "message": "已保存"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    if api_path == "/api/files/delete":
        if not post_body:
            return {"success": False, "error": "需要 POST body"}
        rel_path = post_body.get("path", "")
        base = Path("/")
        target = (base / rel_path.lstrip("/")).resolve()
        if not str(target).startswith(str(base)):
            return {"success": False, "error": "路径不在允许范围内"}
        if _is_protected_delete(str(target)):
            return {"success": False, "error": "系统关键路径，禁止删除"}
        try:
            import shutil
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()
            return {"success": True, "message": "已删除"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    if api_path == "/api/files/mkdir":
        if not post_body:
            return {"success": False, "error": "需要 POST body"}
        rel_path = post_body.get("path", "")
        base = Path("/")
        target = (base / rel_path.lstrip("/")).resolve()
        if not str(target).startswith(str(base)):
            return {"success": False, "error": "路径不在允许范围内"}
        try:
            target.mkdir(parents=True, exist_ok=True)
            return {"success": True, "message": "目录已创建"}
        except Exception as e:
            return {"success": False, "error": str(e)}

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
            "managedSkillsDir": str(SKILL_SCAN_DIRS[0][0]) if SKILL_SCAN_DIRS else "",
            "skills": _scan_skills(),
        }
    if api_path == "/api/systems":
        return {
            "services": _scan_services(),
            "projects": _scan_projects(),
            "skills": _scan_skills(),
            "uptime": _format_uptime(_get_system_info().get("server_uptime_seconds", 0)),
        }
    if api_path == "/api/switch_model":
        aid = agent_id or q.get("agent", [""])[0]
        mid = model_id or q.get("model", [""])[0]
        if not aid or not mid:
            return {"success": False, "error": "缺少 agent_id 或 model_id"}
        result = _update_agent_config(aid, {"model": mid})
        _MODEL_CACHE["expires_at"] = 0
        return result
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

        # Build service-to-unit map from discovered agents
        service_to_unit: dict[str, str] = {}
        for agent_id, cfg in AGENT_DISCOVERY.items():
            svc = cfg.get("systemd_service")
            if svc:
                service_to_unit[agent_id] = svc
                # Also map without -service suffix variants
                service_to_unit[svc.replace(".service", "")] = svc

        # Panel server itself — just return info, don't actually kill it
        if service_id == "panel-server":
            return {"success": True, "message": "面板服务运行中（PID: {}）".format(os.getpid())}

        unit = service_to_unit.get(service_id)
        if unit is None:
            return {"success": False, "message": f"拒绝操作未知服务：{service_id}"}

        if action == "status":
            try:
                r = subprocess.run(
                    ["systemctl", "is-active", unit],
                    capture_output=True, text=True, timeout=5
                )
                active = r.stdout.strip() == "active"
                return {"success": True, "message": f"{service_id} 状态: {'运行中' if active else '已停止'}", "active": active}
            except Exception as e:
                return {"success": False, "message": f"查询状态失败: {e}"}

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
    """Normalize response without hardcoded agent names.

    Now handles all discovered agents dynamically.
    """
    data = _replace_terms(payload)

    if path == "/api/status" and isinstance(data, dict):
        agents = data.setdefault("agents", {})
        if isinstance(agents, dict):
            # Set names from AGENT_DISCOVERY for any known agents
            for agent_id, cfg in AGENT_DISCOVERY.items():
                if agent_id in agents and isinstance(agents[agent_id], dict):
                    agents[agent_id]["name"] = cfg["label"]

        if "model_stats" in data and isinstance(data["model_stats"], dict):
            model_stats = data["model_stats"]
            if "model_name" in model_stats and isinstance(model_stats["model_name"], str):
                pass  # No replacement needed anymore

    if path == "/api/models" and isinstance(data, dict):
        available = data.get("available_models")
        if not isinstance(available, list):
            if isinstance(data.get("models"), list):
                data["available_models"] = data.get("models")
            else:
                data["available_models"] = []

    if path == "/api/call_stats" and isinstance(data, dict):
        pass  # by_source keys are already agent IDs

    return data


def _map_query_for_upstream(path: str, query: str) -> str:
    if not query:
        return ""
    q = urllib.parse.parse_qs(query, keep_blank_values=True)
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
        _force_local = {"/api/status", "/api/call_stats", "/api/sessions", "/api/skills", "/api/systems", "/api/models", "/api/agent_config", "/api/agent_config/fetch_models", "/api/files", "/api/files/write", "/api/files/delete", "/api/files/mkdir", "/api/files/upload"}
        # Service control must always hit local fallback (real systemctl), never upstream
        if method == "GET" and (path in _force_local or path.startswith("/api/service/")):
            fallback = _fallback_payload(path, query)
            payload = _normalize_response(path, fallback)
            self._send_json(200, payload)
            return

        if method == "GET" and path.startswith("/api/"):
            self._proxy_json(path, query, method="GET")
            return


        if method == "POST" and path == "/api/files/upload":
            import cgi
            content_type = self.headers.get("Content-Type", "")
            base = Path("/")
            # Support both multipart and JSON base64 upload
            if content_type.startswith("application/json"):
                body = self._read_json_body()
                rel_path = body.get("path", "")
                file_content = body.get("content", "")
                encoding = body.get("encoding", "utf-8")
                if not rel_path:
                    self._send_json(400, {"success": False, "error": "缺少 path"})
                    return
                target = (base / rel_path).resolve()
                if not str(target).startswith(str(base)):
                    self._send_json(400, {"success": False, "error": "路径不在允许范围内"})
                    return
                try:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if encoding == "base64":
                        import base64 as _b64
                        raw = _b64.b64decode(file_content)
                        with open(target, "wb") as f:
                            f.write(raw)
                    else:
                        target.write_text(file_content, encoding="utf-8")
                    self._send_json(200, {"success": True, "message": "上传成功", "path": str(target.relative_to(base))})
                except Exception as e:
                    self._send_json(500, {"success": False, "error": str(e)})
                return
            if "multipart/form-data" in content_type:
                # Parse multipart form data
                form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={"REQUEST_METHOD": "POST", "CONTENT_TYPE": content_type})
                rel_path = ""
                file_data = None
                file_name = ""
                for key in form.keys():
                    item = form[key]
                    if key == "path":
                        rel_path = item.value if isinstance(item.value, str) else ""
                    elif key == "file":
                        file_data = item.file.read() if item.file else None
                        file_name = item.filename or ""
                base = Path("/")
                if rel_path:
                    target = (base / rel_path).resolve()
                else:
                    target = base / file_name
                target = target.resolve()
                if not str(target).startswith(str(base)):
                    self._send_json(400, {"success": False, "error": "路径不在允许范围内"})
                    return
                try:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with open(target, "wb") as f:
                        f.write(file_data or b"")
                    self._send_json(200, {"success": True, "message": "上传成功", "path": str(target.relative_to(base))})
                except Exception as e:
                    self._send_json(500, {"success": False, "error": str(e)})
                return
        if method == "POST" and path.startswith("/api/"):
            if path in {"/api/agent_config/update", "/api/agent_config/fetch_models"}:
                body = self._read_json_body()
                fallback = _fallback_payload(path, query, post_body=body)
                payload = _normalize_response(path, fallback)
                self._send_json(200, payload)
                return
            # File manager API — handle locally
            if path in {"/api/files/write", "/api/files/delete", "/api/files/mkdir"}:
                body = self._read_json_body()
                result = _fallback_payload(path, query, post_body=body)
                self._send_json(200, result)
                return
            # Upload already handled above
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
