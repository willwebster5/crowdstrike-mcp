"""
FalconClient — shared OAuth2 session with credential resolution chain.

Credential priority:
  1. Constructor parameters (``client_id``, ``client_secret``, ``base_url``)
  2. Environment variables (``FALCON_CLIENT_ID``, ``FALCON_CLIENT_SECRET``, ``FALCON_BASE_URL``)
  3. Credential file (``~/.config/falcon/credentials.json``)

All modules use ``self.client.auth_object`` when creating FalconPy service classes
so they all share a single OAuth2 token.
"""

import json
import os
import platform
import sys
from typing import Optional

from falconpy import OAuth2

try:
    import falconpy

    _FALCONPY_VERSION = getattr(falconpy, "__version__", "unknown")
except Exception:
    _FALCONPY_VERSION = "unknown"

from crowdstrike_mcp import __version__ as SERVER_VERSION

USER_AGENT = f"crowdstrike-custom-mcp/{SERVER_VERSION} (falconpy/{_FALCONPY_VERSION}; Python/{platform.python_version()})"

# Per-request ceiling for every outbound Falcon call, in seconds.
#
# falconpy defaults to timeout=None — no timeout at all — so a socket that goes
# quiet never returns and the calling thread is parked forever. That is how a
# transient network blip turned into a permanently wedged server: the call never
# came back, and nothing downstream could tell "slow" from "dead".
#
# This bounds a single HTTP request, not a whole search. NGSIEM searches poll,
# so a long hunt is many short requests governed by FALCON_MCP_NGSIEM_TIMEOUT;
# no individual one should ever take a minute.
DEFAULT_HTTP_TIMEOUT_SECONDS = 60


def _resolve_http_timeout() -> float:
    """Resolve the per-request timeout from the environment.

    Anything unusable — unset, unparseable, zero or negative — falls back to the
    default. Zero and negative are rejected rather than passed through because
    falconpy reads a falsy timeout as "no timeout", which would reinstate the
    original hang through configuration alone.
    """
    raw = os.environ.get("FALCON_MCP_HTTP_TIMEOUT", "").strip()
    if not raw:
        return DEFAULT_HTTP_TIMEOUT_SECONDS
    try:
        value = float(raw)
    except ValueError:
        print(
            f"[FalconClient] Ignoring FALCON_MCP_HTTP_TIMEOUT={raw!r} (not a number); "
            f"using {DEFAULT_HTTP_TIMEOUT_SECONDS}s",
            file=sys.stderr,
        )
        return DEFAULT_HTTP_TIMEOUT_SECONDS
    if value <= 0:
        print(
            f"[FalconClient] Ignoring FALCON_MCP_HTTP_TIMEOUT={raw!r} (must be > 0); "
            f"using {DEFAULT_HTTP_TIMEOUT_SECONDS}s",
            file=sys.stderr,
        )
        return DEFAULT_HTTP_TIMEOUT_SECONDS
    return value


class FalconClient:
    """Shared CrowdStrike API client with OAuth2 credential chain."""

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        base_url: Optional[str] = None,
        credential_file: Optional[str] = None,
    ):
        resolved = self._resolve_credentials(client_id, client_secret, base_url, credential_file)
        self._client_id = resolved["client_id"]
        self._client_secret = resolved["client_secret"]
        self._base_url = resolved["base_url"]
        self._auth: Optional[OAuth2] = None
        self._deferred = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @classmethod
    def deferred(cls) -> "FalconClient":
        """Create a credential-less instance for HTTP mode.

        Modules construct normally but must use BaseModule._get_auth()
        at call time instead of self.client.auth_object.
        """
        instance = cls.__new__(cls)
        instance._client_id = None
        instance._client_secret = None
        instance._base_url = None
        instance._auth = None
        instance._deferred = True
        return instance

    @property
    def auth_object(self) -> OAuth2:
        """Lazily create and cache a shared OAuth2 session."""
        if self._deferred:
            raise RuntimeError(
                "Cannot access auth_object on a deferred FalconClient. Use BaseModule._get_auth() which resolves from the session ContextVar."
            )
        if self._auth is None:
            # timeout propagates to every service class built with
            # auth_object=this, and to the token request itself, so this single
            # setting bounds every outbound call the server makes.
            self._auth = OAuth2(
                client_id=self._client_id,
                client_secret=self._client_secret,
                base_url=self._base_url,
                user_agent=USER_AGENT,
                timeout=_resolve_http_timeout(),
            )
        return self._auth

    def authenticate(self) -> bool:
        """Eagerly authenticate and verify credentials.

        Forces token generation so bad credentials fail fast at startup
        rather than on the first tool call.

        Returns:
            True if authentication succeeded.

        Raises:
            RuntimeError: If authentication fails.
        """
        auth = self.auth_object
        token = auth.token()
        if token.get("status_code", 0) == 201:
            print("[FalconClient] Authentication successful", file=sys.stderr)
            return True

        status = token.get("status_code", "unknown")
        errors = token.get("body", {}).get("errors", [])
        detail = errors[0].get("message", "Unknown error") if errors else "Unknown error"
        raise RuntimeError(
            f"CrowdStrike authentication failed (HTTP {status}): {detail}\n"
            f"  Client ID: {self._client_id[:8]}...\n"
            f"  Base URL: {self._base_url}\n"
            f"Verify your credentials and API client scopes."
        )

    @property
    def client_id(self) -> str:
        return self._client_id

    @property
    def client_secret(self) -> str:
        return self._client_secret

    @property
    def base_url(self) -> str:
        return self._base_url

    # ------------------------------------------------------------------
    # Credential resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_credentials(
        client_id: Optional[str],
        client_secret: Optional[str],
        base_url: Optional[str],
        credential_file: Optional[str],
    ) -> dict:
        """Resolve credentials using the priority chain.

        Priority: constructor params > env vars > credential file.
        """
        # 1. Constructor params (already provided)
        cid = client_id
        csec = client_secret
        burl = base_url

        # 2. Env var fallback
        if not cid:
            cid = os.environ.get("FALCON_CLIENT_ID")
        if not csec:
            csec = os.environ.get("FALCON_CLIENT_SECRET")
        if not burl:
            burl = os.environ.get("FALCON_BASE_URL")

        # 3. Credential file fallback
        if not cid or not csec:
            file_creds = FalconClient._load_credential_file(credential_file)
            if file_creds:
                if not cid:
                    cid = file_creds.get("falcon_client_id", "")
                if not csec:
                    csec = file_creds.get("falcon_client_secret", "")
                if not burl:
                    burl = file_creds.get("base_url")

        if not cid or not csec:
            raise ValueError(
                "CrowdStrike API credentials not found. Provide them via:\n"
                "  1. Constructor params (client_id, client_secret)\n"
                "  2. Env vars (FALCON_CLIENT_ID, FALCON_CLIENT_SECRET)\n"
                "  3. Credential file (~/.config/falcon/credentials.json)"
            )

        return {
            "client_id": cid,
            "client_secret": csec,
            "base_url": burl or "US1",
        }

    @staticmethod
    def _load_credential_file(path: Optional[str] = None) -> Optional[dict]:
        """Load credentials from a JSON file."""
        if not path:
            path = os.path.expanduser("~/.config/falcon/credentials.json")

        try:
            with open(path, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
            print(f"[FalconClient] Could not load {path}: {e}", file=sys.stderr)
            return None
