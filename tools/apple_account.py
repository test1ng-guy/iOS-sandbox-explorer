#!/usr/bin/env python3
"""
Apple ID Authentication & Free Developer Signing Module.

Implements:
  - GSA (GrandSlam Authentication) via SRP-6a protocol
  - Two-Factor Authentication (Trusted Device / SMS)
  - Apple Developer Portal API (certificates, profiles, devices)
  - Full IPA signing pipeline via Apple's free developer program

Anisette data is obtained from omnisette-server (Docker or native binary).
Credentials are NEVER stored to disk — only held in memory for the session.

Dependencies: srp, pbkdf2, cryptography, requests
"""

import atexit
import base64
import getpass
import hashlib
import hmac as hmac_mod
import json
import os
import platform
import plistlib
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[!] 'requests' not installed. Run: pip install requests")
    sys.exit(1)

# Module-level session with SSL verification disabled (handles self-signed certs)
_session = requests.Session()
_session.verify = False


# ─── Constants ────────────────────────────────────────────────────────────────

GSA_URL = "https://gsa.apple.com/grandslam/GsService2"
DEV_PORTAL_BASE = "https://developerservices2.apple.com/services/QH65B2"
CLIENT_ID = "XABBG36SBA"
PROTOCOL_VERSION = "QH65B2"

CLIENT_INFO = (
    "<MacBookPro15,1> <Mac OS X;13.5;22G74> "
    "<com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>"
)
XCODE_VERSION = "15.2 (15C500b)"
USER_AGENT_GSA = "akd/1.0 CFNetwork/1494 Darwin/23.4.0"

DEFAULT_ANISETTE_URL = "http://localhost:6969"


# ─── Anisette Provider ───────────────────────────────────────────────────────

class AnisetteProvider:
    """
    Fetches anisette data (X-Apple-I-MD, X-Apple-I-MD-M) from omnisette-server.
    
    Setup (one-time):
        docker run -d --restart always --name omnisette \\
          -p 6969:80 --volume omnisette_data:/opt/omnisette-server/lib \\
          ghcr.io/sidestore/omnisette-server:latest
    """

    def __init__(self, server_url: str = DEFAULT_ANISETTE_URL):
        self.server_url = server_url.rstrip("/")
        self.device_id = str(uuid.uuid4()).upper()
        self.local_user_id = str(uuid.uuid4()).upper()

    def fetch(self) -> dict:
        """Fetch fresh anisette data from omnisette-server."""
        try:
            r = _session.get(self.server_url, timeout=10)
            r.raise_for_status()
            data = r.json()
        except requests.ConnectionError:
            raise ConnectionError(
                f"Cannot connect to anisette server at {self.server_url}\n"
                f"Start one with:\n"
                f"  docker run -d --restart always --name omnisette \\\n"
                f"    -p 6969:80 --volume omnisette_data:/opt/omnisette-server/lib \\\n"
                f"    ghcr.io/sidestore/omnisette-server:latest"
            )
        except Exception as e:
            raise RuntimeError(f"Anisette fetch failed: {e}")

        return data

    def generate_headers(self) -> dict:
        """Generate full set of Apple auth headers using anisette data."""
        anisette = self.fetch()
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        # Remove +00:00 and add Z
        if now.endswith("+00:00"):
            now = now[:-6] + "Z"

        return {
            "X-Apple-I-Client-Time": now,
            "X-Apple-I-TimeZone": "UTC",
            "X-Apple-Locale": "en_US",
            "X-Apple-I-MD": anisette["X-Apple-I-MD"],
            "X-Apple-I-MD-M": anisette["X-Apple-I-MD-M"],
            "X-Apple-I-MD-LU": base64.b64encode(self.local_user_id.encode()).decode(),
            "X-Apple-I-MD-RINFO": "17106176",
            "X-Apple-I-SRL-NO": "0",
            "X-Mme-Device-Id": self.device_id,
        }

    def generate_cpd(self) -> dict:
        """Generate Client Provided Data dict for GSA requests."""
        h = self.generate_headers()
        h.update({
            "bootstrap": True,
            "icscrec": True,
            "pbe": False,
            "prkgen": True,
            "svct": "iCloud",
            "loc": "en_US",
        })
        return h

    @staticmethod
    def check_server(url: str = DEFAULT_ANISETTE_URL) -> bool:
        """Check if anisette server is reachable."""
        try:
            r = _session.get(url, timeout=3)
            return r.status_code == 200
        except Exception:
            return False


class NativeAnisetteProvider(AnisetteProvider):
    """
    Native macOS anisette provider — calls AOSKit.framework directly.
    No Docker required. Works on macOS 12+ with SIP enabled.

    AOSUtilities.retrieveOTPHeadersForDSID: returns a fresh OTP + stable
    Machine ID on every call. AKDevice provides real device identifiers.
    """

    _HELPER_SRC = Path(__file__).parent / "anisette_helper.m"
    _HELPER_BIN = Path(__file__).parent / "anisette_helper"

    def __init__(self):
        self._ensure_built()
        data = self._run()
        # Use real stable identifiers from AuthKit instead of random UUIDs
        self.device_id    = data.get("X-Mme-Device-Id",    str(uuid.uuid4()).upper())
        self.local_user_id = data.get("X-Apple-I-MD-LU",  str(uuid.uuid4()).upper())
        self._extra = {
            k: v for k, v in data.items()
            if k in ("X-Mme-Client-Info", "X-Apple-SRL-NO")
        }

    def fetch(self) -> dict:
        """Call native helper to get a fresh OTP + stable Machine ID."""
        data = self._run()
        return {
            "X-Apple-I-MD":   data["X-Apple-I-MD"],
            "X-Apple-I-MD-M": data["X-Apple-I-MD-M"],
        }

    def generate_headers(self) -> dict:
        """Generate auth headers with real device metadata from AuthKit."""
        h = super().generate_headers()
        if self._extra.get("X-Mme-Client-Info"):
            h["X-Mme-Client-Info"] = self._extra["X-Mme-Client-Info"]
        if self._extra.get("X-Apple-SRL-NO"):
            h["X-Apple-I-SRL-NO"] = self._extra["X-Apple-SRL-NO"]
        return h

    def _run(self) -> dict:
        """Execute the native helper binary and return parsed JSON."""
        try:
            result = subprocess.run(
                [str(self._HELPER_BIN)],
                capture_output=True, text=True, timeout=15
            )
        except FileNotFoundError:
            raise RuntimeError(
                f"anisette_helper not found at {self._HELPER_BIN}\n"
                f"Build with: make anisette_helper"
            )
        if result.returncode != 0:
            raise RuntimeError(
                f"anisette_helper failed (exit {result.returncode}):\n"
                f"{result.stderr.strip()}"
            )
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"anisette_helper returned invalid JSON: {e}\n"
                f"{result.stdout[:300]}"
            )

    def _ensure_built(self):
        """Compile the native helper from source if not already built."""
        if self._HELPER_BIN.exists():
            return
        if not self._HELPER_SRC.exists():
            raise FileNotFoundError(
                f"anisette_helper.m not found at {self._HELPER_SRC}"
            )
        print("[*] Building native anisette helper (one-time)...")
        subprocess.run(
            [
                "clang", str(self._HELPER_SRC), "-o", str(self._HELPER_BIN),
                "-framework", "Foundation", "-fmodules", "-fobjc-arc",
            ],
            check=True
        )
        print(f"[+] Built: {self._HELPER_BIN}")

    @staticmethod
    def is_available() -> bool:
        """True if running on macOS (where AOSKit.framework is present)."""
        return platform.system() == "Darwin"


# ─── Linux Anisette Provider ─────────────────────────────────────────────────

def _stop_linux_anisette_server():
    """atexit handler: stop the anisette-server subprocess."""
    proc = LinuxAnisetteProvider._server_proc
    if proc and proc.poll() is None:
        proc.terminate()


class LinuxAnisetteProvider(AnisetteProvider):
    """
    Linux anisette provider using Dadoum/Provision anisette-server.

    First-time setup (~87 MB, one-time):
      1. Downloads anisette-server binary (GitHub Releases)
      2. Downloads Apple Music APK and extracts libstoreservicescore.so
         + libCoreADI.so

    Data dir: ~/.config/cc-ios/anisette/
    Server:   http://localhost:6969 (started as background subprocess)
    """

    _RELEASES_URL = "https://api.github.com/repos/Dadoum/Provision/releases/latest"
    _APK_URL = "https://apps.mzstatic.com/content/android-apple-music-apk/applemusic.apk"
    _PORT = 6969

    # platform.machine() → (server binary suffix, APK lib subdir)
    _ARCH_MAP = {
        "x86_64":  ("x86_64",  "x86_64"),
        "aarch64": ("aarch64", "arm64-v8a"),
        "armv7l":  ("armv7",   "armeabi-v7a"),
        "i686":    ("i686",    "x86"),
    }

    _server_proc: Optional["subprocess.Popen"] = None

    def __init__(self):
        machine = platform.machine()
        if machine not in self._ARCH_MAP:
            raise RuntimeError(f"Unsupported Linux architecture: {machine}")
        self._bin_arch, self._apk_arch = self._ARCH_MAP[machine]
        self._DIR = Path.home() / ".config" / "cc-ios" / "anisette"
        self._BINARY = self._DIR / "anisette-server"
        self._LIB_DIR = self._DIR / "lib" / self._apk_arch
        self._ensure_ready()
        self._start_server()
        super().__init__(f"http://localhost:{self._PORT}")

    # ── setup ────────────────────────────────────────────────────────────────

    def _ensure_ready(self):
        self._DIR.mkdir(parents=True, exist_ok=True)
        if not self._BINARY.exists():
            self._download_binary()
        if not (self._LIB_DIR / "libstoreservicescore.so").exists():
            self._download_libs()

    def _download_binary(self):
        print("[*] Fetching anisette-server release info...")
        r = _session.get(self._RELEASES_URL, timeout=15)
        r.raise_for_status()
        tag = r.json().get("tag_name", "?")
        assets = r.json().get("assets", [])
        name = f"anisette-server-{self._bin_arch}"
        url = next(
            (a["browser_download_url"] for a in assets if a["name"] == name),
            None
        )
        if not url:
            raise RuntimeError(
                f"No anisette-server binary for {self._bin_arch} in release {tag}"
            )
        print(f"[*] Downloading anisette-server {tag} ({self._bin_arch})...")
        self._stream_to(url, self._BINARY)
        self._BINARY.chmod(0o755)
        print(f"[+] Binary: {self._BINARY}")

    def _download_libs(self):
        self._LIB_DIR.mkdir(parents=True, exist_ok=True)
        apk_tmp = self._DIR / "applemusic.apk"
        try:
            print("[*] Downloading Apple Music APK (~87 MB) for native libs (one-time)...")
            self._stream_to(self._APK_URL, apk_tmp, progress=True)
            print("[*] Extracting libstoreservicescore.so + libCoreADI.so...")
            with zipfile.ZipFile(apk_tmp) as zf:
                for lib in ("libstoreservicescore.so", "libCoreADI.so"):
                    src_path = f"lib/{self._apk_arch}/{lib}"
                    dst_path = self._LIB_DIR / lib
                    with zf.open(src_path) as src_f:
                        dst_path.write_bytes(src_f.read())
                    print(f"[+] Extracted: {dst_path.name} ({dst_path.stat().st_size >> 10} KB)")
        finally:
            if apk_tmp.exists():
                apk_tmp.unlink()
                print("[*] Removed APK")

    def _stream_to(self, url: str, dest: Path, progress: bool = False):
        r = _session.get(url, stream=True, timeout=60)
        r.raise_for_status()
        total = int(r.headers.get("content-length", 0))
        done = 0
        with open(dest, "wb") as f:
            for chunk in r.iter_content(chunk_size=1 << 20):  # 1 MB
                f.write(chunk)
                if progress and total:
                    done += len(chunk)
                    pct = done * 100 // total
                    print(f"\r    {done >> 20}/{total >> 20} MB ({pct}%)",
                          end="", flush=True)
        if progress and total:
            print()

    # ── server lifecycle ─────────────────────────────────────────────────────

    def _start_server(self):
        url = f"http://localhost:{self._PORT}"
        if AnisetteProvider.check_server(url):
            return  # already running
        print("[*] Starting anisette-server...")
        proc = subprocess.Popen(
            [str(self._BINARY)],
            cwd=str(self._DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        LinuxAnisetteProvider._server_proc = proc
        atexit.register(_stop_linux_anisette_server)
        for _ in range(20):          # wait up to 10 s
            time.sleep(0.5)
            if AnisetteProvider.check_server(url):
                print("[+] anisette-server ready")
                return
            if proc.poll() is not None:
                raise RuntimeError(
                    f"anisette-server exited prematurely (code {proc.returncode}).\n"
                    f"Check that libstoreservicescore.so is present in {self._LIB_DIR}"
                )
        raise RuntimeError("anisette-server did not become ready within 10 s")

    @staticmethod
    def is_available() -> bool:
        """True if running on Linux."""
        return platform.system() == "Linux"

    @staticmethod
    def reset(data_dir: Path = None):
        """Delete cached data — triggers fresh download on next run."""
        target = data_dir or (Path.home() / ".config" / "cc-ios" / "anisette")
        if target.exists():
            shutil.rmtree(target)
            print(f"[+] Removed {target}")


def _parse_spd_plist(data: bytes) -> dict:
    """
    Parse Apple's SPD (Server Provided Data) as plist.
    Apple sometimes returns a bare <dict>...</dict> without the
    standard <?xml?> + <plist> wrapper; handle both cases.
    """
    try:
        return plistlib.loads(data)
    except Exception:
        pass

    # Strip leading/trailing whitespace or null bytes
    stripped = data.strip(b'\x00').strip()

    # If it starts with <dict>, wrap it with proper plist XML envelope
    if stripped.startswith(b'<dict>'):
        wrapped = (
            b'<?xml version="1.0" encoding="UTF-8"?>\n'
            b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            b'<plist version="1.0">\n'
            + stripped +
            b'\n</plist>'
        )
        return plistlib.loads(wrapped)

    raise ValueError(f"Cannot parse SPD plist, first 64 bytes: {data[:64]!r}")


# ─── Apple GSA Authentication ────────────────────────────────────────────────

class AppleAuth:
    """
    Authenticates with Apple's GrandSlam (GSA) service using SRP-6a.
    Handles 2FA via trusted device or SMS.
    """

    def __init__(self, anisette: AnisetteProvider):
        self.anisette = anisette
        self.adsid: Optional[str] = None
        self.idms_token: Optional[str] = None
        self.session_key: Optional[bytes] = None
        self.cookie: Optional[bytes] = None
        self.xcode_token: Optional[str] = None
        self._ensure_srp()

    @staticmethod
    def _ensure_srp():
        """Import and configure SRP library."""
        try:
            import srp._pysrp as _srp
            _srp.rfc5054_enable()
            _srp.no_username_in_x()
        except ImportError:
            raise ImportError(
                "SRP library not installed. Run: pip install srp"
            )

    def _gsa_request(self, params: dict, timeout: int = 30) -> dict:
        """Send authenticated request to GSA service."""
        body = {
            "Header": {"Version": "1.0.1"},
            "Request": {"cpd": self.anisette.generate_cpd()},
        }
        body["Request"].update(params)

        req_data = plistlib.dumps(body, fmt=plistlib.FMT_XML)

        resp = _session.post(
            GSA_URL,
            headers={
                "Content-Type": "text/x-xml-plist",
                "Accept": "text/x-xml-plist",
                "User-Agent": USER_AGENT_GSA,
                "X-MMe-Client-Info": CLIENT_INFO,
            },
            data=req_data,
            timeout=timeout,
        )

        try:
            parsed = plistlib.loads(resp.content)
        except Exception:
            # Show raw response to diagnose unexpected formats
            preview = resp.content[:500].decode("utf-8", errors="replace")
            raise Exception(
                f"GSA returned non-plist response (HTTP {resp.status_code}):\n{preview}"
            )
        return parsed.get("Response", parsed)

    @staticmethod
    def _encrypt_password(password: str, salt: bytes, iterations: int,
                          protocol: str = "s2k") -> bytes:
        """Derive SRP password using Apple's PBKDF2 scheme."""
        p = hashlib.sha256(password.encode("utf-8")).digest()

        if protocol == "s2k_fo":
            # For newer accounts: hex-encode the SHA-256 digest
            p = p.hex().encode()

        # Use built-in hashlib.pbkdf2_hmac — avoids pbkdf2 library
        # incompatibility with Python 3.14 (no digest_size on builtins)
        return hashlib.pbkdf2_hmac("sha256", p, salt, iterations, dklen=32)

    @staticmethod
    def _decrypt_cbc(session_key: bytes, data: bytes) -> bytes:
        """Decrypt AES-256-CBC encrypted server data (et=2)."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding

        key = hmac_mod.new(session_key, b"extra data key:", hashlib.sha256).digest()
        iv = hmac_mod.new(session_key, b"extra data iv:", hashlib.sha256).digest()[:16]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(decrypted) + unpadder.finalize()

    @staticmethod
    def _decrypt_spd_gcm(session_key: bytes, data: bytes) -> bytes:
        """Decrypt AES-256-GCM encrypted SPD (et=4, newer Apple accounts)."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        key = hmac_mod.new(session_key, b"extra data key:", hashlib.sha256).digest()
        # GCM uses 12-byte nonce (standard) derived the same way as CBC IV
        nonce = hmac_mod.new(session_key, b"extra data iv:", hashlib.sha256).digest()[:12]

        aes = AESGCM(key)
        return aes.decrypt(nonce, data, None)

    @staticmethod
    def _decrypt_gcm(key: bytes, data: bytes) -> bytes:
        """Decrypt AES-256-GCM encrypted app token."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        # Format: 3-byte header + 16-byte nonce + ciphertext+tag
        header = data[:3]
        nonce = data[3:3 + 16]
        ciphertext = data[3 + 16:]

        aes = AESGCM(key)
        return aes.decrypt(nonce, ciphertext, header)

    def authenticate(self, username: str, password: str) -> dict:
        """
        Full SRP-6a authentication flow.
        
        Returns dict with: adsid, idms_token, session_key, cookie, status
        Raises Exception on auth failure.
        """
        import srp._pysrp as _srp

        # Some versions of srp expose SHA256 as hashlib.sha256 (builtin function),
        # which lacks .digest_size. Wrap it in a proper class.
        class _SHA256:
            digest_size = 32
            block_size = 64

            def __init__(self, data: bytes = b""):
                self._h = hashlib.sha256(data)

            def update(self, data: bytes):
                self._h.update(data)

            def digest(self) -> bytes:
                return self._h.digest()

            def hexdigest(self) -> str:
                return self._h.hexdigest()

            def copy(self):
                obj = _SHA256()
                obj._h = self._h.copy()
                return obj

        # Use integer constant if available (newer srp), else our wrapper
        try:
            sha256_alg = _srp.SHA256 if isinstance(_srp.SHA256, int) else _SHA256
        except AttributeError:
            sha256_alg = _SHA256

        usr = _srp.User(username, bytes(), hash_alg=sha256_alg, ng_type=_srp.NG_2048)
        _, A = usr.start_authentication()

        # Step 1: Init
        print("[*] GSA: Sending SRP init...")
        r = self._gsa_request({
            "A2k": A,
            "ps": ["s2k", "s2k_fo"],
            "u": username,
            "o": "init",
        })

        status = r.get("Status", {})
        ec = status.get("ec", -1)
        if ec != 0:
            em = status.get("em", "Unknown error")
            raise Exception(f"GSA init failed (ec={ec}): {em}")

        # Determine protocol
        protocol = r.get("sp", "s2k")

        # Step 2: Complete
        print("[*] GSA: Computing SRP proof...")
        usr.p = self._encrypt_password(password, r["s"], r["i"], protocol)
        M = usr.process_challenge(r["s"], r["B"])

        if M is None:
            raise Exception("SRP challenge failed — wrong password?")

        r2 = self._gsa_request({
            "c": r["c"],
            "M1": M,
            "u": username,
            "o": "complete",
        })

        status = r2.get("Status", {})
        ec = status.get("ec", -1)

        if ec != 0:
            em = status.get("em", "Unknown error")
            if ec == -20101:
                raise Exception("Invalid Apple ID or password")
            elif ec == -22406:
                raise Exception("Apple ID locked for security reasons")
            raise Exception(f"GSA complete failed (ec={ec}): {em}")

        # Verify server proof
        usr.verify_session(r2["M2"])

        # Decrypt server provided data
        # et=2: AES-CBC, et=4: AES-GCM (newer accounts)
        sk = usr.get_session_key()
        et = r2.get("et", 2)
        spd_raw = r2["spd"]
        print(f"[*] GSA: Decrypting spd (et={et}, {len(spd_raw)} bytes)...")

        if et == 4:
            spd_bytes = self._decrypt_spd_gcm(sk, spd_raw)
        else:
            spd_bytes = self._decrypt_cbc(sk, spd_raw)

        # Fallback: try the other mode if first fails
        try:
            spd = _parse_spd_plist(spd_bytes)
        except Exception:
            try:
                if et == 4:
                    spd_bytes = self._decrypt_cbc(sk, spd_raw)
                else:
                    spd_bytes = self._decrypt_spd_gcm(sk, spd_raw)
                spd = _parse_spd_plist(spd_bytes)
            except Exception as e2:
                raise Exception(
                    f"spd decrypt failed (et={et}). "
                    f"First 64 decrypted bytes: {spd_bytes[:64].hex()}"
                ) from e2

        self.adsid = spd["adsid"]
        self.idms_token = spd["GsIdmsToken"]
        self.session_key = spd.get("sk")
        self.cookie = spd.get("c")

        print(f"[+] GSA: Authenticated as {username}")
        return {
            "adsid": self.adsid,
            "idms_token": self.idms_token,
            "session_key": self.session_key,
            "cookie": self.cookie,
            "status": status,
        }

    def needs_2fa(self, status: dict) -> bool:
        """Check if 2FA is required."""
        au = status.get("au")
        return au in ("trustedDeviceSecondaryAuth", "secondaryAuth")

    def get_2fa_type(self, status: dict) -> str:
        """Return 2FA type: 'trusted_device' or 'sms'."""
        au = status.get("au", "")
        if au == "trustedDeviceSecondaryAuth":
            return "trusted_device"
        return "sms"

    def _identity_token(self) -> str:
        return base64.b64encode(f"{self.adsid}:{self.idms_token}".encode()).decode()

    def _2fa_headers(self) -> dict:
        headers = {
            "Content-Type": "text/x-xml-plist",
            "User-Agent": "Xcode",
            "Accept": "text/x-xml-plist",
            "Accept-Language": "en-us",
            "X-Apple-Identity-Token": self._identity_token(),
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": XCODE_VERSION,
            "X-Mme-Client-Info": CLIENT_INFO,
        }
        headers.update(self.anisette.generate_headers())
        return headers

    def send_2fa_trusted_device(self):
        """Trigger 2FA push notification to trusted devices."""
        print("[*] 2FA: Sending push to trusted devices...")
        headers = self._2fa_headers()
        _session.get(
            "https://gsa.apple.com/auth/verify/trusteddevice",
            headers=headers,
            timeout=15,
        )
        print("[*] 2FA: Check your trusted device for the verification code")

    def submit_2fa_code(self, code: str) -> bool:
        """Submit 2FA code (works for both trusted device and SMS methods)."""
        print(f"[*] 2FA: Submitting code...")
        headers = self._2fa_headers()
        headers["security-code"] = code

        resp = _session.get(
            "https://gsa.apple.com/grandslam/GsService2/validate",
            headers=headers,
            timeout=15,
        )

        try:
            result = plistlib.loads(resp.content)
            ec = result.get("ec", -1)
            if ec == 0:
                print("[+] 2FA: Code accepted!")
                return True
            else:
                em = result.get("em", "Unknown error")
                print(f"[!] 2FA: Rejected (ec={ec}): {em}")
                return False
        except Exception:
            # Some responses are not plist — check status code
            if resp.status_code == 200 or resp.status_code == 204:
                print("[+] 2FA: Code accepted!")
                return True
            print(f"[!] 2FA: Unexpected response ({resp.status_code})")
            return False

    def send_2fa_sms(self, phone_id: int = 1):
        """Request SMS 2FA code to phone number."""
        print("[*] 2FA: Requesting SMS code...")
        headers = self._2fa_headers()
        headers["Content-Type"] = "application/json"

        _session.put(
            "https://gsa.apple.com/auth/verify/phone/",
            headers=headers,
            json={"phoneNumber": {"id": phone_id}, "mode": "sms"},
            timeout=15,
        )
        print("[*] 2FA: SMS sent to your phone")

    def submit_2fa_sms_code(self, code: str, phone_id: int = 1) -> bool:
        """Submit SMS 2FA code."""
        print("[*] 2FA: Submitting SMS code...")
        headers = self._2fa_headers()
        headers["Content-Type"] = "application/json"

        resp = _session.post(
            "https://gsa.apple.com/auth/verify/phone/securitycode",
            headers=headers,
            json={
                "securityCode": {"code": code},
                "phoneNumber": {"id": phone_id},
                "mode": "sms",
            },
            timeout=15,
        )

        if resp.status_code in (200, 204):
            print("[+] 2FA: SMS code accepted!")
            return True
        print(f"[!] 2FA: Rejected ({resp.status_code})")
        return False

    def get_xcode_token(self) -> str:
        """
        Request Xcode-specific application token.
        Must be called after successful authentication (and 2FA if needed).
        """
        if not self.session_key or not self.cookie:
            raise RuntimeError("Must authenticate first (session_key/cookie missing)")

        app_id = "com.apple.gs.xcode.auth"

        # Build HMAC checksum
        h = hmac_mod.new(self.session_key, b"", hashlib.sha256)
        h.update(b"apptokens")
        h.update(self.adsid.encode())
        h.update(app_id.encode())
        checksum = h.digest()

        print("[*] Requesting Xcode token...")
        last_err = None
        for attempt in range(3):
            try:
                r = self._gsa_request({
                    "u": self.adsid,
                    "app": [app_id],
                    "c": self.cookie,
                    "t": self.idms_token,
                    "checksum": checksum,
                    "o": "apptokens",
                }, timeout=45)
                break
            except Exception as e:
                last_err = e
                print(f"[!] Xcode token attempt {attempt+1}/3 failed: {e}")
                if attempt < 2:
                    time.sleep(3)
        else:
            raise Exception(f"Xcode token request failed after 3 attempts: {last_err}")

        status = r.get("Status", {})
        ec = status.get("ec", -1)
        if ec != 0:
            em = status.get("em", "Unknown")
            raise Exception(f"App token request failed (ec={ec}): {em}")

        # Decrypt the encrypted token
        et = r.get("et", b"")
        if not et:
            raise Exception("No encrypted token in response")

        token_plist_bytes = self._decrypt_gcm(self.session_key, et)
        token_plist = _parse_spd_plist(token_plist_bytes)

        print(f"[dbg] token_plist keys: {list(token_plist.keys())}")
        t_dict = token_plist.get("t", {})
        print(f"[dbg] t dict keys: {list(t_dict.keys())}")
        if app_id in t_dict:
            print(f"[dbg] app token keys: {list(t_dict[app_id].keys())}")

        token = token_plist.get("t", {}).get(app_id, {}).get("token")
        if not token:
            raise Exception("Xcode token not found in decrypted response")

        # Ensure token is a str (plist may decode it as bytes if stored as <data>)
        if isinstance(token, bytes):
            token = token.decode("utf-8")

        print(f"[*] Xcode token type: {type(token).__name__}, length: {len(token)}, preview: {str(token)[:40]}")

        self.xcode_token = token
        print("[+] Xcode token obtained")
        return token


# ─── Apple Developer Portal API ──────────────────────────────────────────────

class DeveloperPortal:
    """
    Interface to Apple's Developer Portal API.
    Manages certificates, provisioning profiles, App IDs, and devices.
    """

    def __init__(self, auth: AppleAuth):
        self.auth = auth
        self.team_id: Optional[str] = None

    def _request(self, action: str, params: dict = None,
                 device_type: str = "ios") -> dict:
        """Send authenticated request to Developer Portal."""
        request_id = str(uuid.uuid4()).upper()

        body = {
            "clientId": CLIENT_ID,
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": request_id,
            "userLocale": ["en_US"],
        }
        if params:
            body.update(params)

        if device_type:
            url = f"{DEV_PORTAL_BASE}/{device_type}/{action}?clientId={CLIENT_ID}"
        else:
            url = f"{DEV_PORTAL_BASE}/{action}?clientId={CLIENT_ID}"

        headers = {
            "Content-Type": "text/x-xml-plist",
            "Accept": "text/x-xml-plist",
            "Accept-Language": "en-us",
            "User-Agent": "Xcode",
            "X-Apple-I-Identity-Id": self.auth.adsid,
            "X-Apple-GS-Token": self.auth.xcode_token,
            "X-Xcode-Version": XCODE_VERSION,
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-MMe-Client-Info": CLIENT_INFO,
        }
        headers.update(self.auth.anisette.generate_headers())

        resp = _session.post(
            url,
            headers=headers,
            data=plistlib.dumps(body, fmt=plistlib.FMT_XML),
            timeout=45,
        )

        try:
            result = plistlib.loads(resp.content)
        except Exception:
            raise Exception(
                f"Developer Portal non-plist response (HTTP {resp.status_code}):\n"
                f"{resp.content[:500].decode('utf-8', errors='replace')}"
            )

        print(f"[dbg] Portal {action} → HTTP {resp.status_code}, resultCode={result.get('resultCode', 0)}")

        # Check for errors
        rc = result.get("resultCode", 0)
        if rc != 0:
            rm = result.get("resultString", "")
            ue = result.get("userString", rm)
            print(f"[!] Dev Portal raw response: {dict(list(result.items())[:10])}")
            raise Exception(f"Developer Portal error ({rc}): {ue}")

        return result

    def list_teams(self) -> list:
        """List development teams associated with this Apple ID."""
        r = self._request("listTeams.action", device_type=None)
        teams = r.get("teams", [])
        if not teams:
            raise Exception("No development teams found")
        return teams

    def select_team(self, team_id: str = None) -> str:
        """Select a team (auto-selects if only one)."""
        teams = self.list_teams()

        if team_id:
            for t in teams:
                if t["teamId"] == team_id:
                    self.team_id = team_id
                    print(f"[+] Selected team: {t.get('name', team_id)}")
                    return team_id
            raise Exception(f"Team {team_id} not found")

        if len(teams) == 1:
            self.team_id = teams[0]["teamId"]
            print(f"[+] Team: {teams[0].get('name', '')} ({self.team_id})")
            return self.team_id

        # Multiple teams — let user choose
        print("[*] Multiple teams found:")
        for i, t in enumerate(teams):
            print(f"  [{i}] {t.get('name', 'Unknown')} ({t['teamId']})")

        while True:
            try:
                choice = int(input("Select team number: "))
                if 0 <= choice < len(teams):
                    self.team_id = teams[choice]["teamId"]
                    return self.team_id
            except (ValueError, IndexError):
                pass
            print("[!] Invalid choice")

    def register_device(self, name: str, udid: str) -> dict:
        """Register a device UDID with the developer portal."""
        print(f"[*] Registering device: {name} ({udid[:12]}...)")
        try:
            r = self._request("addDevice.action", {
                "teamId": self.team_id,
                "name": name,
                "deviceNumber": udid,
            })
            print(f"[+] Device registered: {name}")
            return r.get("device", {})
        except Exception as e:
            if "already exists" in str(e).lower():
                print(f"[*] Device already registered")
                return {}
            raise

    def list_devices(self) -> list:
        """List registered devices."""
        r = self._request("listDevices.action", {"teamId": self.team_id})
        return r.get("devices", [])

    def generate_csr(self) -> tuple:
        """
        Generate RSA-2048 key pair and PKCS#10 CSR.
        Returns (private_key, csr_pem_string).
        """
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography import x509

        private_key = _rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([]))
            .sign(private_key, hashes.SHA256())
        )

        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        return private_key, csr_pem

    def submit_csr(self, csr_pem: str) -> dict:
        """Submit CSR and get development certificate."""
        machine_id = str(uuid.uuid4()).upper()
        print("[*] Submitting CSR for development certificate...")

        r = self._request("submitDevelopmentCSR.action", {
            "teamId": self.team_id,
            "machineId": machine_id,
            "machineName": "IOSSandboxExplorer",
            "csrContent": csr_pem,
        })

        print("[+] Development certificate created")
        return r.get("certRequest", {})

    def list_certificates(self) -> list:
        """List all development certificates."""
        r = self._request("listAllDevelopmentCerts.action", {
            "teamId": self.team_id,
        })
        return r.get("certificates", [])

    def revoke_certificate(self, serial_number: str):
        """Revoke a development certificate by serial number."""
        print(f"[*] Revoking certificate: {serial_number}")
        try:
            self._request("revokeDevelopmentCert.action", {
                "teamId": self.team_id,
                "serialNumber": serial_number,
            })
            print(f"[+] Certificate revoked")
        except Exception as e:
            # 7252 = cert not found (already revoked or from another session) — OK
            if "(7252)" in str(e):
                print(f"[*] Certificate already gone (7252)")
            else:
                raise

    def add_app_id(self, bundle_id: str, name: str) -> tuple:
        """Register a new App ID. Returns (app_id_dict, actual_bundle_id)."""
        print(f"[*] Creating App ID: {bundle_id}")
        try:
            r = self._request("addAppId.action", {
                "teamId": self.team_id,
                "identifier": bundle_id,
                "name": name,
            })
            print(f"[+] App ID created: {bundle_id}")
            return r.get("appId", {}), bundle_id
        except Exception as e:
            err = str(e)
            # Already registered in THIS team
            if "already exists" in err.lower():
                print(f"[*] App ID already exists, reusing")
                return self.find_app_id(bundle_id), bundle_id
            # Bundle ID taken by ANOTHER team (9401) — prefix with team ID
            if "(9401)" in err or "is not available" in err.lower():
                alt_bundle = f"{self.team_id}.{bundle_id}"
                print(f"[!] Bundle ID '{bundle_id}' is taken by another developer")
                print(f"[*] Trying team-prefixed bundle ID: {alt_bundle}")
                try:
                    r2 = self._request("addAppId.action", {
                        "teamId": self.team_id,
                        "identifier": alt_bundle,
                        "name": name,
                    })
                    print(f"[+] App ID created: {alt_bundle}")
                    return r2.get("appId", {}), alt_bundle
                except Exception as e2:
                    if "already exists" in str(e2).lower() or "is not available" in str(e2).lower():
                        print(f"[*] Alternative App ID already exists, reusing")
                        return self.find_app_id(alt_bundle), alt_bundle
                    raise
            raise

    def list_app_ids(self) -> list:
        """List all App IDs."""
        r = self._request("listAppIds.action", {"teamId": self.team_id})
        return r.get("appIds", [])

    def find_app_id(self, bundle_id: str) -> dict:
        """Find a specific App ID by identifier."""
        for app_id in self.list_app_ids():
            if app_id.get("identifier") == bundle_id:
                return app_id
        return {}

    def download_provisioning_profile(self, app_id_id: str) -> bytes:
        """Download provisioning profile. Returns raw .mobileprovision data."""
        print("[*] Downloading provisioning profile...")
        r = self._request("downloadTeamProvisioningProfile.action", {
            "teamId": self.team_id,
            "appIdId": app_id_id,
        })

        profile_data = r.get("provisioningProfile", {})
        encoded = profile_data.get("encodedProfile")
        if not encoded:
            raise Exception("No profile data in response")

        # encodedProfile is raw bytes (already decoded from plist data)
        if isinstance(encoded, bytes):
            return encoded
        return base64.b64decode(encoded)


# ─── Full Apple Signing Pipeline ─────────────────────────────────────────────

class AppleSigner:
    """
    Orchestrates the full Apple ID signing flow:
      1. Authenticate with Apple ID (SRP)
      2. Handle 2FA
      3. Get Xcode token
      4. Register device 
      5. Create certificate
      6. Create App ID
      7. Download provisioning profile
      8. Sign IPA (via zsign)
    
    Credentials are NEVER stored to disk.
    """

    def __init__(self, anisette_url: str = DEFAULT_ANISETTE_URL):
        if NativeAnisetteProvider.is_available():
            try:
                self.anisette = NativeAnisetteProvider()
            except Exception as _nat_err:
                print(f"[!] Native anisette unavailable ({_nat_err}), falling back to HTTP server")
                self.anisette = AnisetteProvider(anisette_url)
        elif LinuxAnisetteProvider.is_available():
            try:
                self.anisette = LinuxAnisetteProvider()
            except Exception as _lin_err:
                print(f"[!] Linux native anisette failed ({_lin_err}), falling back to HTTP server")
                self.anisette = AnisetteProvider(anisette_url)
        else:
            self.anisette = AnisetteProvider(anisette_url)
        self.auth = AppleAuth(self.anisette)
        self.portal: Optional[DeveloperPortal] = None
        self._private_key = None

    def login(self, apple_id: str, password: str) -> bool:
        """
        Authenticate with Apple ID. Handles 2FA interactively.
        Returns True on success.
        """
        try:
            result = self.auth.authenticate(apple_id, password)
        except Exception as e:
            print(f"[!] Authentication failed: {e}")
            return False

        # Handle 2FA
        status = result["status"]
        if self.auth.needs_2fa(status):
            fa_type = self.auth.get_2fa_type(status)
            print(f"[*] Two-factor authentication required ({fa_type})")

            if fa_type == "trusted_device":
                self.auth.send_2fa_trusted_device()
            else:
                self.auth.send_2fa_sms()

            # Get code from user
            max_attempts = 3
            for attempt in range(max_attempts):
                code = input(f"Enter 2FA code (attempt {attempt + 1}/{max_attempts}): ").strip()
                if not code:
                    continue

                if fa_type == "trusted_device":
                    ok = self.auth.submit_2fa_code(code)
                else:
                    ok = self.auth.submit_2fa_sms_code(code)

                if ok:
                    break
            else:
                print("[!] 2FA failed after maximum attempts")
                return False

            # Re-authenticate after 2FA
            print("[*] Re-authenticating after 2FA...")
            try:
                result = self.auth.authenticate(apple_id, password)
            except Exception as e:
                print(f"[!] Re-authentication failed: {e}")
                return False

        # Get Xcode token
        try:
            self.auth.get_xcode_token()
        except Exception as e:
            print(f"[!] Failed to get Xcode token: {e}")
            return False

        self.portal = DeveloperPortal(self.auth)
        return True

    def provision(self, udid: str, bundle_id: str, app_name: str) -> tuple:
        """
        Provision device and app for signing.
        Returns (private_key_pem, mobileprovision_bytes, cert_der).
        """
        if not self.portal:
            raise RuntimeError("Not logged in")

        from cryptography.hazmat.primitives import serialization

        # Select team
        self.portal.select_team()

        # Register device
        self.portal.register_device(app_name + " Device", udid)

        # Revoke all existing dev certs — free accounts allow only 1 at a time
        certs = self.portal.list_certificates()
        if certs:
            print(f"[!] Revoking {len(certs)} existing certificate(s) to free slot...")
            for cert in sorted(certs, key=lambda c: c.get("dateCreated", "")):
                self.portal.revoke_certificate(cert["serialNumber"])

        # Generate key pair + CSR, get cert from response directly
        self._private_key, csr_pem = self.portal.generate_csr()
        cert_info = self.portal.submit_csr(csr_pem)

        # Decode certContent — may be bytes (DER) or base64 string
        def _decode_cert(raw):
            if not raw:
                return None
            if isinstance(raw, bytes):
                return raw
            if isinstance(raw, str):
                import base64 as _b64
                try:
                    return _b64.b64decode(raw)
                except Exception:
                    pass
            return None

        cert_der = _decode_cert(cert_info.get("certContent"))
        print(f"[dbg] submit_csr certContent: {type(cert_info.get('certContent')).__name__}, "
              f"len={len(cert_info.get('certContent', b''))}")

        if not cert_der:
            # fallback: list certs and match by public key
            import time as _time
            _time.sleep(1)
            certs = self.portal.list_certificates()
            print(f"[dbg] list_certificates returned {len(certs)} cert(s)")
            # Try to find the cert that matches our private key
            from cryptography import x509 as _x509
            our_pub = self._private_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            for c in reversed(certs):  # newest last
                raw = _decode_cert(c.get("certContent"))
                if not raw:
                    continue
                try:
                    loaded = _x509.load_der_x509_certificate(raw)
                    cpub = loaded.public_key().public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    if cpub == our_pub:
                        cert_der = raw
                        print(f"[+] Matched cert by public key")
                        break
                except Exception:
                    pass
            if not cert_der and certs:
                cert_der = _decode_cert(certs[-1].get("certContent"))
                print(f"[!] Using latest cert (no key match found)")

        # Create App ID
        app_id, actual_bundle_id = self.portal.add_app_id(bundle_id, app_name)
        if not app_id:
            app_id = self.portal.find_app_id(bundle_id)
            actual_bundle_id = bundle_id

        app_id_id = app_id.get("appIdId")
        if not app_id_id:
            raise Exception(f"Could not find appIdId for {actual_bundle_id}")

        # Download provisioning profile
        profile_bytes = self.portal.download_provisioning_profile(app_id_id)

        # Export private key as PEM
        private_key_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        print("[+] Provisioning complete!")
        print(f"    Team ID:    {self.portal.team_id}")
        print(f"    Bundle ID:  {actual_bundle_id}" +
              (f" (orig: {bundle_id})" if actual_bundle_id != bundle_id else ""))
        print(f"    Device:     {udid[:12]}...")
        print(f"    Profile:    {len(profile_bytes)} bytes")
        print(f"    Cert:       {len(cert_der) if cert_der else 0} bytes")

        return private_key_pem, profile_bytes, cert_der, actual_bundle_id

    def _sign_with_codesign(self, ipa_path: str, output_path: str,
                             private_key_pem: bytes, cert_der: bytes,
                             profile_path: str,
                             temp_dir: Path) -> bool:
        """Sign IPA using macOS codesign with a temporary keychain."""
        import subprocess
        import zipfile as zf

        sign_dir = temp_dir / "sign_work"
        sign_dir.mkdir(exist_ok=True)
        kc_path = str(temp_dir / "tmp.keychain-db")
        kc_pass = "tmp_kc_pass_12345"
        p12_pass = "tmp_p12_12345"

        try:
            # 1. Create temp keychain and import p12 (must have non-empty password for macOS import)
            # Use openssl to create a legacy-compatible p12 (macOS security import needs RC2/3DES)
            import subprocess as _sp
            key_pem_path = str(temp_dir / "key.pem")
            cert_pem_path = str(temp_dir / "cert.pem")
            p12_enc_path = str(temp_dir / "cert_enc.p12")
            with open(key_pem_path, "wb") as f:
                f.write(private_key_pem)
            # Convert DER cert to PEM
            from cryptography import x509 as _x509
            if not cert_der.startswith(b"-----"):
                cert_obj = _x509.load_der_x509_certificate(cert_der)
                from cryptography.hazmat.primitives.serialization import Encoding as _Enc
                cert_pem = cert_obj.public_bytes(_Enc.PEM)
            else:
                cert_pem = cert_der
            with open(cert_pem_path, "wb") as f:
                f.write(cert_pem)
            _sp.run([
                "/usr/bin/openssl", "pkcs12", "-export",
                "-out", p12_enc_path,
                "-inkey", key_pem_path,
                "-in", cert_pem_path,
                "-passout", f"pass:{p12_pass}",
                "-legacy",
            ], check=True, capture_output=True)
            if not Path(p12_enc_path).exists():
                raise RuntimeError("openssl pkcs12 -legacy failed, trying without")
        except Exception as _e1:
            # Try without -legacy flag (older openssl)
            try:
                _sp.run([
                    "/usr/bin/openssl", "pkcs12", "-export",
                    "-out", p12_enc_path,
                    "-inkey", key_pem_path,
                    "-in", cert_pem_path,
                    "-passout", f"pass:{p12_pass}",
                ], check=True, capture_output=True)
            except Exception as _e2:
                print(f"[!] openssl pkcs12 also failed: {_e2}")
                return False
            subprocess.run(["security", "create-keychain", "-p", kc_pass, kc_path],
                           check=True, capture_output=True)
            subprocess.run(["security", "unlock-keychain", "-p", kc_pass, kc_path],
                           check=True, capture_output=True)
            subprocess.run(["security", "set-keychain-settings", "-lut", "7200", kc_path],
                           check=True, capture_output=True)
            subprocess.run(["security", "import", p12_enc_path, "-k", kc_path,
                            "-P", p12_pass, "-T", "/usr/bin/codesign",
                            "-T", "/usr/bin/security", "-A"],
                           check=True, capture_output=True)
            subprocess.run(["security", "set-key-partition-list",
                            "-S", "apple-tool:,apple:,codesign:", "-s",
                            "-k", kc_pass, kc_path],
                           check=True, capture_output=True)

            # Add to search list
            current_kcs = subprocess.run(
                ["security", "list-keychains", "-d", "user"],
                capture_output=True, text=True
            ).stdout.strip().replace('"', '').split()
            subprocess.run(["security", "list-keychains", "-d", "user", "-s",
                            kc_path] + current_kcs, capture_output=True)

            # 2. Find certificate identity (SHA1 hash is most reliable)
            out = subprocess.run(
                ["security", "find-identity", "-v", kc_path],
                capture_output=True, text=True
            ).stdout
            identity = None
            for line in out.splitlines():
                # Line format: "  1) AABBCCDD... "Some Name""
                import re as _re
                m = _re.search(r'\)\s+([0-9A-Fa-f]{40})', line)
                if m:
                    identity = m.group(1)
                    print(f"[*] Signing identity SHA1: {identity[:8]}...")
                    break
            if not identity:
                print(f"[!] No valid identity found. security output:\n{out}")
                return False

            # 3. Unzip IPA
            with zf.ZipFile(ipa_path, 'r') as z:
                z.extractall(str(sign_dir))

            # 4. Find .app
            payload = sign_dir / "Payload"
            apps = list(payload.glob("*.app"))
            if not apps:
                print("[!] No .app found in IPA")
                return False
            app_path = apps[0]

            # 5. Copy provisioning profile
            import shutil as _sh
            _sh.copy2(profile_path, str(app_path / "embedded.mobileprovision"))

            # 6. Extract entitlements from profile
            ent_path = str(temp_dir / "entitlements.plist")
            with open(profile_path, "rb") as f:
                mp_data = f.read()
            try:
                start = mp_data.index(b"<?xml")
                end = mp_data.index(b"</plist>") + len(b"</plist>")
                mp_plist = plistlib.loads(mp_data[start:end])
                ents = mp_plist.get("Entitlements", {})
                with open(ent_path, "wb") as f:
                    plistlib.dump(ents, f, fmt=plistlib.FMT_XML)
            except Exception:
                ent_path = None

            # 7. Sign frameworks and dylibs first (inside-out)
            def _cs(path, with_ents=False):
                cmd = ["codesign", "--force", "--sign", identity,
                       "--keychain", kc_path, "--timestamp=none"]
                if with_ents and ent_path:
                    cmd += ["--entitlements", ent_path]
                cmd.append(str(path))
                r = subprocess.run(cmd, capture_output=True, text=True)
                if r.returncode != 0:
                    print(f"  [!] codesign {Path(path).name}: {r.stderr.strip()[:120]}")

            # Frameworks (no entitlements)
            fw_dir = app_path / "Frameworks"
            if fw_dir.exists():
                for fw in sorted(fw_dir.iterdir()):
                    if fw.suffix in (".framework", ".dylib"):
                        _cs(fw)

            # PlugIns (no entitlements)
            plugins_dir = app_path / "PlugIns"
            if plugins_dir.exists():
                for plugin in sorted(plugins_dir.glob("*.appex")):
                    _cs(plugin)

            # Main app (with entitlements)
            _cs(app_path, with_ents=True)

            # 8. Repack to IPA preserving Unix permissions from original zip
            print(f"[*] Repacking IPA → {output_path}")
            # Build map: arcname → original external_attr (contains Unix mode)
            orig_attrs = {}
            with zf.ZipFile(ipa_path, 'r') as zorig:
                for info in zorig.infolist():
                    orig_attrs[info.filename] = info.external_attr

            import os as _os

            # Name of the main binary (same as .app bundle name without extension)
            app_binary_name = app_path.name.replace('.app', '')

            # MachO magic bytes (fat, arm64, x86_64)
            _MACHO_MAGIC = {b'\xca\xfe\xba\xbe', b'\xcf\xfa\xed\xfe',
                            b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xfe\xed\xfa\xce'}

            def _is_macho(path):
                try:
                    with open(path, 'rb') as _f:
                        return _f.read(4) in _MACHO_MAGIC
                except Exception:
                    return False

            with zf.ZipFile(output_path, 'w', compression=zf.ZIP_DEFLATED) as zout:
                for f in sorted(sign_dir.rglob("*")):
                    if f.is_file():
                        arcname = str(f.relative_to(sign_dir)).replace(_os.sep, '/')
                        zi = zf.ZipInfo(arcname)
                        zi.compress_type = zf.ZIP_DEFLATED
                        # MachO binaries (main + frameworks + plugins + dylibs) → 0755
                        if _is_macho(f) or f.suffix == '.dylib':
                            zi.external_attr = 0o100755 << 16
                        else:
                            zi.external_attr = 0o100644 << 16
                        with open(f, 'rb') as fp:
                            zout.writestr(zi, fp.read())

            print(f"[+] Signed IPA: {output_path}")
            return True

        except subprocess.CalledProcessError as e:
            print(f"[!] codesign step failed: {e.stderr.decode() if e.stderr else e}")
            return False
        finally:
            # Remove our keychain from search list
            try:
                current = subprocess.run(
                    ["security", "list-keychains", "-d", "user"],
                    capture_output=True, text=True
                ).stdout.strip().replace('"', '').split()
                remaining = [k for k in current if k != kc_path]
                subprocess.run(["security", "list-keychains", "-d", "user", "-s"]
                               + remaining, capture_output=True)
                subprocess.run(["security", "delete-keychain", kc_path],
                               capture_output=True)
            except Exception:
                pass

    def _patch_ipa_bundle_id(self, ipa_path: str, old_id: str, new_id: str, work_dir: str) -> str:
        """Replace bundle ID in IPA's Info.plist and return path to patched IPA."""
        import zipfile, shutil
        patched_path = str(Path(work_dir) / "patched_bundleid.ipa")
        with zipfile.ZipFile(ipa_path, 'r') as zin:
            with zipfile.ZipFile(patched_path, 'w', compression=zipfile.ZIP_DEFLATED) as zout:
                for item in zin.infolist():
                    data = zin.read(item.filename)
                    # Patch Info.plist inside Payload/*.app/
                    if item.filename.endswith('/Info.plist') and item.filename.count('/') == 2:
                        try:
                            pl = plistlib.loads(data)
                            if pl.get('CFBundleIdentifier') == old_id:
                                pl['CFBundleIdentifier'] = new_id
                                data = plistlib.dumps(pl, fmt=plistlib.FMT_XML)
                                print(f"[+] Patched Info.plist: {old_id} → {new_id}")
                        except Exception:
                            pass
                    zout.writestr(item, data)
        return patched_path

    def create_p12(self, private_key_pem: bytes, cert_der: bytes,
                   output_path: str, password: str = "") -> str:
        """
        Create .p12 (PKCS#12) file from private key and certificate.
        For use with zsign.
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, pkcs12, BestAvailableEncryption,
            NoEncryption,
        )
        from cryptography import x509

        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        if isinstance(cert_der, bytes) and not cert_der.startswith(b"-----"):
            cert = x509.load_der_x509_certificate(cert_der)
        else:
            cert = x509.load_pem_x509_certificate(cert_der)

        if password:
            enc = BestAvailableEncryption(password.encode())
        else:
            enc = NoEncryption()

        p12_data = pkcs12.serialize_key_and_certificates(
            name=b"Apple Development",
            key=private_key,
            cert=cert,
            cas=None,
            encryption_algorithm=enc,
        )

        with open(output_path, "wb") as f:
            f.write(p12_data)

        print(f"[+] Created .p12: {output_path}")
        return output_path

    def sign_ipa(self, ipa_path: str, output_path: str = None,
                 udid: str = None, bundle_id: str = None) -> str:
        """
        Full pipeline: authenticate → provision → sign IPA.
        
        If already logged in, reuses the session.
        Returns the path to the signed IPA.
        """
        import shutil
        import zipfile

        ipa_path = str(Path(ipa_path).resolve())
        if not output_path:
            output_path = ipa_path.replace(".ipa", "_signed.ipa")

        # Read bundle ID from IPA if not provided
        if not bundle_id:
            bundle_id = self._get_bundle_id_from_ipa(ipa_path)

        app_name = bundle_id.split(".")[-1] if bundle_id else "App"

        if not udid:
            # Try to get UDID from connected device
            udid = self._get_device_udid()
            if not udid:
                udid = input("Enter device UDID: ").strip()

        # Provision
        private_key_pem, profile_bytes, cert_der, actual_bundle_id = self.provision(
            udid, bundle_id, app_name
        )

        # Create temp files for signing
        temp_dir = Path(tempfile.mkdtemp(prefix="apple_sign_"))
        try:
            # If bundle ID was changed (9401: taken by another dev), patch IPA
            if actual_bundle_id != bundle_id:
                print(f"[*] Patching IPA bundle ID: {bundle_id} → {actual_bundle_id}")
                ipa_path = self._patch_ipa_bundle_id(
                    ipa_path, bundle_id, actual_bundle_id, str(temp_dir)
                )
                bundle_id = actual_bundle_id
            p12_path = str(temp_dir / "cert.p12")
            profile_path = str(temp_dir / "profile.mobileprovision")

            self.create_p12(private_key_pem, cert_der, p12_path)

            with open(profile_path, "wb") as f:
                f.write(profile_bytes)
            print(f"[+] Saved provisioning profile: {profile_path}")

            # Sign with zsign
            if shutil.which("zsign"):
                import subprocess
                cmd = [
                    "zsign",
                    "-k", p12_path,
                    "-m", profile_path,
                    "-o", output_path,
                    ipa_path,
                ]
                print(f"[*] Signing: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"[+] Signed IPA: {output_path}")
                    return output_path
                else:
                    print(f"[!] zsign failed: {result.stderr}")
                    # Keep temp files for manual signing
                    print(f"[*] Manual signing files saved in: {temp_dir}")
                    return ""
            else:
                # No zsign — try macOS codesign (macOS-only, works for dev signing)
                if shutil.which("codesign") and shutil.which("security"):
                    signed = self._sign_with_codesign(
                        ipa_path, output_path, private_key_pem, cert_der,
                        profile_path, temp_dir
                    )
                    if signed:
                        return output_path

                # Final fallback — save files to workspace dir for manual use
                ws = Path(output_path).parent
                final_p12 = str(ws / "diia_cert.p12")
                final_profile = str(ws / "diia.mobileprovision")
                final_ipa = str(ws / "diia_patched_bundleid.ipa")
                shutil.copy2(p12_path, final_p12)
                shutil.copy2(profile_path, final_profile)
                if Path(ipa_path).resolve() != Path(final_ipa).resolve():
                    shutil.copy2(ipa_path, final_ipa)

                print()
                print("=" * 60)
                print("[+] Signing materials saved to workspace:")
                print(f"    Certificate:  {final_p12}")
                print(f"    Profile:      {final_profile}")
                print(f"    Patched IPA:  {final_ipa}")
                print()
                print("    Sign with Sideloadly using the .p12 + .mobileprovision")
                print("    Or install zsign and run:")
                print(f"      zsign -k {final_p12} -m {final_profile} -o {output_path} {final_ipa}")
                print("=" * 60)
                return final_ipa

        finally:
            # Clean up temp dir (but preserve if signing failed without zsign)
            if Path(output_path).exists():
                shutil.rmtree(temp_dir, ignore_errors=True)

    @staticmethod
    def _get_bundle_id_from_ipa(ipa_path: str) -> str:
        """Extract bundle ID from IPA's Info.plist."""
        import zipfile

        with zipfile.ZipFile(ipa_path, "r") as zf:
            for name in zf.namelist():
                if name.endswith("/Info.plist") and name.count("/") == 2:
                    with zf.open(name) as f:
                        info = plistlib.load(f)
                    return info.get("CFBundleIdentifier", "")
        return ""

    @staticmethod
    def _get_device_udid() -> str:
        """Try to get UDID from connected device via pymobiledevice3."""
        try:
            from pymobiledevice3.usbmux import select_devices_by_connection_type
            devices = select_devices_by_connection_type(connection_type="USB")
            if devices:
                return devices[0].serial
        except Exception:
            pass
        return ""


# ─── Interactive CLI Functions ────────────────────────────────────────────────

def interactive_login(anisette_url: str = DEFAULT_ANISETTE_URL, apple_id: str = None, password: str = None) -> AppleSigner:
    """
    Interactive Apple ID login with security warnings.
    Returns configured AppleSigner on success.
    """
    print()
    print("=" * 60)
    print("  APPLE ID AUTHENTICATION")
    print("=" * 60)
    print()
    print("  This will authenticate with Apple's servers to obtain")
    print("  a free development certificate and provisioning profile.")
    print()
    print("  SECURITY NOTES:")
    print("  • Credentials are NEVER saved to disk")
    print("  • Password is transmitted directly to Apple via SRP")
    print("    (server never sees your plaintext password)")
    print("  • macOS: native AOSKit  |  Linux: anisette-server (auto-setup)")
    print("  • 2FA is supported (trusted device & SMS)")
    print()
    print("  FREE ACCOUNT LIMITATIONS:")
    print("  • Apps expire in 7 days (must re-sign weekly)")
    print("  • Max 3 app IDs per week")
    print("  • Max 10 sideloaded apps")
    print()
    print("  To skip this step, use --skip-sign or provide")
    print("  your own --p12 and --mobileprovision files.")
    print("=" * 60)
    print()

    # Check anisette provider
    if NativeAnisetteProvider.is_available():
        print("[+] Anisette: native macOS AOSKit (no Docker required)")
    elif LinuxAnisetteProvider.is_available():
        print("[+] Anisette: Linux native (anisette-server + Apple libs)")
    else:
        if not AnisetteProvider.check_server(anisette_url):
            print(f"[!] Anisette server not reachable at {anisette_url}")
            print()
            print("  Start one with Docker:")
            print("    docker run -d --restart always --name omnisette \\")
            print("      -p 6969:80 \\")
            print("      --volume omnisette_data:/opt/omnisette-server/lib \\")
            print("      ghcr.io/sidestore/omnisette-server:latest")
            print()
            return None
        print(f"[+] Anisette server: {anisette_url} (OK)")
    print()

    if not apple_id:
        apple_id = input("Apple ID (email): ").strip()
    else:
        print(f"Apple ID (email): {apple_id}")
    if not apple_id:
        print("[!] Cancelled")
        return None

    if not password:
        password = getpass.getpass("Password (hidden): ")
    if not password:
        print("[!] Cancelled")
        return None

    signer = AppleSigner(anisette_url)

    if signer.login(apple_id, password):
        # Clear password from memory
        password = "x" * len(password)
        del password
        return signer
    else:
        password = "x" * len(password)
        del password
        return None


def sign_ipa_with_apple_id(
    ipa_path: str,
    output_path: str = None,
    udid: str = None,
    bundle_id: str = None,
    anisette_url: str = DEFAULT_ANISETTE_URL,
    skip_sign: bool = False,
    apple_id: str = None,
    password: str = None,
) -> str:
    """
    High-level function: sign IPA using Apple ID.
    Returns path to signed IPA or empty string.
    """
    if skip_sign:
        print("[*] Signing skipped (--skip-sign)")
        print(f"[*] Unsigned IPA: {ipa_path}")
        print()
        print("  To install unsigned IPA, use:")
        print("    • Sideloadly (handles signing automatically)")
        print("    • AltStore")
        print(f"    • Manual signing: python3 tools/patcher.py sign --ipa {ipa_path} --p12 cert.p12 -m profile.mobileprovision")
        return ipa_path

    signer = interactive_login(anisette_url, apple_id=apple_id, password=password)
    if not signer:
        return ""

    return signer.sign_ipa(ipa_path, output_path, udid, bundle_id)


def install_ipa_on_device(ipa_path: str, udid: str = None) -> bool:
    """
    Install IPA on a connected iOS device using ideviceinstaller.
    Returns True on success.
    """
    import shutil
    import subprocess as _sp

    tool = shutil.which("ideviceinstaller")
    if not tool:
        print()
        print("[!] ideviceinstaller not found.")
        print("    macOS:  brew install ideviceinstaller")
        print("    Linux:  apt install ideviceinstaller  (or build from source)")
        print("    Win:    https://github.com/libimobiledevice-win32")
        return False

    cmd = [tool]
    if udid:
        cmd += ["-u", udid]
    cmd += ["install", ipa_path]

    print()
    print(f"[*] Installing {ipa_path} on device{' ' + udid[:12] + '...' if udid else ''}...")
    result = _sp.run(cmd, text=True)
    if result.returncode == 0:
        print("[+] Installation complete!")
        return True
    else:
        print(f"[!] ideviceinstaller failed (exit {result.returncode})")
        return False


# ─── Standalone Usage ────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Apple ID Authentication & Signing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sign an IPA using Apple ID
  python3 apple_account.py sign --ipa MyApp_patched.ipa

  # Sign with specific UDID and bundle ID
  python3 apple_account.py sign --ipa MyApp.ipa --udid 00008030-... --bundle-id com.example.app

  # Just generate certificate + profile (no signing)
  python3 apple_account.py provision --udid 00008030-... --bundle-id com.example.app

  # Check anisette server status
  python3 apple_account.py check
""",
    )

    sub = parser.add_subparsers(dest="command")

    # sign
    p_sign = sub.add_parser("sign", help="Sign IPA with Apple ID")
    p_sign.add_argument("--ipa", required=True, help="Path to IPA")
    p_sign.add_argument("--output", "-o", help="Output IPA path")
    p_sign.add_argument("--udid", help="Device UDID")
    p_sign.add_argument("--bundle-id", help="Override bundle ID")
    p_sign.add_argument("--anisette-url", default=DEFAULT_ANISETTE_URL,
                        help="Anisette server URL")
    p_sign.add_argument("--skip-sign", action="store_true",
                        help="Skip signing (for paranoid users)")
    p_sign.add_argument("--install", action="store_true",
                        help="Install signed IPA on device via ideviceinstaller after signing")

    # provision
    p_prov = sub.add_parser("provision", help="Generate cert + profile only")
    p_prov.add_argument("--udid", required=True, help="Device UDID")
    p_prov.add_argument("--bundle-id", required=True, help="App bundle ID")
    p_prov.add_argument("--output-dir", default=".", help="Output directory")
    p_prov.add_argument("--anisette-url", default=DEFAULT_ANISETTE_URL)

    # check
    p_check = sub.add_parser("check", help="Check anisette server status")
    p_check.add_argument("--anisette-url", default=DEFAULT_ANISETTE_URL)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "check":
        url = args.anisette_url
        print(f"[*] Checking anisette server: {url}")
        if AnisetteProvider.check_server(url):
            print(f"[+] Server is UP")
            provider = AnisetteProvider(url)
            data = provider.fetch()
            print(f"[+] X-Apple-I-MD:   {data.get('X-Apple-I-MD', 'N/A')[:20]}...")
            print(f"[+] X-Apple-I-MD-M: {data.get('X-Apple-I-MD-M', 'N/A')[:20]}...")
        else:
            print(f"[!] Server is DOWN")
            print()
            print("  Start with Docker:")
            print("    docker run -d --restart always --name omnisette \\")
            print("      -p 6969:80 \\")
            print("      --volume omnisette_data:/opt/omnisette-server/lib \\")
            print("      ghcr.io/sidestore/omnisette-server:latest")
            sys.exit(1)

    elif args.command == "sign":
        result = sign_ipa_with_apple_id(
            ipa_path=args.ipa,
            output_path=args.output,
            udid=args.udid,
            bundle_id=args.bundle_id,
            anisette_url=args.anisette_url,
            skip_sign=args.skip_sign,
        )
        if not result:
            sys.exit(1)
        if args.install:
            install_ipa_on_device(result, udid=args.udid)

    elif args.command == "provision":
        signer = interactive_login(args.anisette_url)
        if not signer:
            sys.exit(1)

        from cryptography.hazmat.primitives import serialization

        pk_pem, profile_bytes, cert_der, actual_bundle_id = signer.provision(
            args.udid, args.bundle_id, args.bundle_id.split(".")[-1]
        )

        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        # Save private key
        pk_path = out_dir / "development_key.pem"
        with open(pk_path, "wb") as f:
            f.write(pk_pem)
        print(f"[+] Private key: {pk_path}")

        # Save provisioning profile
        profile_path = out_dir / "profile.mobileprovision"
        with open(profile_path, "wb") as f:
            f.write(profile_bytes)
        print(f"[+] Profile: {profile_path}")

        # Save certificate
        if cert_der:
            cert_path = out_dir / "development_cert.der"
            with open(cert_path, "wb") as f:
                f.write(cert_der if isinstance(cert_der, bytes) else base64.b64decode(cert_der))
            print(f"[+] Certificate: {cert_path}")

        # Create .p12
        if cert_der:
            p12_path = str(out_dir / "development.p12")
            signer.create_p12(pk_pem, cert_der, p12_path)

        print()
        print("=" * 60)
        print("[+] Signing materials saved!")
        print(f"    Use with zsign or patcher.py:")
        print(f"      python3 tools/patcher.py sign --ipa MyApp.ipa --p12 {out_dir}/development.p12 -m {out_dir}/profile.mobileprovision")
        print("=" * 60)
