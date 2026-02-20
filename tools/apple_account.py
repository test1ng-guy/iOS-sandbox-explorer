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

import base64
import getpass
import hashlib
import hmac as hmac_mod
import os
import plistlib
import secrets
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import requests
except ImportError:
    print("[!] 'requests' not installed. Run: pip install requests")
    sys.exit(1)


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
            r = requests.get(self.server_url, timeout=10)
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
            r = requests.get(url, timeout=3)
            return r.status_code == 200
        except Exception:
            return False


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

    def _gsa_request(self, params: dict) -> dict:
        """Send authenticated request to GSA service."""
        body = {
            "Header": {"Version": "1.0.1"},
            "Request": {"cpd": self.anisette.generate_cpd()},
        }
        body["Request"].update(params)

        resp = requests.post(
            GSA_URL,
            headers={
                "Content-Type": "text/x-xml-plist",
                "Accept": "*/*",
                "User-Agent": USER_AGENT_GSA,
                "X-MMe-Client-Info": CLIENT_INFO,
            },
            data=plistlib.dumps(body),
            verify=True,
            timeout=15,
        )

        parsed = plistlib.loads(resp.content)
        return parsed.get("Response", parsed)

    @staticmethod
    def _encrypt_password(password: str, salt: bytes, iterations: int,
                          protocol: str = "s2k") -> bytes:
        """Derive SRP password using Apple's PBKDF2 scheme."""
        import pbkdf2 as _pbkdf2

        p = hashlib.sha256(password.encode("utf-8")).digest()

        if protocol == "s2k_fo":
            # For newer accounts: hex-encode the SHA-256 digest
            p = p.hex().encode()

        return _pbkdf2.PBKDF2(p, salt, iterations, hashlib.sha256).read(32)

    @staticmethod
    def _decrypt_cbc(session_key: bytes, data: bytes) -> bytes:
        """Decrypt AES-256-CBC encrypted server data."""
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

        usr = _srp.User(username, bytes(), hash_alg=_srp.SHA256, ng_type=_srp.NG_2048)
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
        spd_bytes = self._decrypt_cbc(usr.get_session_key(), r2["spd"])
        spd = plistlib.loads(spd_bytes)

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
        requests.get(
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

        resp = requests.get(
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

        requests.put(
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

        resp = requests.post(
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
        r = self._gsa_request({
            "u": self.adsid,
            "app": [app_id],
            "c": self.cookie,
            "t": self.idms_token,
            "checksum": checksum,
            "o": "apptokens",
        })

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
        token_plist = plistlib.loads(token_plist_bytes)

        token = token_plist.get("t", {}).get(app_id, {}).get("token")
        if not token:
            raise Exception("Xcode token not found in decrypted response")

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
        }
        headers.update(self.auth.anisette.generate_headers())

        resp = requests.post(
            url,
            headers=headers,
            data=plistlib.dumps(body),
            verify=True,
            timeout=20,
        )

        result = plistlib.loads(resp.content)

        # Check for errors
        rc = result.get("resultCode", 0)
        if rc != 0:
            rm = result.get("resultString", "")
            ue = result.get("userString", rm)
            raise Exception(f"Developer Portal error ({rc}): {ue}")

        return result

    def list_teams(self) -> list:
        """List development teams associated with this Apple ID."""
        r = self._request("listTeams.action", device_type="")
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
        self._request("revokeDevelopmentCert.action", {
            "teamId": self.team_id,
            "serialNumber": serial_number,
        })
        print(f"[+] Certificate revoked")

    def add_app_id(self, bundle_id: str, name: str) -> dict:
        """Register a new App ID."""
        print(f"[*] Creating App ID: {bundle_id}")
        try:
            r = self._request("addAppId.action", {
                "teamId": self.team_id,
                "identifier": bundle_id,
                "name": name,
            })
            print(f"[+] App ID created: {bundle_id}")
            return r.get("appId", {})
        except Exception as e:
            if "already exists" in str(e).lower() or "is not available" in str(e).lower():
                print(f"[*] App ID already exists, reusing")
                return self.find_app_id(bundle_id)
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

        # Check existing certificates (free accounts limited to 2)
        certs = self.portal.list_certificates()
        if len(certs) >= 2:
            print(f"[!] Max certificates reached ({len(certs)}). Revoking oldest...")
            oldest = sorted(certs, key=lambda c: c.get("dateCreated", ""))
            self.portal.revoke_certificate(oldest[0]["serialNumber"])

        # Generate key pair + CSR
        self._private_key, csr_pem = self.portal.generate_csr()
        self.portal.submit_csr(csr_pem)

        # Get the certificate we just created
        certs = self.portal.list_certificates()
        cert_der = None
        for cert in certs:
            if cert.get("machineName") == "IOSSandboxExplorer":
                cert_der = cert.get("certContent")
                break
        if cert_der is None and certs:
            cert_der = certs[-1].get("certContent")

        # Create App ID
        app_id = self.portal.add_app_id(bundle_id, app_name)
        if not app_id:
            app_id = self.portal.find_app_id(bundle_id)

        app_id_id = app_id.get("appIdId")
        if not app_id_id:
            raise Exception(f"Could not find appIdId for {bundle_id}")

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
        print(f"    Bundle ID:  {bundle_id}")
        print(f"    Device:     {udid[:12]}...")
        print(f"    Profile:    {len(profile_bytes)} bytes")
        print(f"    Cert:       {len(cert_der) if cert_der else 0} bytes")

        return private_key_pem, profile_bytes, cert_der

    def create_p12(self, private_key_pem: bytes, cert_der: bytes,
                   output_path: str, password: str = "") -> str:
        """
        Create .p12 (PKCS#12) file from private key and certificate.
        For use with zsign.
        """
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
        private_key_pem, profile_bytes, cert_der = self.provision(
            udid, bundle_id, app_name
        )

        # Create temp files for signing
        temp_dir = Path(tempfile.mkdtemp(prefix="apple_sign_"))
        try:
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
                # No zsign — save files for user to sign manually
                final_p12 = ipa_path.replace(".ipa", "_cert.p12")
                final_profile = ipa_path.replace(".ipa", ".mobileprovision")
                shutil.copy2(p12_path, final_p12)
                shutil.copy2(profile_path, final_profile)

                print()
                print("=" * 60)
                print("[!] zsign not found — saved signing materials:")
                print(f"    Certificate: {final_p12}")
                print(f"    Profile:     {final_profile}")
                print()
                print("    Install zsign to sign from CLI:")
                print("      git clone https://github.com/nicetransistor/zSign.git")
                print("      cd zSign && make && sudo cp zsign /usr/local/bin/")
                print()
                print("    Then sign manually:")
                print(f"      zsign -k {final_p12} -m {final_profile} -o {output_path} {ipa_path}")
                print()
                print("    Or use Sideloadly with these files.")
                print("=" * 60)
                return ""

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

def interactive_login(anisette_url: str = DEFAULT_ANISETTE_URL) -> AppleSigner:
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
    print("  • Requires omnisette-server for anisette data")
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

    # Check anisette server
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

    apple_id = input("Apple ID (email): ").strip()
    if not apple_id:
        print("[!] Cancelled")
        return None

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

    signer = interactive_login(anisette_url)
    if not signer:
        return ""

    return signer.sign_ipa(ipa_path, output_path, udid, bundle_id)


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

    elif args.command == "provision":
        signer = interactive_login(args.anisette_url)
        if not signer:
            sys.exit(1)

        from cryptography.hazmat.primitives import serialization

        pk_pem, profile_bytes, cert_der = signer.provision(
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
