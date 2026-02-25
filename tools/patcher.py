#!/usr/bin/env python3
"""
iOS IPA Patcher — Cross-platform tool for injecting dylib into iOS apps.

Works on Windows, Linux, and macOS without Xcode.
Requires: Python 3.8+, lief, pymobiledevice3 (optional, for install)

Usage:
    python3 patcher.py patch       --ipa MyApp.ipa --dylib libShell.dylib [--output patched.ipa]
    python3 patcher.py sign         --ipa patched.ipa --p12 cert.p12 --mobileprovision profile.mobileprovision
    python3 patcher.py sign         --ipa patched.ipa --apple-id user@example.com
    python3 patcher.py sign-apple   --ipa patched.ipa [--udid ...] [--skip-sign]
    python3 patcher.py install      --ipa patched.ipa
    python3 patcher.py devices
    python3 patcher.py full         --ipa MyApp.ipa --dylib libShell.dylib [--apple-id ...] [--skip-sign]
"""

import argparse
import os
import plistlib
import shutil
import struct
import sys
import tempfile
import zipfile
from pathlib import Path

# ─── Constants ────────────────────────────────────────────────────────────────

DYLIB_LOAD_COMMAND = 0x0C        # LC_LOAD_DYLIB
DYLIB_LOAD_WEAK_COMMAND = 0x18   # LC_LOAD_WEAK_DYLIB
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA


# ─── Mach-O Injection (pure Python, no lief dependency) ──────────────────────

class MachOInjector:
    """
    Injects LC_LOAD_DYLIB into a Mach-O binary.
    Supports thin arm64 and FAT binaries.
    Falls back to `lief` library if available for complex cases.
    """

    @staticmethod
    def inject(binary_path: str, dylib_install_name: str, use_lief: bool = False) -> bool:
        """
        Inject dylib reference into Mach-O binary.
        
        Args:
            binary_path: Path to the Mach-O binary to modify
            dylib_install_name: Install name, e.g. "@executable_path/Frameworks/libShell.dylib"
            use_lief: If True, use lief library instead of manual injection
            
        Returns:
            True if injection succeeded
        """
        if use_lief:
            return MachOInjector._inject_with_lief(binary_path, dylib_install_name)
        return MachOInjector._inject_manual(binary_path, dylib_install_name)

    @staticmethod
    def _inject_with_lief(binary_path: str, dylib_install_name: str) -> bool:
        """Inject using lief library."""
        try:
            import lief
        except ImportError:
            print("[!] lief not installed. Install with: pip install lief")
            print("[*] Falling back to manual Mach-O injection...")
            return MachOInjector._inject_manual(binary_path, dylib_install_name)

        binary = lief.MachO.parse(binary_path)
        if binary is None:
            print(f"[!] Failed to parse Mach-O: {binary_path}")
            return False

        for b in binary:
            # Check if already injected
            for lib in b.libraries:
                if dylib_install_name in lib.name:
                    print(f"[*] Dylib already injected: {lib.name}")
                    return True
            b.add_library(dylib_install_name)
            print(f"[+] Injected {dylib_install_name} into slice")

        binary.write(binary_path)
        print(f"[+] Saved modified binary: {binary_path}")
        return True

    @staticmethod
    def _inject_manual(binary_path: str, dylib_install_name: str) -> bool:
        """
        Manual LC_LOAD_DYLIB injection into Mach-O binary.
        Works without any external dependencies.
        """
        with open(binary_path, 'rb') as f:
            data = bytearray(f.read())

        # Detect FAT or thin binary
        magic = struct.unpack_from('>I', data, 0)[0]

        if magic in (FAT_MAGIC, FAT_CIGAM):
            return MachOInjector._inject_fat(data, binary_path, dylib_install_name)
        else:
            success = MachOInjector._inject_thin(data, 0, dylib_install_name)
            if success:
                with open(binary_path, 'wb') as f:
                    f.write(data)
                print(f"[+] Saved modified binary: {binary_path}")
            return success

    @staticmethod
    def _inject_fat(data: bytearray, binary_path: str, dylib_install_name: str) -> bool:
        """Inject into all slices of a FAT binary."""
        magic = struct.unpack_from('>I', data, 0)[0]
        swap = (magic == FAT_CIGAM)

        if swap:
            nfat = struct.unpack_from('<I', data, 4)[0]
        else:
            nfat = struct.unpack_from('>I', data, 4)[0]

        print(f"[*] FAT binary with {nfat} slices")
        all_ok = True

        for i in range(nfat):
            arch_offset = 8 + i * 20
            if swap:
                offset = struct.unpack_from('<I', data, arch_offset + 8)[0]
            else:
                offset = struct.unpack_from('>I', data, arch_offset + 8)[0]

            print(f"[*] Processing slice at offset {offset}")
            if not MachOInjector._inject_thin(data, offset, dylib_install_name):
                all_ok = False

        if all_ok:
            with open(binary_path, 'wb') as f:
                f.write(data)
            print(f"[+] Saved modified FAT binary: {binary_path}")
        return all_ok

    @staticmethod
    def _inject_thin(data: bytearray, base_offset: int, dylib_install_name: str) -> bool:
        """Inject LC_LOAD_DYLIB into a single Mach-O slice."""
        magic = struct.unpack_from('<I', data, base_offset)[0]

        if magic == MH_MAGIC_64:
            is_64 = True
        elif magic == MH_CIGAM_64:
            is_64 = True
        elif magic == 0xFEEDFACE:
            is_64 = False
        elif magic == 0xCEFAEDFE:
            is_64 = False
        else:
            print(f"[!] Unknown Mach-O magic: {hex(magic)}")
            return False

        header_size = 32 if is_64 else 28

        # Read header
        ncmds = struct.unpack_from('<I', data, base_offset + 16)[0]
        sizeofcmds = struct.unpack_from('<I', data, base_offset + 20)[0]

        # Walk existing load commands to check if already injected
        cmd_offset = base_offset + header_size
        for _ in range(ncmds):
            cmd = struct.unpack_from('<I', data, cmd_offset)[0]
            cmdsize = struct.unpack_from('<I', data, cmd_offset + 4)[0]

            if cmd in (DYLIB_LOAD_COMMAND, DYLIB_LOAD_WEAK_COMMAND):
                # Read dylib name offset (relative to cmd_offset)
                name_offset = struct.unpack_from('<I', data, cmd_offset + 8)[0]
                name_start = cmd_offset + name_offset
                name_end = data.index(0, name_start)
                existing_name = data[name_start:name_end].decode('utf-8', errors='ignore')
                if dylib_install_name in existing_name:
                    print(f"[*] Already injected: {existing_name}")
                    return True

            cmd_offset += cmdsize

        # Build the new LC_LOAD_DYLIB command
        dylib_name_bytes = dylib_install_name.encode('utf-8') + b'\x00'
        # LC_LOAD_DYLIB structure:
        #   cmd (4) + cmdsize (4) + name_offset (4) + timestamp (4) +
        #   current_version (4) + compat_version (4) + name string
        name_offset_val = 24  # offset to name from start of command
        cmd_body = bytearray(struct.pack('<II', DYLIB_LOAD_COMMAND, 0))  # cmd, cmdsize (placeholder)
        cmd_body += struct.pack('<I', name_offset_val)  # name offset
        cmd_body += struct.pack('<I', 2)  # timestamp
        cmd_body += struct.pack('<I', 0x00010000)  # current_version (1.0.0)
        cmd_body += struct.pack('<I', 0x00010000)  # compat_version (1.0.0)
        cmd_body += dylib_name_bytes

        # Pad to 8-byte alignment
        while len(cmd_body) % 8 != 0:
            cmd_body += b'\x00'

        new_cmdsize = len(cmd_body)
        struct.pack_into('<I', cmd_body, 4, new_cmdsize)  # fix cmdsize

        # Check if there's space in the header padding
        cmds_end = base_offset + header_size + sizeofcmds
        # Check for zero-padding after load commands
        available_space = 0
        check_offset = cmds_end
        while check_offset < len(data) and data[check_offset] == 0:
            available_space += 1
            check_offset += 1
            if available_space >= new_cmdsize:
                break

        if available_space < new_cmdsize:
            print(f"[!] Not enough space for injection. Need {new_cmdsize} bytes, have {available_space}")
            print("[!] Try using --use-lief flag for smarter injection")
            return False

        # Write new command at the end of existing commands
        data[cmds_end:cmds_end + new_cmdsize] = cmd_body

        # Update header: ncmds += 1, sizeofcmds += new_cmdsize
        struct.pack_into('<I', data, base_offset + 16, ncmds + 1)
        struct.pack_into('<I', data, base_offset + 20, sizeofcmds + new_cmdsize)

        print(f"[+] Injected LC_LOAD_DYLIB: {dylib_install_name}")
        return True


# ─── IPA Handler ──────────────────────────────────────────────────────────────

class IPAHandler:
    """Handles IPA unpacking, modification, and repacking."""

    def __init__(self, ipa_path: str):
        self.ipa_path = Path(ipa_path)
        self.temp_dir = None
        self.app_bundle = None
        self.binary_path = None
        self.info_plist_path = None

    def unpack(self) -> str:
        """Unpack IPA to temporary directory. Returns temp dir path."""
        self.temp_dir = Path(tempfile.mkdtemp(prefix='ipa_patch_'))
        print(f"[*] Unpacking IPA to {self.temp_dir}")

        with zipfile.ZipFile(self.ipa_path, 'r') as zf:
            zf.extractall(self.temp_dir)

        # Find .app bundle
        payload_dir = self.temp_dir / 'Payload'
        if not payload_dir.exists():
            raise FileNotFoundError("No Payload directory found in IPA")

        app_bundles = list(payload_dir.glob('*.app'))
        if not app_bundles:
            raise FileNotFoundError("No .app bundle found in Payload/")

        self.app_bundle = app_bundles[0]
        print(f"[+] Found app bundle: {self.app_bundle.name}")

        # Find main binary via Info.plist
        self.info_plist_path = self.app_bundle / 'Info.plist'
        if not self.info_plist_path.exists():
            raise FileNotFoundError("Info.plist not found in app bundle")

        with open(self.info_plist_path, 'rb') as f:
            info = plistlib.load(f)

        executable_name = info.get('CFBundleExecutable')
        if not executable_name:
            raise ValueError("CFBundleExecutable not found in Info.plist")

        self.binary_path = self.app_bundle / executable_name
        if not self.binary_path.exists():
            raise FileNotFoundError(f"Main binary not found: {self.binary_path}")

        print(f"[+] Main binary: {executable_name}")
        return str(self.temp_dir)

    def inject_dylib(self, dylib_path: str, use_lief: bool = False) -> bool:
        """Copy dylib to Frameworks/ and inject LC_LOAD_DYLIB into binary."""
        if not self.app_bundle:
            raise RuntimeError("IPA not unpacked yet. Call unpack() first.")

        dylib_src = Path(dylib_path)
        if not dylib_src.exists():
            raise FileNotFoundError(f"Dylib not found: {dylib_path}")

        dylib_name = dylib_src.name

        # Copy dylib to Frameworks/
        frameworks_dir = self.app_bundle / 'Frameworks'
        frameworks_dir.mkdir(exist_ok=True)
        dylib_dst = frameworks_dir / dylib_name
        shutil.copy2(dylib_src, dylib_dst)
        print(f"[+] Copied {dylib_name} to Frameworks/")

        # Inject LC_LOAD_DYLIB into main binary
        install_name = f"@executable_path/Frameworks/{dylib_name}"
        return MachOInjector.inject(str(self.binary_path), install_name, use_lief=use_lief)

    def patch_plist(self):
        """
        Update Info.plist:
        - Allow arbitrary network loads (NSAppTransportSecurity)
        """
        if not self.info_plist_path:
            raise RuntimeError("IPA not unpacked yet.")

        with open(self.info_plist_path, 'rb') as f:
            info = plistlib.load(f)

        # Allow arbitrary loads for TCP server
        if 'NSAppTransportSecurity' not in info:
            info['NSAppTransportSecurity'] = {}
        info['NSAppTransportSecurity']['NSAllowsArbitraryLoads'] = True

        with open(self.info_plist_path, 'wb') as f:
            plistlib.dump(info, f)

        print("[+] Updated Info.plist: NSAllowsArbitraryLoads = true")

    def create_entitlements(self) -> str:
        """Create entitlements plist file. Returns path to entitlements file."""
        entitlements = {
            'com.apple.security.network.server': True,
            'com.apple.security.network.client': True,
            'get-task-allow': True,
        }

        ent_path = self.temp_dir / 'entitlements.plist'
        with open(ent_path, 'wb') as f:
            plistlib.dump(entitlements, f)

        print(f"[+] Created entitlements: {ent_path}")
        return str(ent_path)

    def repack(self, output_path: str) -> str:
        """Repack modified app into IPA."""
        if not self.temp_dir:
            raise RuntimeError("Nothing to repack.")

        output = Path(output_path)
        print(f"[*] Repacking IPA to {output}")

        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as zf:
            payload_dir = self.temp_dir / 'Payload'
            for file_path in payload_dir.rglob('*'):
                arcname = file_path.relative_to(self.temp_dir)
                if file_path.is_file():
                    zf.write(file_path, arcname)

        print(f"[+] Patched IPA saved: {output}")
        return str(output)

    def cleanup(self):
        """Remove temporary directory."""
        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
            print("[*] Cleaned up temp files")


# ─── Code Signing (optional, via zsign or ldid) ──────────────────────────────

class CodeSigner:
    """
    Cross-platform code signing.
    Supports:
      - zsign (recommended, works on all platforms)
      - ldid  (for fakesigning / jailbreak)
    """

    @staticmethod
    def find_signer() -> str | None:
        """Find available signing tool."""
        for tool in ('zsign', 'ldid'):
            if shutil.which(tool):
                return tool
        return None

    @staticmethod
    def sign_with_zsign(ipa_path: str, output_path: str,
                        p12_path: str = None, p12_password: str = "",
                        mobileprovision_path: str = None,
                        entitlements_path: str = None) -> bool:
        """Sign IPA using zsign."""
        import subprocess

        cmd = ['zsign']

        if p12_path:
            cmd.extend(['-k', p12_path])
            if p12_password:
                cmd.extend(['-p', p12_password])

        if mobileprovision_path:
            cmd.extend(['-m', mobileprovision_path])

        if entitlements_path:
            cmd.extend(['-e', entitlements_path])

        cmd.extend(['-o', output_path, ipa_path])

        print(f"[*] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            print(f"[+] Signed IPA: {output_path}")
            return True
        else:
            print(f"[!] zsign failed: {result.stderr}")
            return False

    @staticmethod
    def sign_with_ldid(binary_path: str, entitlements_path: str = None) -> bool:
        """Fakesign binary using ldid (for jailbreak or subsequent re-signing)."""
        import subprocess

        cmd = ['ldid']
        if entitlements_path:
            cmd.append(f'-S{entitlements_path}')
        else:
            cmd.append('-S')
        cmd.append(binary_path)

        print(f"[*] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            print(f"[+] Fakesigned: {binary_path}")
            return True
        else:
            print(f"[!] ldid failed: {result.stderr}")
            return False


# ─── Device Installation (via pymobiledevice3) ───────────────────────────────

class DeviceManager:
    """Manage iOS device connection and IPA installation."""

    @staticmethod
    def _check_pymobiledevice3():
        try:
            import pymobiledevice3
            return True
        except ImportError:
            print("[!] pymobiledevice3 not installed.")
            print("    Install with: pip install pymobiledevice3")
            return False

    @staticmethod
    def list_devices():
        """List connected iOS devices."""
        if not DeviceManager._check_pymobiledevice3():
            return

        from pymobiledevice3.usbmux import list_devices as usbmux_list
        devices = usbmux_list()

        if not devices:
            print("[*] No iOS devices connected.")
            return

        print(f"[+] Found {len(devices)} device(s):")
        for i, dev in enumerate(devices):
            print(f"  [{i}] UDID: {dev.serial}")

    @staticmethod
    def install_ipa(ipa_path: str):
        """Install IPA onto connected iOS device."""
        if not DeviceManager._check_pymobiledevice3():
            return False

        from pymobiledevice3.usbmux import select_devices_by_connection_type
        from pymobiledevice3.lockdown import LockdownClient
        from pymobiledevice3.services.installation_proxy import InstallationProxyService

        devices = select_devices_by_connection_type(connection_type='USB')
        if not devices:
            print("[!] No USB-connected iOS devices found.")
            return False

        device = devices[0]
        print(f"[*] Installing on device: {device.serial}")

        lockdown = LockdownClient(device)
        service = InstallationProxyService(lockdown=lockdown)

        print(f"[*] Installing {ipa_path}...")
        service.install_from_local(ipa_path)
        print("[+] Installation complete!")
        return True

    @staticmethod
    def start_tunnel(local_port: int = 8080, remote_port: int = 8080):
        """Start USB tunnel (iproxy equivalent)."""
        import subprocess

        # Try pymobiledevice3 tunnel first
        print(f"[*] Starting USB tunnel: localhost:{local_port} -> device:{remote_port}")

        # Check for iproxy
        if shutil.which('iproxy'):
            cmd = ['iproxy', str(local_port), str(remote_port)]
            print(f"[*] Running: {' '.join(cmd)}")
            subprocess.Popen(cmd)
            print(f"[+] Tunnel active: localhost:{local_port}")
            return True

        print("[!] iproxy not found. Install libimobiledevice:")
        print("    Ubuntu:  sudo apt install libimobiledevice-utils")
        print("    macOS:   brew install libimobiledevice")
        print("    Windows: Download from https://libimobiledevice.org/")
        return False


# ─── CLI Commands ─────────────────────────────────────────────────────────────

def cmd_patch(args):
    """Patch IPA: inject dylib, modify plist, repack."""
    ipa = IPAHandler(args.ipa)

    try:
        ipa.unpack()
        ipa.inject_dylib(args.dylib, use_lief=args.use_lief)
        ipa.patch_plist()
        ipa.create_entitlements()

        output = args.output or args.ipa.replace('.ipa', '_patched.ipa')
        ipa.repack(output)

        print()
        print("=" * 60)
        print("[+] PATCHED IPA READY (unsigned)")
        print(f"    Output: {output}")
        print()
        print("    Next steps:")
        print("    1. Install with Sideloadly (handles signing automatically)")
        print("       → Open Sideloadly, select the patched IPA, connect device")
        print()
        print("    2. OR sign manually:")
        print(f"       python3 {sys.argv[0]} sign --ipa {output} --p12 cert.p12 --mobileprovision profile.mobileprovision")
        print("=" * 60)

    finally:
        ipa.cleanup()


def cmd_sign(args):
    """Sign a patched IPA."""

    # ── Apple ID signing ──
    apple_id = getattr(args, 'apple_id', None)
    skip_sign = getattr(args, 'skip_sign', False)

    if skip_sign:
        print("[*] Signing skipped (--skip-sign)")
        print(f"[*] Use Sideloadly to install unsigned IPA: {args.ipa}")
        return

    if apple_id:
        try:
            from apple_account import sign_ipa_with_apple_id
        except ImportError:
            sys.path.insert(0, str(Path(__file__).parent))
            from apple_account import sign_ipa_with_apple_id

        output = args.output or args.ipa.replace('.ipa', '_signed.ipa')
        anisette_url = getattr(args, 'anisette_url', 'http://localhost:6969')
        udid = getattr(args, 'udid', None)

        sign_ipa_with_apple_id(
            ipa_path=args.ipa,
            output_path=output,
            udid=udid,
            anisette_url=anisette_url,
        )
        return

    # ── Certificate-based signing (p12 / ldid) ──
    signer = CodeSigner.find_signer()

    if args.p12:
        # Sign with zsign + certificate
        if not shutil.which('zsign'):
            print("[!] zsign not found. Install it:")
            print("    git clone https://github.com/nicetransistor/zSign.git && cd zSign && make")
            print("    Or download from releases.")
            return

        output = args.output or args.ipa.replace('.ipa', '_signed.ipa')
        CodeSigner.sign_with_zsign(
            ipa_path=args.ipa,
            output_path=output,
            p12_path=args.p12,
            p12_password=args.p12_password or "",
            mobileprovision_path=args.mobileprovision,
            entitlements_path=args.entitlements,
        )
    elif signer == 'ldid':
        print("[*] Using ldid for fakesigning (jailbreak only)")
        ipa = IPAHandler(args.ipa)
        try:
            ipa.unpack()
            ent_path = ipa.create_entitlements()
            CodeSigner.sign_with_ldid(str(ipa.binary_path), ent_path)

            # Also sign dylib if present
            frameworks = ipa.app_bundle / 'Frameworks'
            if frameworks.exists():
                for dylib in frameworks.glob('*.dylib'):
                    CodeSigner.sign_with_ldid(str(dylib))

            output = args.output or args.ipa.replace('.ipa', '_signed.ipa')
            ipa.repack(output)
        finally:
            ipa.cleanup()
    else:
        print("[!] No signing method available.")
        print()
        print("    Option 1: Sign with Apple ID (free, cross-platform):")
        print(f"      python3 {sys.argv[0]} sign --ipa {args.ipa} --apple-id your@email.com")
        print()
        print("    Option 2: Use Sideloadly (handles signing automatically)")
        print("    Option 3: Install zsign + provide .p12 + .mobileprovision")
        print("    Option 4: Install ldid for fakesigning (jailbreak)")


def cmd_install(args):
    """Install IPA on connected device."""
    DeviceManager.install_ipa(args.ipa)


def cmd_devices(args):
    """List connected iOS devices."""
    DeviceManager.list_devices()


def cmd_tunnel(args):
    """Start USB tunnel."""
    DeviceManager.start_tunnel(args.local_port, args.remote_port)


def cmd_sign_apple(args):
    """Sign IPA using Apple ID (interactive)."""
    try:
        from apple_account import sign_ipa_with_apple_id
    except ImportError:
        sys.path.insert(0, str(Path(__file__).parent))
        from apple_account import sign_ipa_with_apple_id

    output = args.output or args.ipa.replace('.ipa', '_signed.ipa')
    sign_ipa_with_apple_id(
        ipa_path=args.ipa,
        output_path=output,
        udid=args.udid,
        bundle_id=args.bundle_id,
        anisette_url=args.anisette_url,
        skip_sign=args.skip_sign,
    )


def cmd_full(args):
    """Full pipeline: patch → sign (optional) → install."""
    ipa = IPAHandler(args.ipa)

    try:
        ipa.unpack()
        ipa.inject_dylib(args.dylib, use_lief=args.use_lief)
        ipa.patch_plist()
        ent_path = ipa.create_entitlements()

        output = args.output or args.ipa.replace('.ipa', '_patched.ipa')
        ipa.repack(output)

        skip_sign = getattr(args, 'skip_sign', False)
        apple_id = getattr(args, 'apple_id', None)

        if skip_sign:
            print("[*] Signing skipped (--skip-sign)")
            print(f"[*] Use Sideloadly to install: {output}")
        elif apple_id:
            # Sign with Apple ID
            try:
                from apple_account import sign_ipa_with_apple_id
            except ImportError:
                sys.path.insert(0, str(Path(__file__).parent))
                from apple_account import sign_ipa_with_apple_id

            anisette_url = getattr(args, 'anisette_url', 'http://localhost:6969')
            udid = getattr(args, 'udid', None)
            signed_output = output.replace('.ipa', '_signed.ipa')
            result = sign_ipa_with_apple_id(
                ipa_path=output,
                output_path=signed_output,
                udid=udid,
                anisette_url=anisette_url,
            )
            if result:
                output = signed_output
        elif args.p12:
            # Sign with certificate
            signed_output = output.replace('.ipa', '_signed.ipa')
            CodeSigner.sign_with_zsign(
                ipa_path=output,
                output_path=signed_output,
                p12_path=args.p12,
                p12_password=args.p12_password or "",
                mobileprovision_path=args.mobileprovision,
                entitlements_path=ent_path,
            )
            output = signed_output

        # Install if requested
        if getattr(args, 'install', False):
            DeviceManager.install_ipa(output)

        print()
        print("=" * 60)
        print(f"[+] Done! Output: {output}")
        print("=" * 60)

    finally:
        ipa.cleanup()


# ─── Argument Parser ─────────────────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog='patcher',
        description='iOS IPA Patcher — Cross-platform dylib injection tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Patch IPA (then install via Sideloadly)
  python3 patcher.py patch --ipa MyApp.ipa --dylib libShell.dylib

  # Sign with Apple ID (free, cross-platform)
  python3 patcher.py sign --ipa MyApp_patched.ipa --apple-id user@example.com

  # Sign with Apple ID (dedicated command, more options)
  python3 patcher.py sign-apple --ipa MyApp_patched.ipa --udid 00008030-...

  # Skip signing (paranoid mode — use Sideloadly instead)
  python3 patcher.py sign-apple --ipa MyApp_patched.ipa --skip-sign

  # Sign with .p12 certificate
  python3 patcher.py sign --ipa MyApp_patched.ipa --p12 cert.p12 -m profile.mobileprovision

  # Full pipeline: patch + sign with Apple ID + install
  python3 patcher.py full --ipa MyApp.ipa --dylib libShell.dylib --apple-id user@example.com --install

  # Full pipeline: patch only, skip signing
  python3 patcher.py full --ipa MyApp.ipa --dylib libShell.dylib --skip-sign

  # List connected devices
  python3 patcher.py devices
""",
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # ── patch ──
    p_patch = subparsers.add_parser('patch', help='Patch IPA with dylib injection')
    p_patch.add_argument('--ipa', required=True, help='Path to input IPA file')
    p_patch.add_argument('--dylib', required=True, help='Path to dylib to inject')
    p_patch.add_argument('--output', '-o', help='Output IPA path (default: <name>_patched.ipa)')
    p_patch.add_argument('--use-lief', action='store_true', help='Use lief library for injection (handles edge cases better)')
    p_patch.set_defaults(func=cmd_patch)

    # ── sign ──
    p_sign = subparsers.add_parser('sign', help='Sign IPA (Apple ID / zsign / ldid)')
    p_sign.add_argument('--ipa', required=True, help='Path to IPA to sign')
    p_sign.add_argument('--apple-id', help='Apple ID email (free signing via Apple servers)')
    p_sign.add_argument('--p12', help='Path to .p12 certificate file')
    p_sign.add_argument('--p12-password', help='Password for .p12 file')
    p_sign.add_argument('--mobileprovision', '-m', help='Path to .mobileprovision file')
    p_sign.add_argument('--entitlements', '-e', help='Path to entitlements.plist')
    p_sign.add_argument('--udid', help='Device UDID (auto-detected if connected)')
    p_sign.add_argument('--anisette-url', default='http://localhost:6969', help='Anisette server URL (default: localhost:6969)')
    p_sign.add_argument('--skip-sign', action='store_true', help='Skip signing (use Sideloadly instead)')
    p_sign.add_argument('--output', '-o', help='Output IPA path')
    p_sign.set_defaults(func=cmd_sign)

    # ── sign-apple ──
    p_sapple = subparsers.add_parser('sign-apple', help='Sign IPA with Apple ID (interactive)')
    p_sapple.add_argument('--ipa', required=True, help='Path to IPA to sign')
    p_sapple.add_argument('--output', '-o', help='Output signed IPA path')
    p_sapple.add_argument('--udid', help='Device UDID')
    p_sapple.add_argument('--bundle-id', help='Override bundle identifier')
    p_sapple.add_argument('--anisette-url', default='http://localhost:6969', help='Anisette server URL')
    p_sapple.add_argument('--skip-sign', action='store_true',
                          help='Skip signing entirely (for users who prefer Sideloadly or manual signing)')
    p_sapple.set_defaults(func=cmd_sign_apple)

    # ── install ──
    p_install = subparsers.add_parser('install', help='Install IPA on connected device')
    p_install.add_argument('--ipa', required=True, help='Path to IPA to install')
    p_install.set_defaults(func=cmd_install)

    # ── devices ──
    p_devices = subparsers.add_parser('devices', help='List connected iOS devices')
    p_devices.set_defaults(func=cmd_devices)

    # ── tunnel ──
    p_tunnel = subparsers.add_parser('tunnel', help='Start USB tunnel (iproxy)')
    p_tunnel.add_argument('--local-port', type=int, default=8080, help='Local port (default: 8080)')
    p_tunnel.add_argument('--remote-port', type=int, default=8080, help='Remote port (default: 8080)')
    p_tunnel.set_defaults(func=cmd_tunnel)

    # ── full ──
    p_full = subparsers.add_parser('full', help='Full pipeline: patch → sign → install')
    p_full.add_argument('--ipa', required=True, help='Path to input IPA file')
    p_full.add_argument('--dylib', required=True, help='Path to dylib to inject')
    p_full.add_argument('--output', '-o', help='Output IPA path')
    p_full.add_argument('--use-lief', action='store_true', help='Use lief library for injection')
    p_full.add_argument('--apple-id', help='Apple ID email for free signing')
    p_full.add_argument('--p12', help='Path to .p12 certificate for signing')
    p_full.add_argument('--p12-password', help='Password for .p12 file')
    p_full.add_argument('--mobileprovision', '-m', help='Path to .mobileprovision file')
    p_full.add_argument('--udid', help='Device UDID')
    p_full.add_argument('--anisette-url', default='http://localhost:6969', help='Anisette server URL')
    p_full.add_argument('--skip-sign', action='store_true', help='Skip signing step')
    p_full.add_argument('--install', action='store_true', help='Install on device after patching')
    p_full.set_defaults(func=cmd_full)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    print(r"""
  ___ ___  ___   ___      _       _
 |_ _/ _ \/ __| | _ \__ _| |_ ___| |_  ___ _ _
  | | (_) \__ \ |  _/ _` |  _/ __| ' \/ -_) '_|
 |___\___/|___/ |_| \__,_|\__\___|_||_\___|_|
    """)
    print(f"  Cross-platform IPA patching tool")
    print()

    args.func(args)


if __name__ == '__main__':
    main()
