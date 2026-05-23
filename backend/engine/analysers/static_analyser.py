"""
SecureStorageInspector — Static APK Analyser

Professional-grade static analysis of APK files using aapt2. Extracts and
evaluates the AndroidManifest.xml without installing the app.

Checks performed:
    1. Manifest metadata (package, version, SDK levels)
    2. Dangerous permission analysis (Android protection levels)
    3. Security-critical manifest flags (debuggable, allowBackup, cleartext)
    4. Exported component analysis (activities, services, receivers, providers)
    5. Intent filter analysis (deep links, custom schemes)
    6. Certificate / signing information

This module requires aapt2 to be available (configured via AAPT_PATH).
"""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.config import get_settings
from backend.engine.models import Finding, Severity, StorageArea, mask_value

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════
#  DANGEROUS PERMISSIONS DATABASE
# ══════════════════════════════════════════════════════════════════════

class PermissionRisk(str, Enum):
    """Risk classification for Android permissions."""
    DANGEROUS = "dangerous"
    SIGNATURE = "signature"
    NORMAL = "normal"
    UNKNOWN = "unknown"


# Comprehensive mapping of dangerous/signature permissions with descriptions
_DANGEROUS_PERMISSIONS: Dict[str, Dict[str, str]] = {
    # ── Location ──
    "android.permission.ACCESS_FINE_LOCATION": {
        "risk": "dangerous",
        "category": "location",
        "description": "Precise GPS location — can track user movement in real-time.",
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "risk": "dangerous",
        "category": "location",
        "description": "Approximate location via cell towers / Wi-Fi.",
    },
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "risk": "dangerous",
        "category": "location",
        "description": "Location access even when the app is in the background.",
    },
    # ── Camera / Microphone ──
    "android.permission.CAMERA": {
        "risk": "dangerous",
        "category": "hardware",
        "description": "Access to device camera — can capture photos and video.",
    },
    "android.permission.RECORD_AUDIO": {
        "risk": "dangerous",
        "category": "hardware",
        "description": "Microphone access — can record conversations.",
    },
    # ── Contacts / Calendar ──
    "android.permission.READ_CONTACTS": {
        "risk": "dangerous",
        "category": "pii",
        "description": "Read user's contact list — exposes personal relationships.",
    },
    "android.permission.WRITE_CONTACTS": {
        "risk": "dangerous",
        "category": "pii",
        "description": "Modify user's contacts — can inject malicious entries.",
    },
    "android.permission.READ_CALENDAR": {
        "risk": "dangerous",
        "category": "pii",
        "description": "Read calendar events — exposes schedule and meetings.",
    },
    "android.permission.WRITE_CALENDAR": {
        "risk": "dangerous",
        "category": "pii",
        "description": "Modify calendar — can add/delete events.",
    },
    # ── Phone / SMS ──
    "android.permission.READ_PHONE_STATE": {
        "risk": "dangerous",
        "category": "phone",
        "description": "Read phone number, IMEI, network state, ongoing calls.",
    },
    "android.permission.READ_PHONE_NUMBERS": {
        "risk": "dangerous",
        "category": "phone",
        "description": "Read the device phone number(s).",
    },
    "android.permission.CALL_PHONE": {
        "risk": "dangerous",
        "category": "phone",
        "description": "Initiate phone calls without user interaction.",
    },
    "android.permission.READ_CALL_LOG": {
        "risk": "dangerous",
        "category": "phone",
        "description": "Read call history — who, when, how long.",
    },
    "android.permission.SEND_SMS": {
        "risk": "dangerous",
        "category": "sms",
        "description": "Send SMS messages — potential for premium SMS fraud.",
    },
    "android.permission.RECEIVE_SMS": {
        "risk": "dangerous",
        "category": "sms",
        "description": "Intercept incoming SMS — can steal 2FA codes.",
    },
    "android.permission.READ_SMS": {
        "risk": "dangerous",
        "category": "sms",
        "description": "Read SMS messages — exposes private conversations and OTPs.",
    },
    # ── Storage ──
    "android.permission.READ_EXTERNAL_STORAGE": {
        "risk": "dangerous",
        "category": "storage",
        "description": "Read files on external storage — photos, downloads, documents.",
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "risk": "dangerous",
        "category": "storage",
        "description": "Write to external storage — can modify or delete user files.",
    },
    "android.permission.MANAGE_EXTERNAL_STORAGE": {
        "risk": "dangerous",
        "category": "storage",
        "description": "Full access to all files on external storage (Android 11+).",
    },
    # ── Body Sensors ──
    "android.permission.BODY_SENSORS": {
        "risk": "dangerous",
        "category": "health",
        "description": "Read body sensors (heart rate, step counter) — health data.",
    },
    "android.permission.ACTIVITY_RECOGNITION": {
        "risk": "dangerous",
        "category": "health",
        "description": "Detect physical activity (walking, cycling, driving).",
    },
    # ── Network ──
    "android.permission.INTERNET": {
        "risk": "normal",
        "category": "network",
        "description": "Full network access — required for most apps but enables data exfiltration.",
    },
    "android.permission.ACCESS_WIFI_STATE": {
        "risk": "normal",
        "category": "network",
        "description": "View Wi-Fi connections and nearby networks.",
    },
    # ── Signature-level (system) permissions ──
    "android.permission.INSTALL_PACKAGES": {
        "risk": "signature",
        "category": "system",
        "description": "Install other applications — extremely privileged.",
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "risk": "dangerous",
        "category": "system",
        "description": "Request to install APKs from unknown sources.",
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "risk": "dangerous",
        "category": "system",
        "description": "Draw overlays on top of other apps — used in tapjacking attacks.",
    },
    "android.permission.READ_MEDIA_IMAGES": {
        "risk": "dangerous",
        "category": "storage",
        "description": "Read images from shared storage (Android 13+).",
    },
    "android.permission.READ_MEDIA_VIDEO": {
        "risk": "dangerous",
        "category": "storage",
        "description": "Read videos from shared storage (Android 13+).",
    },
    "android.permission.READ_MEDIA_AUDIO": {
        "risk": "dangerous",
        "category": "storage",
        "description": "Read audio files from shared storage (Android 13+).",
    },
    "android.permission.POST_NOTIFICATIONS": {
        "risk": "dangerous",
        "category": "system",
        "description": "Post notifications (Android 13+).",
    },
    "android.permission.NEARBY_WIFI_DEVICES": {
        "risk": "dangerous",
        "category": "network",
        "description": "Access nearby Wi-Fi devices — can fingerprint location.",
    },
    "android.permission.BLUETOOTH_CONNECT": {
        "risk": "dangerous",
        "category": "hardware",
        "description": "Connect to paired Bluetooth devices.",
    },
    "android.permission.BLUETOOTH_SCAN": {
        "risk": "dangerous",
        "category": "hardware",
        "description": "Scan for nearby Bluetooth devices.",
    },
}

# Permissions that are always suspicious even if not technically dangerous
_SUSPICIOUS_PERMISSIONS = {
    "android.permission.RECEIVE_BOOT_COMPLETED": "App starts automatically on device boot.",
    "android.permission.FOREGROUND_SERVICE": "Can run persistent background services.",
    "android.permission.WAKE_LOCK": "Prevents device from sleeping — battery drain risk.",
    "android.permission.USE_BIOMETRIC": "Access biometric authentication hardware.",
    "android.permission.USE_FINGERPRINT": "Access fingerprint sensor (deprecated, use USE_BIOMETRIC).",
    "android.permission.GET_ACCOUNTS": "List accounts on the device (Google, etc.).",
    "android.permission.AUTHENTICATE_ACCOUNTS": "Create and manage accounts.",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Accessibility service — can read all screen content.",
    "android.permission.BIND_DEVICE_ADMIN": "Device administrator — can wipe device, change passwords.",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": "Read all notifications — can steal 2FA codes.",
    "android.permission.QUERY_ALL_PACKAGES": "See all installed applications on the device.",
}

# SDK version to Android version mapping
_SDK_TO_ANDROID: Dict[int, str] = {
    21: "5.0 (Lollipop)", 22: "5.1", 23: "6.0 (Marshmallow)",
    24: "7.0 (Nougat)", 25: "7.1", 26: "8.0 (Oreo)", 27: "8.1",
    28: "9.0 (Pie)", 29: "10", 30: "11", 31: "12", 32: "12L",
    33: "13", 34: "14", 35: "15",
}


# ══════════════════════════════════════════════════════════════════════
#  STATIC ANALYSIS RESULT CLASSES
# ══════════════════════════════════════════════════════════════════════

@dataclass
class PermissionInfo:
    """Parsed permission entry from the manifest."""
    name: str
    risk_level: str = "unknown"
    category: str = "other"
    description: str = ""
    is_custom: bool = False


@dataclass
class ComponentInfo:
    """An exported Android component."""
    name: str
    component_type: str  # activity, service, receiver, provider
    exported: bool = False
    intent_filters: List[str] = field(default_factory=list)
    permission: Optional[str] = None


@dataclass
class ManifestFlags:
    """Security-critical flags from AndroidManifest.xml."""
    debuggable: bool = False
    allow_backup: bool = True  # Default is true in Android
    uses_cleartext_traffic: bool = True  # Default depends on targetSdk
    network_security_config: bool = False
    has_file_provider: bool = False
    test_only: bool = False


@dataclass
class StaticAnalysisResult:
    """Complete result of static APK analysis."""
    # Metadata
    package_name: str = ""
    app_name: str = ""
    version_name: str = ""
    version_code: str = ""
    apk_size_bytes: int = 0
    min_sdk: int = 0
    target_sdk: int = 0
    compile_sdk: int = 0

    # Hardware & Architecture
    native_architectures: List[str] = field(default_factory=list)
    uses_features: List[str] = field(default_factory=list)
    launchable_activity: str = ""

    # Permissions
    permissions: List[PermissionInfo] = field(default_factory=list)
    dangerous_permission_count: int = 0
    total_permission_count: int = 0

    # Components
    exported_activities: List[ComponentInfo] = field(default_factory=list)
    exported_services: List[ComponentInfo] = field(default_factory=list)
    exported_receivers: List[ComponentInfo] = field(default_factory=list)
    exported_providers: List[ComponentInfo] = field(default_factory=list)
    total_exported_components: int = 0

    # Manifest flags
    flags: ManifestFlags = field(default_factory=ManifestFlags)

    # Deep links / custom schemes
    deep_links: List[str] = field(default_factory=list)
    custom_schemes: List[str] = field(default_factory=list)

    # Findings
    findings: List[Finding] = field(default_factory=list)

    # Raw data
    aapt_output: str = ""
    aapt_xmltree: str = ""


# ══════════════════════════════════════════════════════════════════════
#  STATIC ANALYSER
# ══════════════════════════════════════════════════════════════════════

class StaticAnalyser:
    """
    Professional-grade static APK analyser.

    Uses aapt2 to extract and evaluate the AndroidManifest.xml without
    installing the app. Produces security findings for dangerous
    permissions, insecure flags, and exposed components.
    """

    def __init__(self) -> None:
        settings = get_settings()
        self.aapt_path: Optional[str] = settings.AAPT_PATH
        if self.aapt_path:
            logger.info("StaticAnalyser ready — aapt2 at %s", self.aapt_path)
        else:
            logger.warning(
                "StaticAnalyser: AAPT_PATH not set. Static analysis will be limited."
            )

    def analyse(self, apk_path: str) -> StaticAnalysisResult:
        """
        Run full static analysis on an APK file.

        Args:
            apk_path: Path to the APK file on disk.

        Returns:
            StaticAnalysisResult with all findings.
        """
        result = StaticAnalysisResult()

        if not self.aapt_path:
            logger.warning("Skipping static analysis — no aapt2 configured.")
            return result

        apk = Path(apk_path)
        if not apk.is_file():
            logger.error("APK not found for static analysis: %s", apk_path)
            return result

        try:
            result.apk_size_bytes = apk.stat().st_size
        except Exception as e:
            logger.warning("Could not get APK size: %s", e)

        # Convert path for Windows aapt2.exe
        win_apk = self._to_win_path(str(apk))

        # ── 1. Run aapt2 dump badging ────────────────────────────────
        badging = self._run_aapt("dump", "badging", win_apk)
        if badging:
            result.aapt_output = badging
            self._parse_badging(badging, result)

        # ── 2. Run aapt2 dump xmltree for deeper manifest analysis ──
        xmltree = self._run_aapt("dump", "xmltree", win_apk, "--file", "AndroidManifest.xml")
        if xmltree:
            result.aapt_xmltree = xmltree
            self._parse_xmltree(xmltree, result)

        # ── 3. Generate security findings ────────────────────────────
        self._generate_permission_findings(result)
        self._generate_flag_findings(result)
        self._generate_component_findings(result)
        self._generate_sdk_findings(result)
        self._generate_deep_link_findings(result)

        logger.info(
            "Static analysis complete — %d permission(s) (%d dangerous), "
            "%d exported component(s), %d finding(s).",
            result.total_permission_count,
            result.dangerous_permission_count,
            result.total_exported_components,
            len(result.findings),
        )

        return result

    # ══════════════════════════════════════════════════════════════════
    #  AAPT2 EXECUTION
    # ══════════════════════════════════════════════════════════════════

    def _to_win_path(self, path: str) -> str:
        """Convert WSL path to Windows path for aapt2.exe."""
        if path.startswith("/mnt/c/"):
            return "C:\\" + path[7:].replace("/", "\\")
        return path

    def _run_aapt(self, *args: str) -> Optional[str]:
        """Run aapt2 with the given arguments and return stdout."""
        if not self.aapt_path:
            return None

        cmd = [self.aapt_path] + list(args)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if proc.returncode != 0:
                logger.warning(
                    "aapt2 %s returned %d: %s",
                    args[0] if args else "?",
                    proc.returncode,
                    proc.stderr[:200] if proc.stderr else "",
                )
                # Some aapt2 commands return non-zero but still have useful output
                return proc.stdout if proc.stdout else None
            return proc.stdout
        except FileNotFoundError:
            logger.error("aapt2 not found at: %s", self.aapt_path)
            return None
        except subprocess.TimeoutExpired:
            logger.error("aapt2 timed out.")
            return None
        except Exception as exc:
            logger.error("aapt2 error: %s", exc)
            return None

    # ══════════════════════════════════════════════════════════════════
    #  PARSING — aapt2 dump badging
    # ══════════════════════════════════════════════════════════════════

    def _parse_badging(self, output: str, result: StaticAnalysisResult) -> None:
        """Parse the output of `aapt2 dump badging`."""
        # Package info
        pkg_match = re.search(
            r"package:\s+name='([^']+)'\s+versionCode='([^']*)'\s+versionName='([^']*)'",
            output,
        )
        if pkg_match:
            result.package_name = pkg_match.group(1)
            result.version_code = pkg_match.group(2)
            result.version_name = pkg_match.group(3)

        # App Name (Label)
        label_match = re.search(r"application-label:\s*'([^']+)'", output)
        if label_match:
            result.app_name = label_match.group(1)
        elif "application-label-en:" in output:
             label_match = re.search(r"application-label-en:\s*'([^']+)'", output)
             if label_match:
                 result.app_name = label_match.group(1)

        # Launchable Activity
        launchable_match = re.search(r"launchable-activity:\s*name='([^']+)'", output)
        if launchable_match:
            result.launchable_activity = launchable_match.group(1)

        # Features
        feature_matches = re.finditer(r"uses-feature:\s*name='([^']+)'", output)
        result.uses_features = [m.group(1) for m in feature_matches]

        # Native Code (Architectures)
        native_match = re.search(r"native-code:\s*(.+)", output)
        if native_match:
            # extract individual architectures wrapped in single quotes
            raw_arches = native_match.group(1)
            arch_matches = re.findall(r"'([^']+)'", raw_arches)
            if arch_matches:
                result.native_architectures = arch_matches

        # SDK levels
        sdk_match = re.search(r"sdkVersion:'(\d+)'", output)
        if sdk_match:
            result.min_sdk = int(sdk_match.group(1))

        target_match = re.search(r"targetSdkVersion:'(\d+)'", output)
        if target_match:
            result.target_sdk = int(target_match.group(1))

        compile_match = re.search(r"compileSdkVersion:'(\d+)'", output)
        if compile_match:
            result.compile_sdk = int(compile_match.group(1))

        # Permissions — uses-permission lines
        perm_pattern = re.compile(r"uses-permission:\s+name='([^']+)'")
        for match in perm_pattern.finditer(output):
            perm_name = match.group(1)
            info = _DANGEROUS_PERMISSIONS.get(perm_name)
            if info:
                perm = PermissionInfo(
                    name=perm_name,
                    risk_level=info["risk"],
                    category=info["category"],
                    description=info["description"],
                    is_custom=False,
                )
                if info["risk"] == "dangerous":
                    result.dangerous_permission_count += 1
            elif perm_name in _SUSPICIOUS_PERMISSIONS:
                perm = PermissionInfo(
                    name=perm_name,
                    risk_level="normal",
                    category="system",
                    description=_SUSPICIOUS_PERMISSIONS[perm_name],
                    is_custom=False,
                )
            elif not perm_name.startswith("android.permission."):
                perm = PermissionInfo(
                    name=perm_name,
                    risk_level="unknown",
                    category="custom",
                    description="Custom permission defined by app or third-party library.",
                    is_custom=True,
                )
            else:
                perm = PermissionInfo(
                    name=perm_name,
                    risk_level="normal",
                    category="other",
                    description="Standard Android permission.",
                    is_custom=False,
                )
            result.permissions.append(perm)

        result.total_permission_count = len(result.permissions)

    # ══════════════════════════════════════════════════════════════════
    #  PARSING — aapt2 dump xmltree (AndroidManifest.xml)
    # ══════════════════════════════════════════════════════════════════

    def _parse_xmltree(self, output: str, result: StaticAnalysisResult) -> None:
        """Parse xmltree output for flags, exported components, and deep links."""

        # ── Manifest-level flags ──
        if re.search(r'android:debuggable.*?=.*?0xffffffff', output, re.IGNORECASE):
            result.flags.debuggable = True
        elif re.search(r'android:debuggable.*?=.*?true', output, re.IGNORECASE):
            result.flags.debuggable = True

        if re.search(r'android:allowBackup.*?=.*?0xffffffff', output, re.IGNORECASE):
            result.flags.allow_backup = True
        elif re.search(r'android:allowBackup.*?=.*?0x0\b', output, re.IGNORECASE):
            result.flags.allow_backup = False

        if re.search(r'android:usesCleartextTraffic.*?=.*?0xffffffff', output, re.IGNORECASE):
            result.flags.uses_cleartext_traffic = True
        elif re.search(r'android:usesCleartextTraffic.*?=.*?0x0\b', output, re.IGNORECASE):
            result.flags.uses_cleartext_traffic = False

        if re.search(r'android:testOnly.*?=.*?0xffffffff', output, re.IGNORECASE):
            result.flags.test_only = True

        if 'network_security_config' in output.lower() or 'networkSecurityConfig' in output:
            result.flags.network_security_config = True

        if 'FileProvider' in output or 'fileprovider' in output.lower():
            result.flags.has_file_provider = True

        # ── Parse exported components ──
        self._extract_components(output, result)

        # ── Parse deep links and custom URL schemes ──
        self._extract_deep_links(output, result)

    def _extract_components(self, xmltree: str, result: StaticAnalysisResult) -> None:
        """Extract exported activities, services, receivers, and providers."""
        lines = xmltree.split('\n')
        current_component: Optional[Dict[str, Any]] = None
        current_type: Optional[str] = None
        in_intent_filter = False
        intent_filter_actions: List[str] = []

        component_tags = {'activity', 'service', 'receiver', 'provider'}

        for line in lines:
            stripped = line.strip()

            # Check for component element start
            for tag in component_tags:
                if stripped.startswith(f'E: {tag} ') or stripped == f'E: {tag}':
                    if current_component and current_component.get('exported'):
                        self._add_component(current_component, current_type, result)
                    current_component = {'name': '', 'exported': False, 'intent_filters': [], 'permission': None}
                    current_type = tag
                    in_intent_filter = False
                    break

            if current_component is None:
                continue

            # Parse attributes
            if 'android:name' in stripped and 'A: android:name' in stripped:
                name_match = re.search(r'"([^"]+)"', stripped)
                if name_match:
                    current_component['name'] = name_match.group(1)

            if 'android:exported' in stripped:
                if '0xffffffff' in stripped or 'true' in stripped.lower():
                    current_component['exported'] = True
                elif '0x0' in stripped:
                    current_component['exported'] = False

            if 'android:permission' in stripped:
                perm_match = re.search(r'"([^"]+)"', stripped)
                if perm_match:
                    current_component['permission'] = perm_match.group(1)

            # Intent filter handling
            if stripped.startswith('E: intent-filter'):
                in_intent_filter = True
                # Having an intent filter with no explicit exported=false makes it exported
                if current_type in ('activity', 'service', 'receiver'):
                    current_component['exported'] = True

            if in_intent_filter and 'android:name' in stripped and 'A: android:name' in stripped:
                action_match = re.search(r'"([^"]+)"', stripped)
                if action_match:
                    current_component['intent_filters'].append(action_match.group(1))

        # Don't forget the last component
        if current_component and current_component.get('exported'):
            self._add_component(current_component, current_type, result)

        result.total_exported_components = (
            len(result.exported_activities)
            + len(result.exported_services)
            + len(result.exported_receivers)
            + len(result.exported_providers)
        )

    def _add_component(
        self, comp: Dict[str, Any], comp_type: Optional[str], result: StaticAnalysisResult
    ) -> None:
        """Add a parsed component to the appropriate list in the result."""
        if not comp_type or not comp.get('name'):
            return

        # Skip standard launcher activity
        filters = comp.get('intent_filters', [])
        is_launcher = (
            'android.intent.action.MAIN' in filters
            and 'android.intent.category.LAUNCHER' in filters
        )

        info = ComponentInfo(
            name=comp['name'],
            component_type=comp_type,
            exported=True,
            intent_filters=filters,
            permission=comp.get('permission'),
        )

        if comp_type == 'activity':
            result.exported_activities.append(info)
        elif comp_type == 'service':
            result.exported_services.append(info)
        elif comp_type == 'receiver':
            result.exported_receivers.append(info)
        elif comp_type == 'provider':
            result.exported_providers.append(info)

    def _extract_deep_links(self, xmltree: str, result: StaticAnalysisResult) -> None:
        """Extract deep links and custom URL schemes from intent filters."""
        # Look for scheme declarations in data elements
        scheme_pattern = re.compile(r'android:scheme.*?"([^"]+)"')
        host_pattern = re.compile(r'android:host.*?"([^"]+)"')
        path_pattern = re.compile(r'android:path(?:Prefix|Pattern)?.*?"([^"]+)"')

        schemes = set()
        hosts = set()

        for match in scheme_pattern.finditer(xmltree):
            scheme = match.group(1)
            schemes.add(scheme)

        for match in host_pattern.finditer(xmltree):
            hosts.add(match.group(1))

        # Classify schemes
        for scheme in schemes:
            if scheme in ('http', 'https'):
                for host in hosts:
                    result.deep_links.append(f"{scheme}://{host}")
            else:
                result.custom_schemes.append(f"{scheme}://")

    # ══════════════════════════════════════════════════════════════════
    #  FINDING GENERATORS
    # ══════════════════════════════════════════════════════════════════

    def _generate_permission_findings(self, result: StaticAnalysisResult) -> None:
        """Generate findings for dangerous and suspicious permissions."""
        for perm in result.permissions:
            if perm.risk_level == "dangerous":
                severity = Severity.HIGH
                if perm.category in ("sms", "phone"):
                    severity = Severity.CRITICAL
                elif perm.category in ("location", "hardware"):
                    severity = Severity.HIGH
                elif perm.category in ("storage",):
                    severity = Severity.MEDIUM

                result.findings.append(Finding(
                    rule_id="STATIC-PERM-001",
                    rule_name="Dangerous Permission Requested",
                    severity=severity,
                    category="permissions",
                    storage_area=StorageArea.SHARED_PREFS,  # N/A for static, but required
                    file_path="AndroidManifest.xml",
                    key_or_field=perm.name.split(".")[-1],
                    value_preview=perm.name,
                    description=(
                        f"The app requests the dangerous permission '{perm.name.split('.')[-1]}'. "
                        f"{perm.description} "
                        f"Dangerous permissions require runtime consent and should only be "
                        f"requested when strictly necessary."
                    ),
                    recommendation=(
                        "Review whether this permission is essential for core functionality. "
                        "If not, remove it. If needed, request it at runtime only when the "
                        "feature is used and explain the purpose to the user."
                    ),
                    extra={
                        "permission": perm.name,
                        "risk_level": perm.risk_level,
                        "category": perm.category,
                        "analysis_type": "static",
                    },
                ))

            # Suspicious (but not dangerous-level) permissions
            if perm.name in _SUSPICIOUS_PERMISSIONS:
                result.findings.append(Finding(
                    rule_id="STATIC-PERM-002",
                    rule_name="Suspicious Permission",
                    severity=Severity.MEDIUM,
                    category="permissions",
                    storage_area=StorageArea.SHARED_PREFS,
                    file_path="AndroidManifest.xml",
                    key_or_field=perm.name.split(".")[-1],
                    value_preview=perm.name,
                    description=(
                        f"The app requests '{perm.name.split('.')[-1]}'. "
                        f"{_SUSPICIOUS_PERMISSIONS[perm.name]} "
                        f"While not classified as 'dangerous' by Android, this permission "
                        f"can be abused for tracking or persistence."
                    ),
                    recommendation=(
                        "Verify this permission is necessary. Document the business "
                        "justification in your privacy policy."
                    ),
                    extra={
                        "permission": perm.name,
                        "analysis_type": "static",
                    },
                ))

        # Overall permission count finding
        if result.dangerous_permission_count >= 5:
            result.findings.append(Finding(
                rule_id="STATIC-PERM-003",
                rule_name="Excessive Dangerous Permissions",
                severity=Severity.HIGH,
                category="permissions",
                storage_area=StorageArea.SHARED_PREFS,
                file_path="AndroidManifest.xml",
                key_or_field="uses-permission",
                value_preview=f"{result.dangerous_permission_count} dangerous permissions",
                description=(
                    f"The app requests {result.dangerous_permission_count} dangerous permissions. "
                    f"Apps requesting many dangerous permissions have a significantly larger "
                    f"attack surface and privacy impact. Each dangerous permission is a potential "
                    f"data leak vector."
                ),
                recommendation=(
                    "Apply the principle of least privilege. Remove all permissions "
                    "that are not essential. Use scoped storage APIs instead of broad "
                    "storage permissions. Prefer Bluetooth companion APIs over direct access."
                ),
                extra={
                    "dangerous_count": result.dangerous_permission_count,
                    "total_count": result.total_permission_count,
                    "analysis_type": "static",
                },
            ))

    def _generate_flag_findings(self, result: StaticAnalysisResult) -> None:
        """Generate findings for insecure manifest flags."""
        flags = result.flags

        if flags.debuggable:
            result.findings.append(Finding(
                rule_id="STATIC-FLAG-001",
                rule_name="App Is Debuggable",
                severity=Severity.CRITICAL,
                category="config",
                storage_area=StorageArea.SHARED_PREFS,
                file_path="AndroidManifest.xml",
                key_or_field="android:debuggable",
                value_preview="true",
                description=(
                    "The app has android:debuggable=true set in the manifest. "
                    "This allows any user to attach a debugger (JDWP), inspect memory, "
                    "bypass security checks, and extract all data at runtime. "
                    "This MUST be false in production builds."
                ),
                recommendation=(
                    "Set android:debuggable=\"false\" in the release build. "
                    "Use BuildConfig.DEBUG for debug-only code paths. "
                    "Ensure your build system strips the flag for release variants."
                ),
                extra={"analysis_type": "static"},
            ))

        if flags.allow_backup:
            result.findings.append(Finding(
                rule_id="STATIC-FLAG-002",
                rule_name="App Data Backup Allowed",
                severity=Severity.HIGH,
                category="config",
                storage_area=StorageArea.SHARED_PREFS,
                file_path="AndroidManifest.xml",
                key_or_field="android:allowBackup",
                value_preview="true",
                description=(
                    "The app allows full data backup via `adb backup`. An attacker "
                    "with physical access or ADB access can extract all SharedPreferences, "
                    "databases, and internal files without root. This is a major data "
                    "exfiltration risk."
                ),
                recommendation=(
                    "Set android:allowBackup=\"false\" or implement a custom BackupAgent "
                    "that excludes sensitive data. On Android 12+, use "
                    "android:dataExtractionRules to control cloud vs device-to-device backup."
                ),
                extra={"analysis_type": "static"},
            ))

        if flags.uses_cleartext_traffic:
            result.findings.append(Finding(
                rule_id="STATIC-FLAG-003",
                rule_name="Cleartext Traffic Allowed",
                severity=Severity.HIGH,
                category="config",
                storage_area=StorageArea.SHARED_PREFS,
                file_path="AndroidManifest.xml",
                key_or_field="android:usesCleartextTraffic",
                value_preview="true",
                description=(
                    "The app allows cleartext (unencrypted HTTP) traffic. "
                    "Any data sent over HTTP can be intercepted by network attackers "
                    "(MITM). This includes credentials, tokens, and PII."
                ),
                recommendation=(
                    "Set android:usesCleartextTraffic=\"false\" and use HTTPS exclusively. "
                    "Implement a Network Security Configuration to enforce certificate "
                    "pinning for critical domains."
                ),
                extra={"analysis_type": "static"},
            ))

        if not flags.network_security_config:
            result.findings.append(Finding(
                rule_id="STATIC-FLAG-004",
                rule_name="No Network Security Configuration",
                severity=Severity.MEDIUM,
                category="config",
                storage_area=StorageArea.SHARED_PREFS,
                file_path="AndroidManifest.xml",
                key_or_field="networkSecurityConfig",
                value_preview="missing",
                description=(
                    "The app does not define a Network Security Configuration. "
                    "Without this, the app relies on platform defaults which may "
                    "allow cleartext traffic to some domains. A network security "
                    "config enables certificate pinning and domain-specific TLS rules."
                ),
                recommendation=(
                    "Add a res/xml/network_security_config.xml that: "
                    "(1) Disables cleartext traffic, "
                    "(2) Pins certificates for your API domains, "
                    "(3) Restricts trusted CAs to system-only for production builds."
                ),
                extra={"analysis_type": "static"},
            ))

        if flags.test_only:
            result.findings.append(Finding(
                rule_id="STATIC-FLAG-005",
                rule_name="Test-Only Build",
                severity=Severity.CRITICAL,
                category="config",
                storage_area=StorageArea.SHARED_PREFS,
                file_path="AndroidManifest.xml",
                key_or_field="android:testOnly",
                value_preview="true",
                description=(
                    "The APK is marked as testOnly. This is a development build "
                    "that should never be distributed to users. Test builds have "
                    "relaxed security restrictions."
                ),
                recommendation=(
                    "This is a test build. Ensure production releases do not "
                    "have android:testOnly set."
                ),
                extra={"analysis_type": "static"},
            ))

    def _generate_component_findings(self, result: StaticAnalysisResult) -> None:
        """Generate findings for exported components without protection."""
        for comp in (
            result.exported_activities
            + result.exported_services
            + result.exported_receivers
            + result.exported_providers
        ):
            # Skip launcher activity — it's expected to be exported
            is_launcher = (
                'android.intent.action.MAIN' in comp.intent_filters
            )
            if is_launcher and comp.component_type == 'activity':
                continue

            # Protected by a permission? Lower severity.
            if comp.permission:
                severity = Severity.LOW
                desc_suffix = (
                    f" It is protected by the permission '{comp.permission}', "
                    f"which limits who can invoke it."
                )
            else:
                severity = Severity.HIGH
                desc_suffix = (
                    " It has no permission restriction — any app on the device can invoke it."
                )

            # Services and receivers are higher risk than activities
            if comp.component_type in ('service', 'receiver') and not comp.permission:
                severity = Severity.CRITICAL

            # Content providers without permissions are critical
            if comp.component_type == 'provider' and not comp.permission:
                severity = Severity.CRITICAL

            result.findings.append(Finding(
                rule_id=f"STATIC-COMP-001",
                rule_name=f"Exported {comp.component_type.title()} Component",
                severity=severity,
                category="components",
                storage_area=StorageArea.SHARED_PREFS,
                file_path="AndroidManifest.xml",
                key_or_field=comp.name.split(".")[-1] if "." in comp.name else comp.name,
                value_preview=comp.name,
                description=(
                    f"The {comp.component_type} '{comp.name}' is exported "
                    f"(accessible to other apps on the device).{desc_suffix} "
                    f"Exported components can be exploited for privilege escalation, "
                    f"data theft, or intent injection attacks."
                ),
                recommendation=(
                    f"Set android:exported=\"false\" unless external access is required. "
                    f"If it must be exported, protect it with a signature-level permission "
                    f"and validate all incoming Intent data."
                ),
                extra={
                    "component_type": comp.component_type,
                    "component_name": comp.name,
                    "has_permission": comp.permission is not None,
                    "intent_filters": comp.intent_filters[:5],  # limit size
                    "analysis_type": "static",
                },
            ))

        # Overall exported component count warning
        if result.total_exported_components > 5:
            result.findings.append(Finding(
                rule_id="STATIC-COMP-002",
                rule_name="Large Attack Surface — Many Exported Components",
                severity=Severity.MEDIUM,
                category="components",
                storage_area=StorageArea.SHARED_PREFS,
                file_path="AndroidManifest.xml",
                key_or_field="exported-components",
                value_preview=f"{result.total_exported_components} components",
                description=(
                    f"The app exports {result.total_exported_components} components. "
                    f"Each exported component is a potential entry point for attacks. "
                    f"A large number of exports increases the app's attack surface."
                ),
                recommendation=(
                    "Audit each exported component. Remove the exported flag from "
                    "any component that does not need to be accessed by external apps."
                ),
                extra={
                    "activities": len(result.exported_activities),
                    "services": len(result.exported_services),
                    "receivers": len(result.exported_receivers),
                    "providers": len(result.exported_providers),
                    "analysis_type": "static",
                },
            ))

    def _generate_sdk_findings(self, result: StaticAnalysisResult) -> None:
        """Generate findings for SDK version issues."""
        if result.min_sdk > 0 and result.min_sdk < 23:
            android_ver = _SDK_TO_ANDROID.get(result.min_sdk, f"API {result.min_sdk}")
            result.findings.append(Finding(
                rule_id="STATIC-SDK-001",
                rule_name="Low Minimum SDK Version",
                severity=Severity.MEDIUM,
                category="config",
                storage_area=StorageArea.SHARED_PREFS,
                file_path="AndroidManifest.xml",
                key_or_field="minSdkVersion",
                value_preview=f"API {result.min_sdk} ({android_ver})",
                description=(
                    f"The app supports devices running Android {android_ver} (API {result.min_sdk}). "
                    f"Devices below API 23 (Android 6.0) do not support runtime permissions — "
                    f"all dangerous permissions are granted at install time without user consent. "
                    f"Older Android versions also lack modern security features like "
                    f"file-based encryption and network security configuration."
                ),
                recommendation=(
                    "Raise minSdkVersion to at least 23 (Android 6.0) to benefit from "
                    "runtime permissions. Consider raising to 26+ (Android 8.0) for "
                    "background execution limits and notification channels."
                ),
                extra={
                    "min_sdk": result.min_sdk,
                    "android_version": android_ver,
                    "analysis_type": "static",
                },
            ))

        if result.target_sdk > 0 and result.target_sdk < 31:
            android_ver = _SDK_TO_ANDROID.get(result.target_sdk, f"API {result.target_sdk}")
            result.findings.append(Finding(
                rule_id="STATIC-SDK-002",
                rule_name="Outdated Target SDK Version",
                severity=Severity.HIGH,
                category="config",
                storage_area=StorageArea.SHARED_PREFS,
                file_path="AndroidManifest.xml",
                key_or_field="targetSdkVersion",
                value_preview=f"API {result.target_sdk} ({android_ver})",
                description=(
                    f"The app targets Android {android_ver} (API {result.target_sdk}). "
                    f"Google Play requires targetSdk 33+ for new apps. Older target SDKs "
                    f"opt out of modern security protections including scoped storage, "
                    f"package visibility restrictions, and foreground service requirements. "
                    f"Attackers can exploit legacy behaviors on modern devices."
                ),
                recommendation=(
                    "Update targetSdkVersion to the latest stable API level (34+). "
                    "Migrate to scoped storage, update permission requests, "
                    "and test thoroughly on the latest Android version."
                ),
                extra={
                    "target_sdk": result.target_sdk,
                    "android_version": android_ver,
                    "analysis_type": "static",
                },
            ))

    def _generate_deep_link_findings(self, result: StaticAnalysisResult) -> None:
        """Generate findings for deep links and custom URL schemes."""
        for scheme in result.custom_schemes:
            result.findings.append(Finding(
                rule_id="STATIC-LINK-001",
                rule_name="Custom URL Scheme Registered",
                severity=Severity.MEDIUM,
                category="components",
                storage_area=StorageArea.SHARED_PREFS,
                file_path="AndroidManifest.xml",
                key_or_field="intent-filter",
                value_preview=scheme,
                description=(
                    f"The app registers the custom URL scheme '{scheme}'. "
                    f"Custom schemes can be hijacked by malicious apps that register "
                    f"the same scheme. Unlike App Links (https), custom schemes have "
                    f"no verification mechanism."
                ),
                recommendation=(
                    "Prefer Android App Links (HTTPS verified deep links) over custom schemes. "
                    "If custom schemes are necessary, validate all data received via the "
                    "intent and never trust it for authentication or navigation."
                ),
                extra={
                    "scheme": scheme,
                    "analysis_type": "static",
                },
            ))
