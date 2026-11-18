import re
import zipfile
import hashlib
import binascii
import logging
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional, Union
import xml.etree.ElementTree as ET

# Silence verbose Androguard stderr logging to prevent pipe buffer saturation deadlocks
logging.getLogger("androguard").setLevel(logging.ERROR)
try:
    from loguru import logger as loguru_logger
    loguru_logger.disable("androguard")
except Exception:
    pass

from backend.app.core.models import (
    ApkMetadata, PermissionInfo, ComponentInfo, CertificateInfo
)
from backend.app.analyzers.manifest_analyzer import DANGEROUS_PERMISSIONS_DB

_PRINTABLE_PATTERN = re.compile(rb"[\x20-\x7e]{4,}")

def _extract_raw_strings(data: bytes, min_len: int = 4, max_strings: int = 15000) -> List[str]:
    """High-speed native C-regex extraction of printable ASCII strings from arbitrary binary data."""
    if not data:
        return []
    matches = _PRINTABLE_PATTERN.findall(data)
    result = []
    for m in matches[:max_strings]:
        try:
            result.append(m.decode("ascii", errors="ignore"))
        except Exception:
            pass
    return result

def _clean_str(val: Any) -> str:
    """Clean string values and handle byte literals if present."""
    if val is None:
        return ""
    if isinstance(val, bytes):
        val = val.decode("utf-8", errors="ignore")
    val_str = str(val).strip()
    if val_str.startswith("b'") and val_str.endswith("'"):
        val_str = val_str[2:-1]
    return val_str

def _parse_manifest_element_tree(root: ET.Element, metadata: ApkMetadata):
    """Deep structural inspection of AndroidManifest XML element tree."""
    ns_android = "{http://schemas.android.com/apk/res/android}"

    # Package and versioning attributes
    pkg = root.attrib.get("package") or root.attrib.get(f"{ns_android}package")
    if pkg:
        metadata.package_name = _clean_str(pkg)

    v_code = root.attrib.get(f"{ns_android}versionCode") or root.attrib.get("versionCode")
    if v_code:
        metadata.version_code = _clean_str(v_code)

    v_name = root.attrib.get(f"{ns_android}versionName") or root.attrib.get("versionName")
    if v_name:
        metadata.version_name = _clean_str(v_name)

    # Uses-sdk
    for sdk_elem in root.findall("uses-sdk"):
        min_sdk = sdk_elem.attrib.get(f"{ns_android}minSdkVersion") or sdk_elem.attrib.get("minSdkVersion")
        if min_sdk:
            metadata.min_sdk_version = _clean_str(min_sdk)
        tgt_sdk = sdk_elem.attrib.get(f"{ns_android}targetSdkVersion") or sdk_elem.attrib.get("targetSdkVersion")
        if tgt_sdk:
            metadata.target_sdk_version = _clean_str(tgt_sdk)
        max_sdk = sdk_elem.attrib.get(f"{ns_android}maxSdkVersion") or sdk_elem.attrib.get("maxSdkVersion")
        if max_sdk:
            metadata.max_sdk_version = _clean_str(max_sdk)

    # Uses-permission
    for perm_elem in root.findall("uses-permission"):
        pname = perm_elem.attrib.get(f"{ns_android}name") or perm_elem.attrib.get("name")
        if pname:
            pname = _clean_str(pname)
            if not any(p.name == pname for p in metadata.permissions):
                is_danger = pname in DANGEROUS_PERMISSIONS_DB
                metadata.permissions.append(PermissionInfo(
                    name=pname,
                    protection_level="dangerous" if is_danger else "normal",
                    description=DANGEROUS_PERMISSIONS_DB.get(pname, "Standard application permission."),
                    is_dangerous=is_danger,
                    is_custom=not pname.startswith("android.permission.")
                ))

    # Application node flags
    app_elem = root.find("application")
    if app_elem is not None:
        label = app_elem.attrib.get(f"{ns_android}label") or app_elem.attrib.get("label")
        if label and not label.startswith("@"):
            metadata.app_name = _clean_str(label)

        cleartext = app_elem.attrib.get(f"{ns_android}usesCleartextTraffic") or app_elem.attrib.get("usesCleartextTraffic")
        if cleartext is not None:
            metadata.uses_cleartext_traffic = (_clean_str(cleartext).lower() == "true")

        debuggable = app_elem.attrib.get(f"{ns_android}debuggable") or app_elem.attrib.get("debuggable")
        if debuggable is not None:
            metadata.is_debuggable = (_clean_str(debuggable).lower() == "true")

        allow_backup = app_elem.attrib.get(f"{ns_android}allowBackup") or app_elem.attrib.get("allowBackup")
        if allow_backup is not None:
            metadata.allow_backup = (_clean_str(allow_backup).lower() == "true")

        nsc = app_elem.attrib.get(f"{ns_android}networkSecurityConfig") or app_elem.attrib.get("networkSecurityConfig")
        if nsc:
            metadata.network_security_config = _clean_str(nsc)

        # Components: activities, services, receivers, providers
        component_tags = [
            ("activity", "activities"),
            ("activity-alias", "activities"),
            ("service", "services"),
            ("receiver", "receivers"),
            ("provider", "providers")
        ]

        for tag, target_list_attr in component_tags:
            for elem in app_elem.findall(tag):
                raw_cname = elem.attrib.get(f"{ns_android}name") or elem.attrib.get("name") or "UnknownComponent"
                cname = _clean_str(raw_cname)
                if cname.startswith(".") and metadata.package_name:
                    cname = f"{metadata.package_name}{cname}"

                perm = elem.attrib.get(f"{ns_android}permission") or elem.attrib.get("permission")

                # Parse intent filters
                intent_filters = []
                has_launcher = False
                for if_elem in elem.findall("intent-filter"):
                    actions = [_clean_str(a.attrib.get(f"{ns_android}name") or a.attrib.get("name")) for a in if_elem.findall("action")]
                    categories = [_clean_str(c.attrib.get(f"{ns_android}name") or c.attrib.get("name")) for c in if_elem.findall("category")]
                    data_items = []
                    for d in if_elem.findall("data"):
                        d_dict = {}
                        for k, v in d.attrib.items():
                            clean_k = k.split("}")[-1]
                            d_dict[clean_k] = _clean_str(v)
                        if d_dict:
                            data_items.append(d_dict)

                    if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in categories:
                        has_launcher = True

                    intent_filters.append({
                        "actions": [a for a in actions if a],
                        "categories": [c for c in categories if c],
                        "data": data_items
                    })

                # Exported logic: explicit exported attribute, or defaults to True if intent filters present
                exp_str = elem.attrib.get(f"{ns_android}exported") or elem.attrib.get("exported")
                if exp_str is not None:
                    is_exported = (_clean_str(exp_str).lower() == "true")
                else:
                    is_exported = (len(intent_filters) > 0)

                comp = ComponentInfo(
                    name=cname,
                    component_type="activity" if "activity" in tag else tag,
                    exported=is_exported,
                    permission=_clean_str(perm) if perm else None,
                    intent_filters=intent_filters
                )

                target_list = getattr(metadata, target_list_attr)
                # Avoid duplicates
                if not any(c.name == comp.name for c in target_list):
                    target_list.append(comp)

                if has_launcher and not metadata.launcher_activity:
                    metadata.launcher_activity = cname

def parse_apk_with_androguard(apk_path: Union[Path, str]) -> Tuple[ApkMetadata, List[Tuple[str, str]], List[str]]:
    """
    Parses APK using Androguard 4.x and defensive fallback parsers.
    Extracts structural manifest metadata, signing certificates, multi-DEX files,
    native libraries, and full strings pool for static forensics.
    Never executes target binary.
    """
    apk_path = Path(apk_path)
    strings_pool: List[Tuple[str, str]] = []
    dex_methods: List[str] = []

    metadata = ApkMetadata(
        app_name=apk_path.stem,
        package_name="unknown.package",
        version_name="1.0",
        version_code="1"
    )

    andro_apk = None
    try:
        from androguard.core.apk import APK
        andro_apk = APK(str(apk_path))
    except Exception:
        andro_apk = None

    if andro_apk and andro_apk.is_valid_APK():
        try:
            metadata.package_name = _clean_str(andro_apk.get_package()) or metadata.package_name
            metadata.app_name = _clean_str(andro_apk.get_app_name()) or metadata.app_name
            metadata.version_name = _clean_str(andro_apk.get_androidversion_name()) or "1.0"
            metadata.version_code = _clean_str(andro_apk.get_androidversion_code()) or "1"
            metadata.min_sdk_version = _clean_str(andro_apk.get_min_sdk_version()) or "N/A"
            metadata.target_sdk_version = _clean_str(andro_apk.get_target_sdk_version()) or "N/A"
            metadata.max_sdk_version = _clean_str(andro_apk.get_max_sdk_version()) or "N/A"
            metadata.launcher_activity = _clean_str(andro_apk.get_main_activity()) or ""
            try:
                debug_val = andro_apk.get_element("application", "debuggable")
                if debug_val is not None:
                    metadata.is_debuggable = (str(debug_val).lower() == "true")
            except Exception:
                pass
        except Exception:
            pass

        # Permissions from Androguard
        try:
            for p in andro_apk.get_permissions() or []:
                pname = _clean_str(p)
                if not any(existing.name == pname for existing in metadata.permissions):
                    is_danger = pname in DANGEROUS_PERMISSIONS_DB
                    metadata.permissions.append(PermissionInfo(
                        name=pname,
                        protection_level="dangerous" if is_danger else "normal",
                        description=DANGEROUS_PERMISSIONS_DB.get(pname, "Standard Android application permission."),
                        is_dangerous=is_danger,
                        is_custom=not pname.startswith("android.permission.")
                    ))
        except Exception:
            pass

        # Parse deep XML manifest tree via Androguard get_android_manifest_xml
        try:
            xml_manifest = andro_apk.get_android_manifest_xml()
            if xml_manifest is not None:
                _parse_manifest_element_tree(xml_manifest, metadata)
        except Exception:
            pass

        # Certificates and Signing Schemes
        try:
            v1 = False
            v2 = False
            v3 = False
            try:
                v1 = bool(andro_apk.is_signed_v1())
            except Exception:
                pass
            try:
                v2 = bool(andro_apk.is_signed_v2())
            except Exception:
                pass
            try:
                v3 = bool(andro_apk.is_signed_v3())
            except Exception:
                pass

            certs = []
            try:
                certs = andro_apk.get_certificates() or []
            except Exception:
                pass

            for cert in certs:
                try:
                    der_bytes = cert.dump() if hasattr(cert, "dump") else b""
                    sha256_fp = hashlib.sha256(der_bytes).hexdigest() if der_bytes else ""
                    sha1_fp = hashlib.sha1(der_bytes).hexdigest() if der_bytes else ""
                    md5_fp = hashlib.md5(der_bytes).hexdigest() if der_bytes else ""

                    issuer_dict = {str(k): str(v) for k, v in cert.issuer.native.items()} if hasattr(cert, "issuer") and hasattr(cert.issuer, "native") else {}
                    subject_dict = {str(k): str(v) for k, v in cert.subject.native.items()} if hasattr(cert, "subject") and hasattr(cert.subject, "native") else {}

                    valid_from = str(getattr(cert, "not_valid_before", "")) or None
                    valid_to = str(getattr(cert, "not_valid_after", "")) or None

                    self_signed_raw = getattr(cert, "self_signed", False)
                    is_self_signed = bool(self_signed_raw in (True, "yes", "maybe", 1) or (issuer_dict == subject_dict and bool(issuer_dict)))

                    serial_num = str(hex(getattr(cert, "serial_number", 0))) if hasattr(cert, "serial_number") else None

                    metadata.certificates.append(CertificateInfo(
                        subject=subject_dict,
                        issuer=issuer_dict,
                        serial_number=serial_num,
                        valid_from=valid_from,
                        valid_to=valid_to,
                        sha1_fingerprint=sha1_fp,
                        sha256_fingerprint=sha256_fp,
                        md5_fingerprint=md5_fp,
                        signature_algorithm=str(getattr(cert, "signature_algo", "")) or None,
                        is_self_signed=is_self_signed,
                        v1_signed=v1,
                        v2_signed=v2,
                        v3_signed=v3
                    ))
                except Exception:
                    pass
        except Exception:
            pass

    # Inspect APK Zip Entries (Inventory native libs, multi-dex, embedded files, assets)
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            # Fallback manifest parsing if package name still unresolved
            if (metadata.package_name == "unknown.package" or len(metadata.activities) == 0) and "AndroidManifest.xml" in zf.namelist():
                try:
                    axml_bytes = zf.read("AndroidManifest.xml")
                    root = None
                    try:
                        from androguard.core.axml import AXMLPrinter
                        printer = AXMLPrinter(axml_bytes)
                        xml_content = printer.get_xml()
                        if xml_content:
                            root = ET.fromstring(xml_content)
                    except Exception:
                        pass
                    # If binary AXML decoding failed, try parsing directly as raw XML (e.g. synthetic test fixtures)
                    if root is None:
                        try:
                            root = ET.fromstring(axml_bytes.decode("utf-8", errors="ignore"))
                        except Exception:
                            pass
                    if root is not None:
                        _parse_manifest_element_tree(root, metadata)
                except Exception:
                    pass

            for info in zf.infolist():
                name = info.filename
                # Native libraries categorized by ABI
                if name.startswith("lib/") and name.endswith(".so"):
                    metadata.native_libraries.append(name)
                # Multi-DEX files
                elif name.endswith(".dex"):
                    metadata.dex_files.append({
                        "name": name,
                        "size": info.file_size,
                        "compressed_size": info.compress_size
                    })
                    try:
                        dex_bytes = zf.read(name)
                        extracted_strs, extracted_methods = _parse_dex_bytes(dex_bytes, name)
                        for s in extracted_strs:
                            strings_pool.append((name, s))
                        dex_methods.extend(extracted_methods)
                    except Exception:
                        pass
                # Embedded archives and executables
                elif name.lower().endswith((".jar", ".apk", ".zip", ".tar", ".gz")):
                    metadata.embedded_archives.append(name)
                elif name.lower().endswith((".elf", ".bin", ".sh", ".exe", ".so")):
                    metadata.embedded_executables.append(name)
                # Embedded config/assets strings
                elif name.startswith("assets/") or name.endswith((".json", ".xml", ".properties", ".cfg", ".ini", ".env", ".conf", ".txt")):
                    try:
                        content = zf.read(name)
                        for raw_s in _extract_raw_strings(content):
                            strings_pool.append((name, raw_s))
                    except Exception:
                        pass
    except Exception:
        pass

    return metadata, strings_pool, dex_methods

def _parse_dex_bytes(dex_bytes: bytes, dex_filename: str) -> Tuple[List[str], List[str]]:
    """
    Parses strings and method identifiers from DEX bytecode bytes.
    Uses Androguard DEX with bounds checking and binary fallback.
    """
    strings: List[str] = []
    methods: List[str] = []

    try:
        from androguard.core.dex import DEX
        d = DEX(dex_bytes)
        count = 0
        for s in d.get_strings():
            if s and isinstance(s, str):
                strings.append(s)
                count += 1
                if count >= 25000:
                    break
        m_count = 0
        for m in d.get_methods():
            try:
                cname = m.get_class_name() or ""
                mname = m.get_name() or ""
                desc = m.get_descriptor() or ""
                methods.append(f"{cname}->{mname}{desc}")
                m_count += 1
                if m_count >= 25000:
                    break
            except Exception:
                continue
        if strings:
            return strings, methods
    except Exception:
        pass

    # High-performance fallback binary extractor for DEX files
    strings = _extract_raw_strings(dex_bytes)
    return strings, methods
