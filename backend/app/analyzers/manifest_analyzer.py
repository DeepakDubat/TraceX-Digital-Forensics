import re
from typing import List, Dict, Any, Tuple
from backend.app.core.models import ApkMetadata, StaticFinding, PermissionInfo, ComponentInfo

DANGEROUS_PERMISSIONS_DB = {
    "android.permission.READ_SMS": "Allows application to read SMS messages, frequently abused for intercepting 2FA OTP codes and banking verification.",
    "android.permission.RECEIVE_SMS": "Allows monitoring and intercepting incoming SMS messages before user visibility.",
    "android.permission.SEND_SMS": "Allows sending SMS messages without user interaction, commonly abused for premium-rate SMS fraud.",
    "android.permission.READ_CONTACTS": "Allows access to the user's address book, leveraged by spyware for contact exfiltration.",
    "android.permission.WRITE_CONTACTS": "Allows modifying address book entries.",
    "android.permission.ACCESS_FINE_LOCATION": "Allows high-precision GPS tracking of the victim device.",
    "android.permission.ACCESS_COARSE_LOCATION": "Allows network-based location tracking.",
    "android.permission.RECORD_AUDIO": "Allows continuous audio eavesdropping and ambient microphone recording.",
    "android.permission.CAMERA": "Allows capturing photos and videos without explicit real-time preview.",
    "android.permission.READ_CALL_LOG": "Allows exfiltrating complete incoming/outgoing call history.",
    "android.permission.WRITE_CALL_LOG": "Allows tampering with or deleting forensic call records.",
    "android.permission.PROCESS_OUTGOING_CALLS": "Allows redirecting or eavesdropping on phone calls.",
    "android.permission.READ_PHONE_STATE": "Allows reading IMSI, IMEI, phone number, and network state.",
    "android.permission.SYSTEM_ALERT_WINDOW": "Allows displaying overlay windows over other applications, key component for Android banking trojan overlays and tapjacking.",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Allows automating clicks, reading onscreen content, and intercepting keystrokes. Heavily abused by modern Android malware (e.g. FluBot, SharkBot).",
    "android.permission.BIND_DEVICE_ADMIN": "Enables device administration privileges, preventing straightforward uninstallation and enabling remote wipe/lock.",
    "android.permission.RECEIVE_BOOT_COMPLETED": "Allows automatic execution immediately upon device startup, establishing persistent background execution.",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Allows triggering installation of secondary APK packages (dropper / payload staging capability).",
    "android.permission.INTERNET": "Allows opening network sockets to communicate with external infrastructure.",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Allows broad file access, tampering with shared storage files.",
    "android.permission.READ_EXTERNAL_STORAGE": "Allows accessing user documents, photos, and files on external storage.",
    "android.permission.WAKE_LOCK": "Prevents device from sleeping, ensuring prolonged background beaconing.",
    "android.permission.QUERY_ALL_PACKAGES": "Allows inventorying all installed apps, frequently used by banking trojans to detect target banking applications."
}

def analyze_manifest(metadata: ApkMetadata) -> Tuple[List[StaticFinding], Dict[str, Any]]:
    """
    Inspects manifest permissions, components, and security flags.
    Flags suspicious permission combinations, exported services/receivers,
    cleartext traffic, and debuggable settings.
    """
    findings: List[StaticFinding] = []
    summary_flags = {}
    
    perm_names = {p.name for p in metadata.permissions}
    
    # 1. Cleartext Traffic
    if metadata.uses_cleartext_traffic is True:
        findings.append(StaticFinding(
            id="MAN-001",
            category="manifest",
            severity="Medium",
            confidence="Confirmed",
            title="Cleartext HTTP Traffic Allowed",
            description="The manifest explicitly sets 'android:usesCleartextTraffic=true'.",
            source_file="AndroidManifest.xml",
            code_reference="<application android:usesCleartextTraffic=\"true\">",
            evidence_snippet="usesCleartextTraffic=true",
            explanation="Allows unencrypted HTTP communication across network paths, exposing network traffic to interception, manipulation, or plain-text C2 inspection.",
            remediation_advice="Enforce TLS (HTTPS) across all network communications and disable cleartext traffic."
        ))

    # 2. Debuggable Setting
    if metadata.is_debuggable:
        findings.append(StaticFinding(
            id="MAN-002",
            category="manifest",
            severity="High",
            confidence="Confirmed",
            title="Application is Marked as Debuggable",
            description="The manifest declares 'android:debuggable=true' in production artifact.",
            source_file="AndroidManifest.xml",
            code_reference="<application android:debuggable=\"true\">",
            evidence_snippet="android:debuggable=true",
            explanation="Enables JDWP debugger attachment, allowing arbitrary memory inspection and code injection. High risk in production software.",
            remediation_advice="Set android:debuggable to false in production builds."
        ))

    # 3. Dangerous Permission Combinations
    
    # Combination A: SMS Interception + Internet (Banking Trojan / Spyware classic)
    sms_perms = {"android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS"}
    matched_sms = perm_names.intersection(sms_perms)
    if matched_sms and "android.permission.INTERNET" in perm_names:
        findings.append(StaticFinding(
            id="MAN-COMB-01",
            category="manifest",
            severity="High",
            confidence="High",
            title="Suspicious Permission Combination: SMS Access + Internet",
            description=f"Application requests SMS capabilities ({', '.join(matched_sms)}) alongside INTERNET permission.",
            source_file="AndroidManifest.xml",
            explanation="This combination is characteristic of SMS grabbers, banking trojans intercepting 2FA OTP tokens, and toll-fraud malware.",
            remediation_advice="Validate whether SMS operations are core to the application purpose and inspect DEX bytecode for SMS transmission endpoints."
        ))
        summary_flags["sms_exfiltration_risk"] = True

    # Combination B: Accessibility Service + Overlay (Banking Trojan / Credential Stealer)
    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in perm_names or any("accessibility" in p.lower() for p in perm_names):
        has_overlay = "android.permission.SYSTEM_ALERT_WINDOW" in perm_names
        findings.append(StaticFinding(
            id="MAN-COMB-02",
            category="manifest",
            severity="Critical" if has_overlay else "High",
            confidence="High",
            title="High-Risk Permission: Accessibility Service" + (" Combined with System Overlay" if has_overlay else ""),
            description="Application requests accessibility service integration" + (" and SYSTEM_ALERT_WINDOW overlay permission." if has_overlay else "."),
            source_file="AndroidManifest.xml",
            explanation="Accessibility abuse is the primary mechanism in contemporary Android malware to bypass Google Play Protect, automate clicks, intercept SMS/keystrokes, and overlay fake banking login screens.",
            remediation_advice="Scrutinize AccessibilityService implementation in DEX bytecode for clickjacking and automated input dispatch."
        ))
        summary_flags["accessibility_abuse_risk"] = True

    # Combination C: Boot Persistence + Background Service + Network
    if "android.permission.RECEIVE_BOOT_COMPLETED" in perm_names and "android.permission.INTERNET" in perm_names:
        findings.append(StaticFinding(
            id="MAN-COMB-03",
            category="manifest",
            severity="Medium",
            confidence="High",
            title="Persistence Mechanism: Boot Completed Receiver with Network Access",
            description="Application requests RECEIVE_BOOT_COMPLETED with INTERNET access.",
            source_file="AndroidManifest.xml",
            explanation="Allows malware to automatically start background services or beacon to C2 immediately when device boots, maintaining persistence across reboots.",
            remediation_advice="Trace the BroadcastReceiver that handles 'android.intent.action.BOOT_COMPLETED'."
        ))
        summary_flags["boot_persistence"] = True

    # Combination D: Device Administration
    if "android.permission.BIND_DEVICE_ADMIN" in perm_names:
        findings.append(StaticFinding(
            id="MAN-COMB-04",
            category="manifest",
            severity="High",
            confidence="High",
            title="Device Administration Privileges Requested",
            description="Application declares BIND_DEVICE_ADMIN permission.",
            source_file="AndroidManifest.xml",
            explanation="Device admin privileges allow an app to lock device screens, change passcodes, or prevent uninstallation. Often leveraged by Android ransomware and persistent trojans.",
            remediation_advice="Inspect DeviceAdminReceiver declarations to determine triggered policies."
        ))

    # Combination E: Dropper / Stager Indicator
    if "android.permission.REQUEST_INSTALL_PACKAGES" in perm_names:
        findings.append(StaticFinding(
            id="MAN-COMB-05",
            category="manifest",
            severity="High",
            confidence="Medium",
            title="Payload Staging Capability: REQUEST_INSTALL_PACKAGES",
            description="Application requests permission to install secondary APK packages without user navigating to system settings.",
            source_file="AndroidManifest.xml",
            explanation="Characteristic of first-stage dropper malware that fetches and prompts installation of encrypted secondary payloads from remote C2.",
            remediation_advice="Inspect dynamic download routines and file provider installations."
        ))

    # 4. Exported Components without Permissions
    exported_services = [s for s in metadata.services if s.exported and not s.permission]
    if exported_services:
        findings.append(StaticFinding(
            id="MAN-EXP-01",
            category="manifest",
            severity="Medium",
            confidence="Confirmed",
            title=f"Exported Services Without Permission Protection ({len(exported_services)})",
            description=f"Declared {len(exported_services)} exported services accessible to any third-party application on the device.",
            source_file="AndroidManifest.xml",
            code_reference=", ".join(s.name for s in exported_services[:3]),
            explanation="Exported services without explicit permissions can be triggered by malicious collocated applications to induce unintended state changes or privilege escalation.",
            remediation_advice="Add 'android:exported=false' or protect with a custom signature permission."
        ))

    exported_receivers = [r for r in metadata.receivers if r.exported and not r.permission]
    if exported_receivers:
        findings.append(StaticFinding(
            id="MAN-EXP-02",
            category="manifest",
            severity="Low",
            confidence="Confirmed",
            title=f"Exported Broadcast Receivers ({len(exported_receivers)})",
            description=f"Found {len(exported_receivers)} exported broadcast receivers.",
            source_file="AndroidManifest.xml",
            code_reference=", ".join(r.name for r in exported_receivers[:3]),
            explanation="Unprotected broadcast receivers can receive forged intents from other apps.",
            remediation_advice="Verify intent filtering and enforce caller permission checks."
        ))

    # 5. Certificate Security Analysis
    for cert in metadata.certificates:
        if cert.is_self_signed:
            findings.append(StaticFinding(
                id="MAN-CERT-01",
                category="certificate",
                severity="Medium",
                confidence="Confirmed",
                title="Self-Signed APK Signing Certificate",
                description="The APK is signed with a self-signed X.509 certificate without a recognized Certificate Authority chain.",
                source_file="META-INF/ signing block",
                evidence_snippet=f"Issuer: {cert.issuer.get('common_name', 'Unknown')}, Subject: {cert.subject.get('common_name', 'Unknown')}",
                explanation="Self-signed certificates are standard for development but cannot establish organizational provenance, common in ad-hoc malware and unverified sideloaded apps.",
                remediation_advice="Sign production applications with a verifiable enterprise key or Google Play App Signing."
            ))
            summary_flags["self_signed_cert"] = True

        # Check for generic/test certificate subject
        subj_str = " ".join(cert.subject.values()).lower()
        if any(kw in subj_str for kw in ("test", "debug", "android", "example", "personal")):
            findings.append(StaticFinding(
                id="MAN-CERT-02",
                category="certificate",
                severity="Low",
                confidence="High",
                title="Non-Production / Personal Certificate Identity",
                description=f"Signing certificate subject indicates non-enterprise identity: {cert.subject.get('organization_name', 'Personal')}",
                source_file="META-INF/ signing block",
                evidence_snippet=f"Subject: {cert.subject}",
                explanation="Certificates issued to personal or debug entities suggest the package did not undergo vetted enterprise software release lifecycles.",
                remediation_advice="Review certificate fingerprints against known legitimate developer keys."
            ))

    # 6. Network Security Configuration
    if not metadata.network_security_config and metadata.uses_cleartext_traffic is not False:
        findings.append(StaticFinding(
            id="MAN-SEC-01",
            category="manifest",
            severity="Low",
            confidence="Confirmed",
            title="Missing Network Security Configuration",
            description="The application does not declare an android:networkSecurityConfig attribute.",
            source_file="AndroidManifest.xml",
            explanation="Without a custom network security configuration, Android defaults may permit cleartext traffic on older platforms or fail to enforce certificate pinning.",
            remediation_advice="Add a res/xml/network_security_config.xml declaring cleartextTrafficPermitted=false and pin trusted CAs."
        ))

    # 7. Exported Activities
    exported_activities = [a for a in metadata.activities if a.exported and a.name != metadata.launcher_activity]
    if exported_activities:
        findings.append(StaticFinding(
            id="MAN-EXP-03",
            category="manifest",
            severity="Low",
            confidence="Confirmed",
            title=f"Exported Secondary Activities ({len(exported_activities)})",
            description=f"Application exposes {len(exported_activities)} non-launcher activities to external apps without permission requirement.",
            source_file="AndroidManifest.xml",
            code_reference=", ".join(a.name for a in exported_activities[:3]),
            explanation="Unprotected activities may be launched directly by third-party applications, potentially bypassing authentication or workflow steps.",
            remediation_advice="Set android:exported=\"false\" on internal activities."
        ))

    return findings, summary_flags
