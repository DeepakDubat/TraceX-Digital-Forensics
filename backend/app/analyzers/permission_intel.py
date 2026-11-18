"""
Universal Android Permission Intelligence & Knowledge Base
Defines standard Android permissions with protection levels, categories,
purposes, privacy risks, and security implications based on AOSP specs.
"""
from typing import Dict, Any, Optional, List, Tuple
from pydantic import BaseModel

class PermissionDetail(BaseModel):
    name: str
    category: str  # e.g., 'INTERNET & NETWORK', 'STORAGE & FILE ACCESS', 'CAMERA & MICROPHONE', etc.
    protection_level: str  # 'normal', 'dangerous', 'signature', 'special_access', 'custom'
    description: str
    purpose: str
    access_scope: str
    privacy_risk: str
    security_implication: str
    risk_level: str  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'

# Authoritative AOSP & Extended Android Permission Catalog
ANDROID_PERMISSIONS_CATALOG: Dict[str, Dict[str, str]] = {
    # A. INTERNET & NETWORK
    "android.permission.INTERNET": {
        "category": "INTERNET & NETWORK",
        "protection_level": "normal",
        "description": "Allows application to open network sockets and communicate over the Internet.",
        "purpose": "Permits connection to backend servers, APIs, content delivery networks, or external command-and-control infrastructure.",
        "access_scope": "Full network socket creation and outgoing/incoming TCP/UDP traffic.",
        "privacy_risk": "Data exfiltration: permits uploading harvested credentials, device identifiers, or telemetry to remote servers.",
        "security_implication": "Essential for network-connected malware to establish remote C2 channels, download secondary payloads, or leak sensitive device state.",
        "risk_level": "MEDIUM"
    },
    "android.permission.ACCESS_NETWORK_STATE": {
        "category": "INTERNET & NETWORK",
        "protection_level": "normal",
        "description": "Allows application to view status of network connections.",
        "purpose": "Allows detecting whether device is on Wi-Fi, mobile data, or disconnected to optimize network requests.",
        "access_scope": "Network connectivity state, roaming status, connection type.",
        "privacy_risk": "Low privacy risk; can be used for passive device profiling.",
        "security_implication": "Malware uses this to wait for Wi-Fi before bulk exfiltration to avoid raising cellular data alerts.",
        "risk_level": "LOW"
    },
    "android.permission.ACCESS_WIFI_STATE": {
        "category": "INTERNET & NETWORK",
        "protection_level": "normal",
        "description": "Allows application to view information about Wi-Fi networking.",
        "purpose": "Permits querying Wi-Fi SSID, BSSID, link speed, and MAC address state.",
        "access_scope": "Wi-Fi access point identifiers, signal strength, connection metrics.",
        "privacy_risk": "Wi-Fi BSSID scanning can be cross-referenced with public geolocation databases to pinpoint device physical location without GPS.",
        "security_implication": "Enables physical tracking and reconnaissance of local network topology.",
        "risk_level": "MEDIUM"
    },
    "android.permission.CHANGE_NETWORK_STATE": {
        "category": "INTERNET & NETWORK",
        "protection_level": "normal",
        "description": "Allows application to change network connectivity state.",
        "purpose": "Permits enabling/disabling data connectivity or routing traffic.",
        "access_scope": "Network interface control and connection toggling.",
        "privacy_risk": "Could force data connection over unmetered or metered interfaces.",
        "security_implication": "May be abused to manipulate network paths or bypass captive portals.",
        "risk_level": "LOW"
    },
    "android.permission.CHANGE_WIFI_STATE": {
        "category": "INTERNET & NETWORK",
        "protection_level": "normal",
        "description": "Allows application to connect to and disconnect from Wi-Fi access points and make changes to configured Wi-Fi networks.",
        "purpose": "Connecting to IoT devices, printers, or enterprise Wi-Fi networks.",
        "access_scope": "Wi-Fi association, disconnection, and profile management.",
        "privacy_risk": "Can connect device to rogue access points without user awareness.",
        "security_implication": "Man-in-the-middle vector if application connects device to attacker-controlled Wi-Fi.",
        "risk_level": "MEDIUM"
    },

    # B. STORAGE & FILE ACCESS
    "android.permission.READ_EXTERNAL_STORAGE": {
        "category": "STORAGE & FILE ACCESS",
        "protection_level": "dangerous",
        "description": "Allows application to read files from external and shared storage.",
        "purpose": "Accessing user documents, media, downloads, and files stored on shared storage.",
        "access_scope": "Full read access to shared /sdcard partitions, user files, downloads.",
        "privacy_risk": "Extensive privacy exposure: access to personal photos, downloaded PDFs, documents, WhatsApp media backups.",
        "security_implication": "Spyware routinely sweeps shared storage for sensitive tokens, wallet keys, or confidential documents.",
        "risk_level": "HIGH"
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "category": "STORAGE & FILE ACCESS",
        "protection_level": "dangerous",
        "description": "Allows application to write and modify files on external and shared storage.",
        "purpose": "Saving downloaded files, caching application media, creating user-facing documents.",
        "access_scope": "Write, overwrite, and delete access across shared storage volumes.",
        "privacy_risk": "Tampering with documents, planting malicious files, or modifying other applications' unencrypted shared data.",
        "security_implication": "Ransomware encryption vector: encrypts or destroys user files in shared storage.",
        "risk_level": "HIGH"
    },
    "android.permission.READ_MEDIA_IMAGES": {
        "category": "STORAGE & FILE ACCESS",
        "protection_level": "dangerous",
        "description": "Allows application to read image files from shared storage (Android 13+ granular permission).",
        "purpose": "Photo gallery viewers, image editors, avatar uploads.",
        "access_scope": "All stored photographs and images across device storage.",
        "privacy_risk": "Direct access to private personal photographs, screenshots, and visual records.",
        "security_implication": "Targeted exfiltration of personal photos and screenshot evidence.",
        "risk_level": "HIGH"
    },
    "android.permission.READ_MEDIA_VIDEO": {
        "category": "STORAGE & FILE ACCESS",
        "protection_level": "dangerous",
        "description": "Allows application to read video files from shared storage (Android 13+ granular permission).",
        "purpose": "Video playback, editing, social sharing.",
        "access_scope": "All recorded and downloaded video files.",
        "privacy_risk": "Exposes personal recordings and downloaded videos.",
        "security_implication": "Bulk exfiltration of personal video recordings.",
        "risk_level": "HIGH"
    },
    "android.permission.READ_MEDIA_AUDIO": {
        "category": "STORAGE & FILE ACCESS",
        "protection_level": "dangerous",
        "description": "Allows application to read audio files from shared storage (Android 13+ granular permission).",
        "purpose": "Music players, voice message playback.",
        "access_scope": "Music tracks, audio recordings, podcast downloads.",
        "privacy_risk": "Access to voice memos, call recordings stored in audio directories.",
        "security_implication": "May expose recorded conversations or sensitive audio transcripts.",
        "risk_level": "MEDIUM"
    },
    "android.permission.MANAGE_EXTERNAL_STORAGE": {
        "category": "STORAGE & FILE ACCESS",
        "protection_level": "special_access",
        "description": "Allows broad access to shared storage in all-files-access mode (Android 11+).",
        "purpose": "File manager apps, anti-virus scanners, backup/restore utilities.",
        "access_scope": "Unrestricted read, write, and delete access across all storage partitions including root of SD card.",
        "privacy_risk": "Complete compromise of all device files, bypasses Scoped Storage safeguards.",
        "security_implication": "Critical ransomware and wiper capability; permits encrypting or deleting all user files.",
        "risk_level": "CRITICAL"
    },

    # C. CAMERA & MICROPHONE
    "android.permission.CAMERA": {
        "category": "CAMERA & MICROPHONE",
        "protection_level": "dangerous",
        "description": "Allows application to take photos and record video using device cameras.",
        "purpose": "Barcode scanning, photo taking, video calls, augmented reality.",
        "access_scope": "Front and rear camera hardware sensors, image capture stream.",
        "privacy_risk": "Surreptitious visual surveillance: capturing surroundings or user without visible preview.",
        "security_implication": "Classic stalkerware/spyware capability for ambient visual monitoring.",
        "risk_level": "CRITICAL"
    },
    "android.permission.RECORD_AUDIO": {
        "category": "CAMERA & MICROPHONE",
        "protection_level": "dangerous",
        "description": "Allows application to record audio using the microphone sensor.",
        "purpose": "Voice notes, audio messaging, VoIP calls, speech recognition.",
        "access_scope": "Microphone hardware, continuous audio sampling.",
        "privacy_risk": "Continuous ambient eavesdropping: intercepts private room conversations and phone calls.",
        "security_implication": "Key spyware capability used by commercial surveillance implants (e.g. Pegasus, Predator).",
        "risk_level": "CRITICAL"
    },

    # D. LOCATION
    "android.permission.ACCESS_FINE_LOCATION": {
        "category": "LOCATION",
        "protection_level": "dangerous",
        "description": "Allows application to access precise location from GPS and cellular/Wi-Fi positioning.",
        "purpose": "Turn-by-turn navigation, geofencing, local ride-hailing.",
        "access_scope": "Precise geographic coordinates (accurate within meters).",
        "privacy_risk": "Real-time physical tracking of the device holder's home, workplace, and movements.",
        "security_implication": "Stalkerware and reconnaissance tracking vector.",
        "risk_level": "CRITICAL"
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "category": "LOCATION",
        "protection_level": "dangerous",
        "description": "Allows application to access approximate location derived from network location providers.",
        "purpose": "Weather reports, city-level regionalization, localized content.",
        "access_scope": "Approximate geographic coordinates (block- or neighborhood-level).",
        "privacy_risk": "Regional tracking of user location over time.",
        "security_implication": "Provides adversary with general city or neighborhood location history.",
        "risk_level": "HIGH"
    },
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "category": "LOCATION",
        "protection_level": "dangerous",
        "description": "Allows application to access device location in the background without user interaction.",
        "purpose": "Continuous fitness tracking, emergency safety beaconing.",
        "access_scope": "Perpetual GPS and network location tracking even when app is closed or minimized.",
        "privacy_risk": "Constant 24/7 location logging without active user awareness.",
        "security_implication": "Persistent stalking and location profiling vector.",
        "risk_level": "CRITICAL"
    },

    # E. CONTACTS & COMMUNICATION
    "android.permission.READ_CONTACTS": {
        "category": "CONTACTS & COMMUNICATION",
        "protection_level": "dangerous",
        "description": "Allows application to read the user's contacts data.",
        "purpose": "Social graph synchronization, contact search, messaging companion.",
        "access_scope": "Complete device address book: names, phone numbers, emails, postal addresses.",
        "privacy_risk": "Severe privacy violation: harvesting entire social and professional network.",
        "security_implication": "Spyware harvests contact lists for social engineering, spam campaigns, and extortion.",
        "risk_level": "HIGH"
    },
    "android.permission.WRITE_CONTACTS": {
        "category": "CONTACTS & COMMUNICATION",
        "protection_level": "dangerous",
        "description": "Allows application to modify the user's contacts data.",
        "purpose": "Syncing contact updates, adding new contacts.",
        "access_scope": "Adding, editing, or deleting contact book entries.",
        "privacy_risk": "Tampering with contact records, injecting spoofed emergency numbers.",
        "security_implication": "Phishing vector: replacing legitimate contact phone numbers with attacker-controlled ones.",
        "risk_level": "HIGH"
    },
    "android.permission.READ_PHONE_STATE": {
        "category": "CONTACTS & COMMUNICATION",
        "protection_level": "dangerous",
        "description": "Allows read-only access to phone state, including phone number, cellular network info, and ongoing calls.",
        "purpose": "Pausing media playback on incoming calls, cellular network diagnostic.",
        "access_scope": "Device identifiers (IMEI/IMSI on older Android), cellular operator, call state, phone number.",
        "privacy_risk": "Permanent device tracking via hardware identifiers; victim phone number extraction.",
        "security_implication": "Used by malware for device fingerprinting and victim profiling before payload deployment.",
        "risk_level": "HIGH"
    },
    "android.permission.READ_CALL_LOG": {
        "category": "CONTACTS & COMMUNICATION",
        "protection_level": "dangerous",
        "description": "Allows application to read the user's call log.",
        "purpose": "Caller ID utilities, call history backup apps.",
        "access_scope": "Complete call history: caller names, phone numbers, timestamps, durations.",
        "privacy_risk": "Exposes who the user speaks with, call frequencies, and private relationships.",
        "security_implication": "Commercial spyware and stalkerware standard capability.",
        "risk_level": "CRITICAL"
    },
    "android.permission.WRITE_CALL_LOG": {
        "category": "CONTACTS & COMMUNICATION",
        "protection_level": "dangerous",
        "description": "Allows application to write (but not read) the user's call log data.",
        "purpose": "Call management, automated call history cleanup.",
        "access_scope": "Inserting, modifying, or deleting entries in call records.",
        "privacy_risk": "Erasing forensic traces of unauthorized calls.",
        "security_implication": "Malware deletes records of premium-rate numbers dialed surreptitiously to evade discovery.",
        "risk_level": "HIGH"
    },
    "android.permission.SEND_SMS": {
        "category": "CONTACTS & COMMUNICATION",
        "protection_level": "dangerous",
        "description": "Allows application to send SMS messages without user interaction.",
        "purpose": "Automated notification dispatch, carrier billing verification.",
        "access_scope": "Direct cellular SMS transmission without showing SMS application or user prompt.",
        "privacy_risk": "Financial harm: sending messages to premium-rate short codes resulting in fraudulent charges.",
        "security_implication": "Toll fraud malware and worm spreading via SMS distribution.",
        "risk_level": "CRITICAL"
    },
    "android.permission.RECEIVE_SMS": {
        "category": "CONTACTS & COMMUNICATION",
        "protection_level": "dangerous",
        "description": "Allows application to receive and monitor incoming SMS messages.",
        "purpose": "Automatic OTP verification in payment apps.",
        "access_scope": "Interception of all incoming SMS text messages before the default SMS app processes them.",
        "privacy_risk": "Interception of two-factor authentication (2FA) OTP tokens, banking authorization codes, private SMS.",
        "security_implication": "Core banking trojan component used to bypass bank SMS 2FA protections.",
        "risk_level": "CRITICAL"
    },
    "android.permission.READ_SMS": {
        "category": "CONTACTS & COMMUNICATION",
        "protection_level": "dangerous",
        "description": "Allows application to read SMS messages stored on the device.",
        "purpose": "SMS backup and restore, message search.",
        "access_scope": "Stored SMS inbox, sent messages, draft threads.",
        "privacy_risk": "Exfiltration of entire messaging history including historic banking alerts and 2FA credentials.",
        "security_implication": "Banking trojans search stored messages for account balances, PINs, and authentication secrets.",
        "risk_level": "CRITICAL"
    },

    # F. DEVICE & SYSTEM
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "category": "DEVICE & SYSTEM",
        "protection_level": "normal",
        "description": "Allows application to receive the BOOT_COMPLETED broadcast sent after system boot completes.",
        "purpose": "Re-establishing alarm timers, synchronizing calendar alerts, starting background service workers.",
        "access_scope": "Broadcast receiver triggered automatically upon device startup.",
        "privacy_risk": "Ensures application starts without explicit user invocation.",
        "security_implication": "Primary persistence mechanism in Android malware, allowing background C2 beaconing across restarts.",
        "risk_level": "MEDIUM"
    },
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": {
        "category": "DEVICE & SYSTEM",
        "protection_level": "normal",
        "description": "Allows application to ask the user to disable battery optimizations (Doze mode exemption).",
        "purpose": "VOIP calling apps, critical emergency beaconing.",
        "access_scope": "Exemption from Android Doze and App Standby power management.",
        "privacy_risk": "Allows app to run perpetually in the background without being suspended by OS.",
        "security_implication": "Malware maintains unbroken background connection to C2 without sleep interruptions.",
        "risk_level": "MEDIUM"
    },
    "android.permission.WAKE_LOCK": {
        "category": "DEVICE & SYSTEM",
        "protection_level": "normal",
        "description": "Allows using PowerManager WakeLocks to keep processor from sleeping or screen from dimming.",
        "purpose": "Video playback, audio streaming, active navigation.",
        "access_scope": "CPU power state control.",
        "privacy_risk": "Battery drain.",
        "security_implication": "Prevents CPU sleep to sustain background beaconing and remote access sessions.",
        "risk_level": "LOW"
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "category": "DEVICE & SYSTEM",
        "protection_level": "special_access",
        "description": "Allows application to display overlay windows over any other application on the screen.",
        "purpose": "Floating chat heads, screen recorders, accessibility tools.",
        "access_scope": "Rendering transparent or opaque UI elements directly over running target apps.",
        "privacy_risk": "Tapjacking and credential phishing: overlays fake login dialogs over legitimate banking apps.",
        "security_implication": "Hallmark of Android banking trojans (Anatsa, Hook, Godfather) to steal credentials and 2FA.",
        "risk_level": "CRITICAL"
    },
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "category": "DEVICE & SYSTEM",
        "protection_level": "signature|privileged",
        "description": "Must be required by an AccessibilityService to ensure that only the system can bind to it.",
        "purpose": "Assistive software for users with disabilities (screen readers, automated navigation).",
        "access_scope": "Full observation of all screen text, keystroke logging, synthetic touch click dispatch, window event stream.",
        "privacy_risk": "Complete total compromise of user input, onscreen content, and unencrypted passwords.",
        "security_implication": "Most dangerous privilege in modern Android malware: automates bank transfers, clicks through Play Protect, and logs keystrokes.",
        "risk_level": "CRITICAL"
    },
    "android.permission.BIND_DEVICE_ADMIN": {
        "category": "DEVICE & SYSTEM",
        "protection_level": "signature",
        "description": "Must be required by device administration receivers to ensure only system can interact with them.",
        "purpose": "Enterprise Mobility Management (EMM), MDM remote wipe and passcode enforcement.",
        "access_scope": "Device locking, passcode reset, storage wiping, disabling camera, uninstallation prevention.",
        "privacy_risk": "Remote device wipe or lock capability.",
        "security_implication": "Ransomware locks the screen and prevents user uninstallation via Device Admin.",
        "risk_level": "CRITICAL"
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "category": "DEVICE & SYSTEM",
        "protection_level": "special_access",
        "description": "Allows application to request installing secondary APK packages.",
        "purpose": "Third-party app stores, enterprise internal software distributors.",
        "access_scope": "Prompts system package installer to install staged APK files.",
        "privacy_risk": "Sideloading unverified third-party binaries.",
        "security_implication": "Dropper/stager architecture: fetches secondary encrypted payload and prompts installation.",
        "risk_level": "HIGH"
    },
    "android.permission.QUERY_ALL_PACKAGES": {
        "category": "DEVICE & SYSTEM",
        "protection_level": "normal",
        "description": "Allows querying inventory of any normal apps on the device, regardless of manifest declarations (Android 11+).",
        "purpose": "Launcher apps, device security inventory.",
        "access_scope": "Full list of all installed packages, versions, and package metadata.",
        "privacy_risk": "Device behavioral profiling: reveals banking apps, dating apps, crypto wallets, and religious apps.",
        "security_implication": "Banking trojans scan installed apps to identify target bank apps and trigger corresponding phishing overlays.",
        "risk_level": "HIGH"
    },

    # G. OTHER SENSITIVE PERMISSIONS
    "android.permission.GET_ACCOUNTS": {
        "category": "OTHER SENSITIVE PERMISSIONS",
        "protection_level": "dangerous",
        "description": "Allows access to the list of accounts in the Accounts Service.",
        "purpose": "Account selection, single sign-on integration.",
        "access_scope": "Registered Google, Microsoft, email account identities.",
        "privacy_risk": "Exposes primary email addresses and cloud identity profiles associated with device.",
        "security_implication": "Aids credential stuffing and identity correlation.",
        "risk_level": "MEDIUM"
    },
    "android.permission.READ_CALENDAR": {
        "category": "OTHER SENSITIVE PERMISSIONS",
        "protection_level": "dangerous",
        "description": "Allows application to read the user's calendar events and data.",
        "purpose": "Calendar sync, meeting assistant apps.",
        "access_scope": "Meeting titles, attendee lists, notes, locations, schedules.",
        "privacy_risk": "Reveals user physical itinerary, business meetings, and personal appointments.",
        "security_implication": "Reconnaissance against corporate targets in executive spearphishing.",
        "risk_level": "MEDIUM"
    },
    "android.permission.WRITE_CALENDAR": {
        "category": "OTHER SENSITIVE PERMISSIONS",
        "protection_level": "dangerous",
        "description": "Allows application to create, edit, or delete calendar events.",
        "purpose": "Adding meeting bookings, event invitations.",
        "access_scope": "Injecting or removing events from user calendar.",
        "privacy_risk": "Spam calendar injection (phishing lures inserted directly into calendar).",
        "security_implication": "Calendar phishing vector.",
        "risk_level": "LOW"
    },
    "android.permission.POST_NOTIFICATIONS": {
        "category": "OTHER SENSITIVE PERMISSIONS",
        "protection_level": "dangerous",
        "description": "Allows application to post notifications to system status bar (Android 13+).",
        "purpose": "Displaying incoming message alerts, transaction notices, reminders.",
        "access_scope": "System notification shade display.",
        "privacy_risk": "Displaying deceptive notifications.",
        "security_implication": "Malware displays fake system security warnings or bank alerts to lure user into opening overlay.",
        "risk_level": "LOW"
    },
    "android.permission.USE_BIOMETRIC": {
        "category": "OTHER SENSITIVE PERMISSIONS",
        "protection_level": "normal",
        "description": "Allows application to use device biometric hardware (fingerprint, face unlock).",
        "purpose": "Fast biometric login and payment authorization.",
        "access_scope": "BiometricPrompt authentication API.",
        "privacy_risk": "No raw biometric data exposed; checks success/failure token.",
        "security_implication": "Malware can prompt biometric unlock under deceptive contexts.",
        "risk_level": "LOW"
    },
    "android.permission.USE_FINGERPRINT": {
        "category": "OTHER SENSITIVE PERMISSIONS",
        "protection_level": "normal",
        "description": "Allows application to use fingerprint hardware (deprecated in API 28 in favor of USE_BIOMETRIC).",
        "purpose": "Legacy fingerprint authentication.",
        "access_scope": "Fingerprint hardware prompt.",
        "privacy_risk": "Low; checks authentication result.",
        "security_implication": "Deceptive authentication prompts.",
        "risk_level": "LOW"
    }
}

# Categorization mapping for fallback prefix matching
CATEGORY_RULES: List[Tuple[str, str]] = [
    ("SMS", "CONTACTS & COMMUNICATION"),
    ("CALL", "CONTACTS & COMMUNICATION"),
    ("PHONE", "CONTACTS & COMMUNICATION"),
    ("CONTACT", "CONTACTS & COMMUNICATION"),
    ("STORAGE", "STORAGE & FILE ACCESS"),
    ("MEDIA", "STORAGE & FILE ACCESS"),
    ("FILE", "STORAGE & FILE ACCESS"),
    ("CAMERA", "CAMERA & MICROPHONE"),
    ("AUDIO", "CAMERA & MICROPHONE"),
    ("RECORD", "CAMERA & MICROPHONE"),
    ("LOCATION", "LOCATION"),
    ("GPS", "LOCATION"),
    ("NETWORK", "INTERNET & NETWORK"),
    ("WIFI", "INTERNET & NETWORK"),
    ("INTERNET", "INTERNET & NETWORK"),
    ("BOOT", "DEVICE & SYSTEM"),
    ("BATTERY", "DEVICE & SYSTEM"),
    ("WAKE", "DEVICE & SYSTEM"),
    ("ACCESSIBILITY", "DEVICE & SYSTEM"),
    ("ADMIN", "DEVICE & SYSTEM"),
    ("PACKAGE", "DEVICE & SYSTEM"),
    ("WINDOW", "DEVICE & SYSTEM"),
    ("OVERLAY", "DEVICE & SYSTEM"),
    ("CALENDAR", "OTHER SENSITIVE PERMISSIONS"),
    ("ACCOUNT", "OTHER SENSITIVE PERMISSIONS"),
    ("BIOMETRIC", "OTHER SENSITIVE PERMISSIONS"),
    ("FINGERPRINT", "OTHER SENSITIVE PERMISSIONS"),
    ("NOTIFICATION", "OTHER SENSITIVE PERMISSIONS"),
]

def classify_permission(perm_name: str) -> PermissionDetail:
    """
    Universally analyzes and enriches any Android permission.
    Works for standard AOSP, custom third-party, and newer permissions.
    """
    clean_name = perm_name.strip()
    
    # Check authoritative catalog first
    if clean_name in ANDROID_PERMISSIONS_CATALOG:
        data = ANDROID_PERMISSIONS_CATALOG[clean_name]
        return PermissionDetail(
            name=clean_name,
            category=data["category"],
            protection_level=data["protection_level"],
            description=data["description"],
            purpose=data["purpose"],
            access_scope=data["access_scope"],
            privacy_risk=data["privacy_risk"],
            security_implication=data["security_implication"],
            risk_level=data["risk_level"]
        )

    # Dynamic classification for custom, third-party, or new permissions
    short_name = clean_name.split(".")[-1].upper()
    category = "OTHER SENSITIVE PERMISSIONS"
    for keyword, cat in CATEGORY_RULES:
        if keyword in short_name:
            category = cat
            break

    # Determine protection level
    protection_level = "custom"
    if clean_name.startswith("android.permission."):
        protection_level = "normal"
    elif "signature" in clean_name.lower():
        protection_level = "signature"

    # Risk level determination based on category and name
    risk_level = "LOW"
    if any(k in short_name for k in ("SMS", "ACCESSIBILITY", "ADMIN", "ALERT_WINDOW", "MANAGE_EXTERNAL_STORAGE")):
        risk_level = "CRITICAL"
        protection_level = "dangerous" if protection_level != "signature" else protection_level
    elif any(k in short_name for k in ("CAMERA", "RECORD", "LOCATION", "CONTACT", "CALL", "STORAGE")):
        risk_level = "HIGH"
        protection_level = "dangerous"
    elif any(k in short_name for k in ("INTERNET", "WIFI", "BOOT", "ACCOUNT")):
        risk_level = "MEDIUM"

    desc = f"Application requests '{clean_name}' permission."
    purpose = f"Grants application access to resources governed by {clean_name}."
    access_scope = f"Scope governed by {short_name} capability."
    privacy_risk = f"Access to resources under {clean_name} may expose user data if abused."
    sec_imp = "Inspect application bytecode to verify legitimate operational context."

    return PermissionDetail(
        name=clean_name,
        category=category,
        protection_level=protection_level,
        description=desc,
        purpose=purpose,
        access_scope=access_scope,
        privacy_risk=privacy_risk,
        security_implication=sec_imp,
        risk_level=risk_level
    )
