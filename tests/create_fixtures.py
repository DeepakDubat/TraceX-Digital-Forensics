import zipfile
import io
from pathlib import Path

def create_harmless_test_apk(output_path: Path) -> Path:
    """
    Constructs a harmless synthetic APK file for automated forensic unit tests.
    Contains valid ZIP header (PK\x03\x04), AndroidManifest.xml, and a mock classes.dex
    with embedded harmless test indicators (Google API key format, dynamic DNS, shell command strings).
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Harmless synthetic manifest XML
    manifest_xml = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="org.forensics.testapp"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE" />
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
    <application
        android:label="ForensicTestApp"
        android:usesCleartextTraffic="true"
        android:debuggable="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <service android:name=".BackgroundC2Service" android:exported="true" />
        <receiver android:name=".BootReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
    </application>
</manifest>"""

    # Synthetic DEX content with harmless forensic indicator strings
    # We include standard DEX magic bytes "dex\n035\0"
    dex_header = b"dex\n035\x00" + b"\x00" * 100
    dex_strings = (
        b"http://malicious-telemetry.duckdns.org:4444/gate.php\x00"
        b"https://api.telegram.org/bot123456789:ABCdefGHIjklMNOpqrsTUVwxyz012345678\x00"
        b"AIzaSyD-TestFakeAPIKey_ForForensics9876543\x00"
        b"192.168.1.105\x00"
        b"198.51.100.45\x00"
        b"/system/bin/sh\x00"
        b"java/net/Socket\x00"
        b"Runtime;->exec\x00"
        b"ProcessBuilder\x00"
        b"getInputStream\x00"
        b"getOutputStream\x00"
        b"DexClassLoader\x00"
        b"javax/crypto/Cipher\x00"
        b"aHR0cDovL2JhY2t1cC1jMi5kdWNrZG5zLm9yZw==\x00" # Base64 of 'http://backup-c2.duckdns.org'
    )
    mock_dex = dex_header + dex_strings

    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest_xml)
        zf.writestr("classes.dex", mock_dex)
        zf.writestr("res/values/strings.xml", b"<resources><string name='app_name'>ForensicTestApp</string></resources>")
        zf.writestr("assets/config.json", b'{"server": "http://assets-c2.duckdns.org:8080"}')

    return output_path
