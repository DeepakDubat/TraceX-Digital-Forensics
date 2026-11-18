rule Android_Reverse_Shell {
    meta:
        description = "Detects reverse shell indicators and interactive socket stream redirection"
        severity = "Critical"
        confidence = "High"
    strings:
        $sh1 = "/system/bin/sh" ascii wide
        $sh2 = "/bin/sh" ascii wide
        $socket = "java/net/Socket" ascii wide
        $exec1 = "Runtime;->exec" ascii wide
        $exec2 = "ProcessBuilder" ascii wide
        $stream1 = "getInputStream" ascii wide
        $stream2 = "getOutputStream" ascii wide
    condition:
        ($sh1 or $sh2) and $socket and ($exec1 or $exec2) and ($stream1 and $stream2)
}

rule Android_Dynamic_Dex_Dropper {
    meta:
        description = "Detects dynamic Dalvik code loading used in stager/dropper malware"
        severity = "High"
        confidence = "High"
    strings:
        $d1 = "DexClassLoader" ascii wide
        $d2 = "PathClassLoader" ascii wide
        $d3 = "InMemoryDexClassLoader" ascii wide
        $cipher = "javax/crypto/Cipher" ascii wide
    condition:
        ($d1 or $d2 or $d3) and $cipher
}

rule Android_SMS_Toll_Fraud {
    meta:
        description = "Detects silent SMS sending routines associated with billing fraud"
        severity = "High"
        confidence = "Medium"
    strings:
        $sms1 = "sendTextMessage" ascii wide
        $sms2 = "android/telephony/SmsManager" ascii wide
        $sub = "getSubscriberId" ascii wide
    condition:
        $sms1 and ($sms2 or $sub)
}

rule Android_C2_Beaconing {
    meta:
        description = "Detects dynamic DNS or Telegram bot token C2 communication patterns"
        severity = "High"
        confidence = "High"
    strings:
        $ddns1 = "duckdns.org" ascii wide
        $ddns2 = "no-ip.com" ascii wide
        $ddns3 = "ngrok.io" ascii wide
        $tg1 = "api.telegram.org/bot" ascii wide
    condition:
        any of ($ddns*) or $tg1
}

rule Android_Banking_Overlay_Accessibility {
    meta:
        description = "Detects Accessibility Service abuse combined with overlay triggers"
        severity = "Critical"
        confidence = "High"
    strings:
        $acc = "AccessibilityService" ascii wide
        $event = "onAccessibilityEvent" ascii wide
        $window = "TYPE_APPLICATION_OVERLAY" ascii wide
    condition:
        $acc and $event and $window
}
