"""Nepali strings for every Kavach finding message and fix.

Placeholders match the English templates in checks.py exactly. A finding
message states what was found and what it means; the fix says what to do.
Nothing here claims a site is secure — a good grade only means the checks
run found nothing.
"""
from __future__ import annotations

MESSAGE_NE = {
    "http_not_https": (
        "यो साइट साधारण HTTP बाट चल्छ — लगइन, कुकी र सबै ट्राफिक पढ्न र "
        "बदल्न सकिन्छ।"
    ),
    "https_downgrade": (
        "HTTPS ठेगाना खोल्दा साइटले HTTP मा पठायो — सुरक्षित जडान हटाइयो।"
    ),
    "tls_old": (
        "सर्भरले पुरानो TLS {version} प्रयोग गर्छ — TLS 1.2 भन्दा तलको "
        "संस्करण असुरक्षित मानिन्छ।"
    ),
    "cert_invalid": (
        "साइटको प्रमाणपत्र (certificate) मान्य छैन: {error}। ब्राउजरले "
        "चेतावनी देखाउँछ र प्रयोगकर्ताले विश्वास गर्दैनन्।"
    ),
    "tls_check_failed": (
        "TLS जाँच गर्न सकिएन (नेटवर्क) — प्रमाणपत्र र TLS संस्करण जाँचिएन।"
    ),
    "missing_hsts": (
        "Strict-Transport-Security हेडर छैन — ब्राउजरले यो साइटलाई HTTP "
        "बाट पनि खोल्न सक्छ, जसले आक्रमणको बाटो खोल्छ।"
    ),
    "hsts_weak": (
        "HSTS छ तर max-age {max_age} सेकेन्ड मात्र छ — कम्तीमा एक वर्ष "
        "(31536000) हुनुपर्छ।"
    ),
    "missing_csp": (
        "Content-Security-Policy हेडर छैन — XSS र इन्जेक्सन आक्रमण रोक्ने "
        "मुख्य सुरक्षा छैन।"
    ),
    "csp_weak": (
        "Content-Security-Policy मा 'unsafe-inline' छ — यसले नीतिलाई "
        "कमजोर बनाउँछ।"
    ),
    "missing_x_frame_options": (
        "X-Frame-Options हेडर छैन — यो साइटलाई अर्को साइटको फ्रेमभित्र "
        "राखेर क्लिकज्याकिङ गर्न सकिन्छ।"
    ),
    "missing_x_content_type_options": (
        "X-Content-Type-Options: nosniff छैन — ब्राउजरले फाइलको प्रकार "
        "अनुमान गरेर गलत तरिकाले चलाउन सक्छ।"
    ),
    "missing_referrer_policy": (
        "Referrer-Policy हेडर छैन — लिङ्क थिच्दा पूरै ठेगाना अर्को साइटलाई "
        "जान सक्छ।"
    ),
    "missing_permissions_policy": (
        "Permissions-Policy हेडर छैन — ब्राउजरका शक्तिशाली सुविधा "
        "(क्यामेरा, माइक्रोफोन, स्थान) नियन्त्रण गरिएको छैन।"
    ),
    "server_header": (
        "Server हेडरले सफ्टवेयर देखाउँछ ({value}) — आक्रमणकारीले कुन "
        "संस्करणमा कुन कमजोरी छ भनेर खोज्न सक्छन्।"
    ),
    "x_powered_by": (
        "X-Powered-By हेडरले प्रविधि देखाउँछ ({value}) — आक्रमणकारीलाई "
        "सहयोग पुग्छ।"
    ),
    "cookie_no_secure": (
        "कुकी {names} मा Secure झण्डा छैन — HTTP बाट पनि कुकी पठाइन सक्छ "
        "र चोरिन सक्छ।"
    ),
    "cookie_no_httponly": (
        "कुकी {names} मा HttpOnly झण्डा छैन — जाभास्क्रिप्टले कुकी पढ्न "
        "सक्छ, जसले XSS आक्रमणलाई सजिलो बनाउँछ।"
    ),
    "cookie_no_samesite": (
        "कुकी {names} मा SameSite झण्डा छैन — अर्को साइटबाट अनुरोध गर्दा "
        "कुकी पठाइन सक्छ (CSRF जोखिम)।"
    ),
    "cors_wildcard": (
        "Access-Control-Allow-Origin: * छ{credentials} — कुनै पनि साइटले "
        "यो साइटको जवाफ पढ्न सक्छ।"
    ),
    "git_exposed": (
        "/.git/HEAD सार्वजनिक रूपमा खुला छ — स्रोत कोड र इतिहास डाउनलोड "
        "गर्न सकिन्छ।"
    ),
    "env_exposed": (
        "/.env फाइल सार्वजनिक रूपमा खुला छ — यसमा पासवर्ड र API कुञ्जी "
        "हुन सक्छन्। तुरुन्तै बदल्नुहोस्।"
    ),
    "backup_file_exposed": (
        "ब्याकअप फाइल {path} सार्वजनिक रूपमा खुला छ — यसमा डाटाबेस वा "
        "स्रोत कोड हुन सक्छ।"
    ),
    "sqli_error": (
        "प्यारामिटरमा ' राख्दा डाटाबेस त्रुटि देखियो ({sign}) — SQL "
        "इन्जेक्सनको सम्भावना छ।"
    ),
    "xss_reflected": (
        "प्यारामिटरमा पठाएको {marker} जवाफमा इन्कोड नगरी फर्कियो — "
        "reflected XSS को सम्भावना छ।"
    ),
    "robots_sensitive": (
        "robots.txt ले संवेदनशील बाटो देखाउँछ ({paths}) — आक्रमणकारीले "
        "त्यही बाटो खोज्छन्।"
    ),
    "unreachable": (
        "साइट खोल्न सकिएन ({error}) — ठेगाना वा नेटवर्क जाँच्नुहोस्।"
    ),
}

FIX_NE = {
    "http_not_https": "साइटलाई HTTPS मा सार्नुहोस् र HTTP बाट HTTPS मा रिडाइरेक्ट गर्नुहोस्।",
    "https_downgrade": "HTTPS बाट HTTP मा रिडाइरेक्ट हटाउनुहोस्; सबै ट्राफिक HTTPS मा राख्नुहोस्।",
    "tls_old": "सर्भरमा TLS 1.2 वा 1.3 मात्र खोल्नुहोस्; पुराना संस्करण बन्द गर्नुहोस्।",
    "cert_invalid": "मान्य प्रमाणपत्र (Let's Encrypt निःशुल्क छ) राख्नुहोस् र म्याद सकिनुअघि नवीकरण गर्नुहोस्।",
    "tls_check_failed": "नेटवर्क जाँचेर फेरि स्क्यान गर्नुहोस्।",
    "missing_hsts": "Strict-Transport-Security: max-age=31536000; includeSubDomains हेडर थप्नुहोस्।",
    "hsts_weak": "max-age लाई 31536000 (एक वर्ष) वा बढी बनाउनुहोस्।",
    "missing_csp": "Content-Security-Policy हेडर थप्नुहोस् — सुरुमा default-src 'self' बाट।",
    "csp_weak": "'unsafe-inline' हटाउनुहोस्; स्क्रिप्टका लागि nonce वा hash प्रयोग गर्नुहोस्।",
    "missing_x_frame_options": "X-Frame-Options: DENY वा SAMEORIGIN हेडर थप्नुहोस्।",
    "missing_x_content_type_options": "X-Content-Type-Options: nosniff हेडर थप्नुहोस्।",
    "missing_referrer_policy": "Referrer-Policy: strict-origin-when-cross-origin हेडर थप्नुहोस्।",
    "missing_permissions_policy": "Permissions-Policy हेडर थप्नुहोस् (जस्तै camera=(), microphone=(), geolocation=())।",
    "server_header": "Server हेडर नपठाउनुहोस् वा संस्करण नलेख्नुहोस्।",
    "x_powered_by": "X-Powered-By हेडर हटाउनुहोस्।",
    "cookie_no_secure": "सबै कुकीमा Secure झण्डा थप्नुहोस्।",
    "cookie_no_httponly": "सबै कुकीमा HttpOnly झण्डा थप्नुहोस्।",
    "cookie_no_samesite": "सबै कुकीमा SameSite=Lax (वा Strict) थप्नुहोस्।",
    "cors_wildcard": "Access-Control-Allow-Origin मा * को सट्टा ठ्याक्कै अनुमति भएका डोमेन लेख्नुहोस्।",
    "git_exposed": "/.git लाई वेब सर्भरबाट रोक्नुहोस् (वा डिप्लोयमा नराख्नुहोस्)।",
    "env_exposed": "/.env लाई वेब सर्भरबाट रोक्नुहोस् र भित्रका सबै पासवर्ड/कुञ्जी तुरुन्तै बदल्नुहोस्।",
    "backup_file_exposed": "ब्याकअप फाइललाई वेब रुटबाट हटाउनुहोस् वा पहुँच रोक्नुहोस्।",
    "sqli_error": "SQL क्वेरीमा prepared statement / parameterised query प्रयोग गर्नुहोस्; डाटाबेस त्रुटि प्रयोगकर्तालाई कहिल्यै नदेखाउनुहोस्।",
    "xss_reflected": "प्रयोगकर्ताको इनपुट देखाउँदा सधैं escape गर्नुहोस् (वा framework को auto-escaping प्रयोग गर्नुहोस्)।",
    "robots_sensitive": "संवेदनशील बाटो robots.txt मा नलेख्नुहोस्; पहुँच नियन्त्रणले सुरक्षा गर्नुहोस्, robots.txt ले होइन।",
    "unreachable": "ठेगाना सही छ कि नाइँ र साइट चलेको छ कि नाइँ जाँच्नुहोस्।",
}

SUMMARY_NE = {
    "clean": "जाँचिएका कुरामा कुनै समस्या भेटिएन। यो ग्यारेन्टी होइन — जाँच नगरिएका कुरा अझै हुन सक्छन्।",
    "found": "{n} वटा समस्या भेटिए — सबैभन्दा गम्भीर पहिले हेर्नुहोस्।",
}

DISCLAIMER_NE = (
    "Kavach ले सूचीमा भएका कुरा मात्र जाँच्छ। राम्रो ग्रेडको अर्थ साइट "
    "पूर्ण रूपमा सुरक्षित छ भन्ने होइन — यो जाँचिएको कुराको नतिजा मात्र हो।"
)
