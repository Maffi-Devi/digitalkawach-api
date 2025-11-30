from flask import Flask, request, jsonify
from flask_cors import CORS
from groq import Groq
import os
import re

app = Flask(__name__)
CORS(app)

groq_client = None

def get_groq_client():
    global groq_client
    if groq_client is None:
        api_key = os.environ.get('GROQ_API_KEY')
        if api_key:
            groq_client = Groq(api_key=api_key)
    return groq_client

SCAM_KEYWORDS = [
    'lottery', 'winner', 'prize', 'click here', 'urgent', 'act now',
    'free gift', 'congratulations', 'selected', 'claim', 'limited time',
    'verify account', 'suspended', 'password', 'otp', 'pin', 'cvv',
    'bank account', 'credit card', 'transfer money', 'kyc update',
    'aadhar', 'pan card', 'link expired', 'blocked', 'unblock',
    'cash prize', 'lucky draw', 'investment', 'double money', 'guaranteed returns',
    'work from home', 'earn money', 'loan approved', 'instant loan',
    'bitcoin', 'crypto', 'trading', 'forex'
]

WARNING_KEYWORDS = [
    'discount', 'offer', 'sale', 'deal', 'coupon', 'cashback',
    'subscribe', 'register', 'signup', 'download', 'install',
    'update', 'new version', 'app update', 'delivery', 'package'
]

SCAM_URL_PATTERNS = [
    r'bit\.ly', r'tinyurl', r'goo\.gl', r't\.co', r'ow\.ly',
    r'is\.gd', r'buff\.ly', r'adf\.ly', r'bc\.vc',
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$', r'\.gq$',
    r'login.*\.', r'secure.*\.', r'verify.*\.', r'update.*\.',
    r'bank.*\.(?!com)', r'account.*\.', r'password.*\.'
]

SCAM_PHONE_PREFIXES = ['140', '141', '142', '143', '144', '145', '146', '147', '148', '149']


def analyze_with_groq(prompt_type, content):
    """Use Groq AI for intelligent analysis"""
    client = get_groq_client()
    if not client:
        return None
    
    try:
        if prompt_type == "sms":
            system_prompt = """You are a fraud detection expert for Indian users. Analyze the SMS message and determine if it's a scam, suspicious, or safe.

Consider these fraud patterns:
- Fake bank/KYC/Aadhar/PAN update requests
- Lottery/prize winning scams
- Job/loan offer scams
- OTP/password phishing attempts
- Suspicious shortened URLs
- Urgency tactics to create panic

Respond in this exact JSON format only:
{
    "risk": "dangerous" or "warning" or "safe",
    "reason": "Brief explanation in Hindi-English mix (Hinglish) that a common person can understand",
    "details": "What the user should do next"
}"""
            user_prompt = f"Analyze this SMS message:\n\n{content}"
            
        elif prompt_type == "phone":
            system_prompt = """You are a phone number fraud detection expert for India. Analyze the phone number and determine its risk level.

Consider:
- Telemarketing prefixes (140-149)
- International numbers
- Virtual/VoIP numbers
- Known scam number patterns
- Number length validity

Respond in this exact JSON format only:
{
    "risk": "dangerous" or "warning" or "safe",
    "reason": "Brief explanation in Hindi-English mix (Hinglish)",
    "details": "What precautions the user should take"
}"""
            user_prompt = f"Analyze this phone number: {content}"
            
        elif prompt_type == "url":
            system_prompt = """You are a URL/link security expert. Analyze the URL and determine if it's safe to visit.

Consider:
- Shortened URLs hiding real destination
- Phishing domain patterns
- Typosquatting of famous brands
- IP address based URLs
- Suspicious subdomains
- Free domain extensions (.tk, .ml, etc.)

Respond in this exact JSON format only:
{
    "risk": "dangerous" or "warning" or "safe",
    "reason": "Brief explanation in Hindi-English mix (Hinglish)",
    "details": "Security advice for the user"
}"""
            user_prompt = f"Analyze this URL: {content}"
        else:
            return None

        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.3,
            max_tokens=500
        )
        
        result_text = response.choices[0].message.content.strip()
        
        import json
        if result_text.startswith("```json"):
            result_text = result_text[7:]
        if result_text.startswith("```"):
            result_text = result_text[3:]
        if result_text.endswith("```"):
            result_text = result_text[:-3]
        result_text = result_text.strip()
        
        result = json.loads(result_text)
        return {
            "risk": result.get("risk", "unknown"),
            "reason": result.get("reason", "Analysis complete"),
            "details": result.get("details", ""),
            "ai_powered": True
        }
        
    except Exception as e:
        print(f"Groq API error: {e}")
        return None


def analyze_text_basic(text):
    """Fallback basic keyword analysis"""
    text_lower = text.lower()
    
    scam_found = []
    warning_found = []
    
    for keyword in SCAM_KEYWORDS:
        if keyword in text_lower:
            scam_found.append(keyword)
    
    for keyword in WARNING_KEYWORDS:
        if keyword in text_lower:
            warning_found.append(keyword)
    
    url_pattern = r'https?://[^\s]+'
    urls = re.findall(url_pattern, text_lower)
    
    for url in urls:
        for pattern in SCAM_URL_PATTERNS:
            if re.search(pattern, url):
                scam_found.append(f"suspicious URL")
                break
    
    if len(scam_found) >= 2:
        return {
            "risk": "dangerous",
            "reason": f"Scam indicators found: {', '.join(scam_found[:3])}. Ye message fraud ho sakta hai!",
            "ai_powered": False
        }
    elif len(scam_found) == 1:
        return {
            "risk": "warning",
            "reason": f"Suspicious content: {scam_found[0]}. Savdhan rahein!",
            "ai_powered": False
        }
    elif len(warning_found) >= 2:
        return {
            "risk": "warning",
            "reason": f"Promotional message detected. Verify before responding.",
            "ai_powered": False
        }
    else:
        return {
            "risk": "safe",
            "reason": "Koi suspicious content nahi mila. Safe lagta hai.",
            "ai_powered": False
        }


def analyze_url_basic(url):
    """Fallback basic URL analysis"""
    url_lower = url.lower()
    
    scam_indicators = []
    
    for pattern in SCAM_URL_PATTERNS:
        if re.search(pattern, url_lower):
            scam_indicators.append("suspicious pattern")
    
    suspicious_words = ['login', 'secure', 'verify', 'bank', 'account', 'password', 'update', 'confirm']
    for word in suspicious_words:
        if word in url_lower and not any(legit in url_lower for legit in ['google.com', 'facebook.com', 'amazon.com', 'microsoft.com']):
            scam_indicators.append(f"suspicious word: {word}")
    
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
        scam_indicators.append("IP address URL")
    
    if url_lower.count('.') > 4:
        scam_indicators.append("too many subdomains")
    
    if len(scam_indicators) >= 2:
        return {
            "risk": "dangerous",
            "reason": "Ye link khatarnak ho sakta hai. Click mat karein!",
            "ai_powered": False
        }
    elif len(scam_indicators) == 1:
        return {
            "risk": "warning",
            "reason": "Is link mein kuch suspicious hai. Savdhan rahein.",
            "ai_powered": False
        }
    else:
        return {
            "risk": "safe",
            "reason": "Link safe lagta hai. Phir bhi verified sources se hi click karein.",
            "ai_powered": False
        }


def analyze_phone_basic(phone):
    """Fallback basic phone analysis"""
    phone_clean = re.sub(r'[^\d]', '', phone)
    
    for prefix in SCAM_PHONE_PREFIXES:
        if phone_clean.startswith(prefix):
            return {
                "risk": "dangerous",
                "reason": f"Ye telemarketing/spam number hai (prefix {prefix}). Call mat uthao!",
                "ai_powered": False
            }
    
    if phone_clean.startswith('00') or (len(phone_clean) > 10 and not phone_clean.startswith('91')):
        return {
            "risk": "warning",
            "reason": "International number hai. Pehchaan verify karein.",
            "ai_powered": False
        }
    
    if len(phone_clean) < 10:
        return {
            "risk": "warning",
            "reason": "Number ki length unusual hai.",
            "ai_powered": False
        }
    
    return {
        "risk": "safe",
        "reason": "Number normal lagta hai. Phir bhi unknown callers se savdhan rahein.",
        "ai_powered": False
    }


@app.route('/')
def home():
    groq_status = "connected" if get_groq_client() else "not configured"
    return jsonify({
        "status": "running",
        "app": "DigitalKawach Backend API",
        "version": "2.0.0",
        "groq_ai": groq_status,
        "endpoints": [
            "POST /classify-text - Analyze SMS text with AI",
            "POST /scan-url - Check URL safety with AI",
            "POST /check-phone - Verify phone number with AI",
            "POST /check-call - Real-time call fraud detection"
        ]
    })


@app.route('/classify-text', methods=['POST'])
def classify_text():
    try:
        data = request.get_json()
        if not data or 'text' not in data:
            return jsonify({"error": "Missing 'text' field"}), 400
        
        text = data['text']
        
        ai_result = analyze_with_groq("sms", text)
        if ai_result:
            return jsonify(ai_result)
        
        result = analyze_text_basic(text)
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/scan-url', methods=['POST'])
def scan_url():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "Missing 'url' field"}), 400
        
        url = data['url']
        
        ai_result = analyze_with_groq("url", url)
        if ai_result:
            return jsonify(ai_result)
        
        result = analyze_url_basic(url)
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/check-phone', methods=['POST'])
def check_phone():
    try:
        data = request.get_json()
        if not data or 'phone' not in data:
            return jsonify({"error": "Missing 'phone' field"}), 400
        
        phone = data['phone']
        
        ai_result = analyze_with_groq("phone", phone)
        if ai_result:
            return jsonify(ai_result)
        
        result = analyze_phone_basic(phone)
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/check-call', methods=['POST'])
def check_call():
    """Real-time call fraud detection endpoint"""
    try:
        data = request.get_json()
        if not data or 'phone' not in data:
            return jsonify({"error": "Missing 'phone' field"}), 400
        
        phone = data['phone']
        call_type = data.get('type', 'incoming')
        
        ai_result = analyze_with_groq("phone", phone)
        if ai_result:
            ai_result['call_type'] = call_type
            return jsonify(ai_result)
        
        result = analyze_phone_basic(phone)
        result['call_type'] = call_type
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
