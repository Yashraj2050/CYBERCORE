"""
CYBERCORE Backend — AI Cybersecurity Assistant Service

Provides intelligent cybersecurity explanations and threat triage.
Supports OpenAI / Google Gemini API when configured, with an offline
high-fidelity cybersecurity expert knowledge base as a zero-failure fallback.
"""

import logging
from typing import Optional, List, Dict
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

SYSTEM_PROMPT = """You are CYBERCORE AI, an expert cybersecurity assistant and digital safety advisor.
Your mission is to help everyday users, developers, and security professionals identify online scams,
phishing attacks, malicious websites, credential risks, and cyber threats.
Always provide actionable, clear, calm, and protective guidance.
Never generate exploit code or provide instructions on how to attack systems."""

SUGGESTED_QUESTIONS = [
    "How can I tell if an email or SMS asking for an OTP is a scam?",
    "What should I do immediately if I clicked a suspicious link?",
    "Why does CYBERCORE warn against using passwords with personal info?",
    "How does a multi-factor authentication (MFA) protect against credential theft?",
    "What is typosquatting and how do attackers spoof real company websites?",
    "Is public Wi-Fi safe for online banking without a VPN?",
]

# Knowledge base for offline fallback
KNOWLEDGE_BASE = [
    {
        "keywords": ["clicked", "suspicious link", "clicked link", "opened link", "phished"],
        "answer": """**Immediate Action Plan if You Clicked a Suspicious Link:**

1. **Disconnect from the Network:** Turn off Wi-Fi or unplug Ethernet immediately if you suspect a file was downloaded.
2. **Do NOT Enter Any Credentials:** If the page asked for login, password, or OTP, never submit it.
3. **Change Compromised Passwords:** If you submitted your password, immediately change it from a different, trusted device. Enable 2-Factor Authentication (2FA).
4. **Scan Your Device:** Run a comprehensive scan with reputable antivirus or Windows Defender.
5. **Check Recent Downloads:** Inspect your Downloads folder for recently saved `.exe`, `.scr`, `.bat`, or `.iso` files and delete them without opening.
6. **Monitor Financial Accounts:** If banking details or cards were involved, notify your bank immediately to freeze the card or account."""
    },
    {
        "keywords": ["otp", "one time password", "share otp", "bank otp", "kyc"],
        "answer": """**Critical Rule About OTPs:**

**Legitimate banks, payment gateways, and organizations NEVER call or message you asking for your OTP.**

- Scammers frequently pose as bank representatives claiming your "KYC is expiring", "card is blocked", or "unauthorized transaction needs cancellation".
- Sharing the OTP gives attackers full access to transfer funds or authenticate logins.
- If anyone asks for your OTP, immediately hang up, block their number, and contact your bank using the official phone number on the back of your card."""
    },
    {
        "keywords": ["password", "strong password", "generator", "passphrase", "reuse"],
        "answer": """**CYBERCORE Password Security Principles:**

1. **Length Beats Complexity:** A 16+ character passphrase like `solar-granite-blue-meadow` is astronomically harder to crack than `P@ss123`.
2. **Never Reuse Passwords:** If one site gets breached, attackers use credential stuffing across all other services (email, banking, social media).
3. **Use a Password Manager:** Bitwarden, 1Password, or Apple Keychain generate and store unique, strong credentials for every site.
4. **Always Enable 2FA:** Prefer Authenticator Apps (Google Authenticator, Microsoft Authenticator) or hardware security keys over SMS verification."""
    },
    {
        "keywords": ["typosquatting", "lookalike", "fake domain", "homograph"],
        "answer": """**Understanding Typosquatting and Domain Spoofing:**

Attackers register domains that look almost identical to trusted brands to trick users:
- **Character substitution:** `paypa1.com` instead of `paypal.com` (using `1` instead of `l`).
- **Omission/Addition:** `amazn.com` or `netflix-verify.com`.
- **Combosquatting:** Adding terms like `login-`, `secure-`, or `-support` (e.g. `chase-security-login.com`).
- **Homograph attacks:** Using lookalike characters from other alphabets (Cyrillic `а` instead of Latin `a`).

CYBERCORE inspects domain registration age, DNS entries, and character entropy to detect these attacks before you enter data."""
    },
    {
        "keywords": ["public wifi", "vpn", "coffee shop", "hotel wifi", "airport wifi"],
        "answer": """**Public Wi-Fi Safety Guide:**

Public networks in hotels, cafes, and airports carry risks of **Man-in-the-Middle (MitM)** attacks and **Evil Twin** fake hotspots:
1. **Verify HTTPS:** Ensure websites display the padlock and valid SSL certificate.
2. **Use a Reputable VPN:** Encrypts all traffic between your device and the internet, preventing anyone on the local Wi-Fi from inspecting your packet stream.
3. **Turn Off File Sharing:** Disable AirDrop / file sharing and set your network profile to 'Public'.
4. **Avoid Sensitive Transactions:** Save banking and sensitive account logins for cellular data (4G/5G) or a trusted private network."""
    }
]


async def generate_ai_response(prompt: str, chat_history: Optional[List[Dict[str, str]]] = None) -> str:
    """Generate intelligent response using LLM or fallback knowledge base."""
    clean_prompt = prompt.strip().lower()

    # Try Gemini if key is provided and valid
    if settings.gemini_api_key and not settings.gemini_api_key.startswith("your-"):
        try:
            import google.generativeai as genai
            genai.configure(api_key=settings.gemini_api_key)
            model = genai.GenerativeModel(
                model_name=settings.ai_model or "gemini-1.5-flash",
                system_instruction=SYSTEM_PROMPT
            )
            response = await model.generate_content_async(prompt)
            if response and response.text:
                return response.text
        except Exception as e:
            logger.warning("Gemini AI API error: %s; falling back to knowledge base", str(e))

    # Try OpenAI if key is provided and valid
    if settings.openai_api_key and not settings.openai_api_key.startswith("your-"):
        try:
            from openai import AsyncOpenAI
            client = AsyncOpenAI(api_key=settings.openai_api_key)
            messages = [{"role": "system", "content": SYSTEM_PROMPT}]
            if chat_history:
                for msg in chat_history[-6:]:
                    messages.append({"role": msg.get("role", "user"), "content": msg.get("content", "")})
            messages.append({"role": "user", "content": prompt})

            completion = await client.chat.completions.create(
                model=settings.ai_model or "gpt-4o-mini",
                messages=messages,
                max_tokens=600,
            )
            ans = completion.choices[0].message.content
            if ans:
                return ans
        except Exception as e:
            logger.warning("OpenAI API error: %s; falling back to knowledge base", str(e))

    # Knowledge Base Fallback
    for item in KNOWLEDGE_BASE:
        if any(kw in clean_prompt for kw in item["keywords"]):
            return item["answer"]

    # General expert fallback
    return f"""**CYBERCORE Safety Assessment:**

Thank you for consulting CYBERCORE AI regarding your digital security query.

Key Protective Guidelines:
1. **Verify Before Trusting:** Never trust unsolicited messages, unexpected attachments, or urgent demands for verification.
2. **Inspect URLs Carefully:** Look at the exact domain name before entering credentials. Pay attention to subdomains and unusual top-level domains (.xyz, .top, .ru).
3. **Protect Authentication Secrets:** Never disclose OTPs, PINs, or passwords to anyone, even if they claim to represent technical support or law enforcement.
4. **Use CYBERCORE Tools:** You can run any suspicious link through the **CYBERCORE Website Scanner**, analyze suspicious messages with the **Message Scanner**, or verify suspicious files in the **File Security** module.

Stay alert and browse safely!"""
