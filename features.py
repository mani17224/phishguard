"""
features.py  —  PhishGuard Pro
Extract 35 ML features from a URL (lexical, host, semantic, typosquat).
"""
import re, math, urllib.parse
from collections import Counter

# ── Typosquat similarity ───────────────────────────────────────────
try:
    import jellyfish
    def _jaro(a, b): return jellyfish.jaro_winkler_similarity(a, b)
except ImportError:
    from difflib import SequenceMatcher
    def _jaro(a, b): return SequenceMatcher(None, a, b).ratio()

# ── Brand list (used for impersonation detection) ──────────────────
BRANDS = {
    "paypal","apple","google","amazon","microsoft","netflix","facebook",
    "instagram","twitter","linkedin","dropbox","chase","wellsfargo",
    "bankofamerica","citibank","hsbc","ebay","walmart","target",
    "visa","mastercard","stripe","github","slack","zoom","spotify",
    "coinbase","binance","robinhood","venmo","cashapp","barclays",
}

# ── Homoglyph substitution map ─────────────────────────────────────
HOMOGLYPHS = {
    "1":"l","0":"o","@":"a","4":"a","3":"e",
    "5":"s","$":"s","7":"t","+":"t","!":"i",
}

# ── High-risk TLDs (abused heavily by phishing campaigns) ──────────
SUSPICIOUS_TLDS = {
    "xyz","tk","ml","ga","cf","gq","pw","top","click","link","online",
    "site","icu","buzz","live","support","download","review","stream",
    "gdn","cam","loan","work","party","win","racing","date","faith",
}

# ── URL shorteners (neutral — not phishing, not legit) ─────────────
URL_SHORTENERS = {
    "bit","tinyurl","t","goo","ow","is","buff","rebrand",
    "cutt","tiny","rb","short","clck","qr",
}

# ── Legitimate domains (expanded — reduces false positives) ────────
LEGIT_DOMAINS = {
    # Search & tech
    "google","youtube","gmail","maps","drive","docs","play",
    "github","gitlab","stackoverflow","dev","medium","hashnode",
    "microsoft","azure","office","linkedin","outlook","bing",
    "apple","icloud","developer",
    # Social
    "facebook","instagram","twitter","reddit","tiktok","snapchat",
    "pinterest","tumblr","discord","telegram","whatsapp","signal",
    # Shopping & finance
    "amazon","ebay","walmart","target","shopify","etsy","bestbuy",
    "paypal","stripe","square","venmo","cashapp","chase","wellsfargo",
    "bankofamerica","citibank","barclays","hsbc","capitalone",
    # Streaming & media
    "netflix","spotify","youtube","twitch","hulu","disneyplus",
    "primevideo","soundcloud","bandcamp",
    # Cloud & infra
    "aws","cloudflare","digitalocean","heroku","vercel","netlify",
    "dropbox","onedrive","gdrive","notion","airtable",
    # News & reference
    "wikipedia","bbc","cnn","reuters","nytimes","theguardian",
    "techcrunch","wired","arstechnica","hackernews",
    # Other legit
    "zoom","slack","teams","atlassian","jira","confluence",
    "salesforce","hubspot","mailchimp","sendgrid","twilio",
    "npmjs","pypi","dockerhub","kubernetes",
}

# ── Sensitive keywords (login/credential harvest patterns) ─────────
KEYWORDS = {
    "login","signin","verify","secure","account","update","confirm",
    "banking","payment","credential","password","auth","authenticate",
    "recover","reset","unlock","suspend","validate","suspended",
    "limited","reactivate","billing","invoice","unusual","alert",
}

def _entropy(s):
    if not s: return 0.0
    f = Counter(s); n = len(s)
    return -sum((c/n)*math.log2(c/n) for c in f.values())

def _digit_ratio(s):
    return sum(1 for c in s if c.isdigit()) / len(s) if s else 0.0

def _vowel_ratio(s):
    letters = [c for c in s.lower() if c.isalpha()]
    return sum(1 for c in letters if c in "aeiou") / len(letters) if letters else 0.0

def _longest_word(s):
    tokens = re.findall(r"[a-zA-Z]+", s)
    return max((len(t) for t in tokens), default=0)

def _lev(a, b):
    if len(a) < len(b): return _lev(b, a)
    if not b: return len(a)
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a):
        curr = [i+1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(ca!=cb)))
        prev = curr
    return prev[-1]

def _normalize_hg(s):
    return "".join(HOMOGLYPHS.get(c, c) for c in s.lower())

def _ngram(a, b, n=2):
    ga = {a[i:i+n] for i in range(len(a)-n+1)}
    gb = {b[i:i+n] for i in range(len(b)-n+1)}
    if not ga or not gb: return 0.0
    return 2*len(ga&gb)/(len(ga)+len(gb))

def _typosquat_score(host):
    parts = host.lower().split(".")
    root  = parts[-2] if len(parts) >= 2 else parts[0]
    # Skip URL shorteners — they're not typosquatting
    if root in URL_SHORTENERS: return 0.0
    norm  = _normalize_hg(root)
    best  = 0.0
    for brand in BRANDS:
        if root == brand: return 0.0       # exact = legit
        lev = _lev(norm, brand)
        jw  = _jaro(norm, brand)
        bi  = _ngram(norm, brand)
        sim = (1 - min(lev,5)/5)*0.30 + jw*0.30 + bi*0.20
        if sim > best: best = sim
    return round(best, 4)

def _typosquat_detected(host):
    parts = host.lower().split(".")
    root  = parts[-2] if len(parts) >= 2 else parts[0]
    if root in URL_SHORTENERS: return 0
    norm  = _normalize_hg(root)
    for brand in BRANDS:
        if root == brand: return 0
        lev = _lev(norm, brand)
        jw  = _jaro(norm, brand)
        bi  = _ngram(norm, brand)
        sim = (1 - min(lev,5)/5)*0.30 + jw*0.30 + bi*0.20
        is_ts = (sim > 0.75 and norm != brand) or \
                (lev <= 2 and len(brand) >= 5 and norm != brand)
        if is_ts: return 1
    return 0

def _parse(url):
    try:
        # Handle non-http schemes gracefully
        if url.startswith("ftp://") or url.startswith("ftps://"):
            url = "http://" + url.split("://",1)[1]
        p     = urllib.parse.urlparse(url if "://" in url else "http://"+url)
        host  = p.hostname or ""
        parts = host.split(".")
        tld   = parts[-1] if parts else ""
        dom   = parts[-2] if len(parts) >= 2 else ""
        subs  = parts[:-2]
        return p.scheme, host, p.path, p.query, tld, dom, subs
    except Exception:
        return "","","","","","",[]

def extract_features(url: str) -> dict:
    """Extract 35 ML features from a URL."""
    scheme, host, path, query, tld, dom, subs = _parse(url)
    f        = {}
    sub_str  = ".".join(subs)
    url_l    = url.lower()

    # ── URL-level lexical (13) ─────────────────────────────────────
    f["url_length"]              = len(url)
    f["url_entropy"]             = round(_entropy(url), 4)
    f["num_dots"]                = url.count(".")
    f["num_hyphens"]             = url.count("-")
    f["num_underscores"]         = url.count("_")
    f["num_slashes"]             = url.count("/")
    f["num_at"]                  = url.count("@")
    f["num_question"]            = url.count("?")
    f["num_equals"]              = url.count("=")
    f["num_ampersand"]           = url.count("&")
    f["num_percent"]             = url.count("%")
    f["url_digit_ratio"]         = round(_digit_ratio(url), 4)
    f["longest_word"]            = _longest_word(url)

    # ── Host-level (9) ─────────────────────────────────────────────
    f["host_length"]             = len(host)
    f["host_entropy"]            = round(_entropy(host), 4)
    f["host_digit_ratio"]        = round(_digit_ratio(host), 4)
    f["host_vowel_ratio"]        = round(_vowel_ratio(host), 4)
    f["num_subdomains"]          = len(subs)
    f["has_ip"]                  = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) else 0
    f["suspicious_tld"]          = 1 if tld in SUSPICIOUS_TLDS else 0
    f["domain_length"]           = len(dom)
    f["domain_entropy"]          = round(_entropy(dom), 4)

    # ── Subdomain (2) ──────────────────────────────────────────────
    f["subdomain_length"]        = len(sub_str)
    # Brand in subdomain only fires when domain is NOT the brand itself
    f["brand_in_subdomain"]      = 1 if (
        any(b in sub_str.lower() for b in BRANDS) and dom.lower() not in BRANDS
    ) else 0

    # ── Path & query (4) ───────────────────────────────────────────
    f["path_length"]             = len(path)
    f["query_length"]            = len(query)
    f["num_query_params"]        = len(query.split("&")) if query else 0
    f["has_encoded_chars"]       = 1 if "%" in path or "%" in query else 0

    # ── Semantic (6) ───────────────────────────────────────────────
    f["sensitive_keyword_count"] = sum(1 for k in KEYWORDS if k in url_l)
    f["brand_in_domain"]         = 1 if any(b in dom.lower() for b in BRANDS) else 0
    f["brand_in_path"]           = 1 if any(b in (path+query).lower() for b in BRANDS) else 0
    f["is_https"]                = 1 if scheme == "https" else 0
    # known_legit: exact domain match OR known shortener
    f["known_legit_domain"]      = 1 if (
        dom.lower() in LEGIT_DOMAINS or dom.lower() in URL_SHORTENERS
    ) else 0
    f["is_url_shortener"]        = 1 if dom.lower() in URL_SHORTENERS else 0

    # ── Typosquat (2) ──────────────────────────────────────────────
    f["typosquat_score"]         = _typosquat_score(host)
    f["typosquat_detected"]      = _typosquat_detected(host)

    return f

FEATURE_NAMES = list(extract_features("https://example.com/test?q=1").keys())
