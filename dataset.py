"""
dataset.py  —  PhishGuard Pro
Generates a balanced synthetic dataset of phishing + legitimate URLs.
Run:  python dataset.py
"""
import random, string, json, os

random.seed(42)

LEGIT = [
    "google.com","youtube.com","facebook.com","twitter.com","instagram.com",
    "linkedin.com","github.com","microsoft.com","apple.com","amazon.com",
    "netflix.com","reddit.com","wikipedia.org","stackoverflow.com","medium.com",
    "dropbox.com","slack.com","zoom.us","spotify.com","airbnb.com",
    "paypal.com","ebay.com","shopify.com","stripe.com","cloudflare.com",
    "accounts.google.com","mail.google.com","docs.google.com","developer.apple.com",
]
LEGIT_PATHS = [
    "/","/login","/signin","/home","/dashboard","/profile","/settings",
    "/search?q=python","/api/v1/users","/docs/getting-started","/about",
    "/products/details/123","/news/latest","/blog/2024-updates",
]
PHISH_BRANDS = [
    "paypal","apple","google","amazon","microsoft","netflix","facebook",
    "instagram","twitter","linkedin","dropbox","chase","wellsfargo","bankofamerica",
]
SUS_TLDS   = ["xyz","tk","ml","ga","cf","gq","pw","top","click","link","online","site","icu","live"]
LEGIT_TLDS = ["com","org","net","io","co"]

def _rs(n, chars=string.ascii_lowercase): return "".join(random.choices(chars, k=n))
def _hex(n): return "".join(random.choices("0123456789abcdef", k=n))

def _legit_url():
    return f"https://{random.choice(LEGIT)}{random.choice(LEGIT_PATHS)}"

def _phish_url():
    strat = random.choice(["typo","subdomain","ip","encoded","sus_tld","homoglyph","harvest"])
    b = random.choice(PHISH_BRANDS)
    if strat == "typo":
        variants = [f"{b}-secure",f"secure-{b}",f"{b}-login",f"{b}1",f"my{b}",f"{b}-verify"]
        return f"http://{random.choice(variants)}.{random.choice(SUS_TLDS)}/login"
    if strat == "subdomain":
        att = _rs(random.randint(5,12))
        return f"http://{b}.secure.{att}.{random.choice(SUS_TLDS)}/account/login?redirect={_hex(16)}"
    if strat == "ip":
        ip = f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        return f"http://{ip}/login?redirect={_hex(20)}"
    if strat == "encoded":
        d = _rs(random.randint(10,20))
        return f"http://{d}.{random.choice(SUS_TLDS)}/{b}/auth?data={_hex(32)}&token={_hex(16)}"
    if strat == "sus_tld":
        return f"http://{b}-account.{random.choice(SUS_TLDS)}/update-payment"
    if strat == "homoglyph":
        subs = {"a":"4","e":"3","i":"1","o":"0","l":"1"}
        mangled = "".join(subs.get(c, c) for c in b)
        return f"http://{mangled}.{random.choice(LEGIT_TLDS)}/login"
    # harvest
    fake = _rs(random.randint(8,14))
    return f"http://{fake}.{random.choice(SUS_TLDS)}/{b}/harvest?user=victim@email.com&csrf={_hex(20)}"

def generate(n_legit=2000, n_phish=2000):
    data = [{"url":_legit_url(),"label":0} for _ in range(n_legit)] + \
           [{"url":_phish_url(),"label":1} for _ in range(n_phish)]
    random.shuffle(data)
    return data

if __name__ == "__main__":
    data = generate()
    out  = os.path.join(os.path.dirname(__file__), "data", "dataset.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f: json.dump(data, f)
    print(f"Generated {len(data)} samples → {out}")
    print(f"  Legit: {sum(1 for d in data if d['label']==0)}")
    print(f"  Phish: {sum(1 for d in data if d['label']==1)}")
