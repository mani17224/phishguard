"""
cli.py  —  PhishGuard Pro
Command-line URL threat analyzer with colored output.

Usage:
  python cli.py --url "http://paypal-secure.xyz/login"
  python cli.py --file data/sample_urls.txt
  python cli.py --url "https://google.com" --json
"""
import argparse, json, os, sys
sys.path.insert(0, os.path.dirname(__file__))

R="\033[91m"; Y="\033[93m"; G="\033[92m"; C="\033[96m"
B="\033[1m";  D="\033[2m";  X="\033[0m"

def col(text, *codes): return "".join(codes)+str(text)+X

def _color(tier): return {  "HIGH":R, "MEDIUM":Y, "LOW":G }.get(tier, D)

def print_result(r, as_json=False):
    if as_json: print(json.dumps(r, indent=2)); return
    tier = r.get("risk_tier","LOW")
    c    = _color(tier)
    prob = r.get("probability",0)*100
    print()
    print(col("─"*60, D))
    print(col("  URL:       ", B) + col(r.get("url","")[:70], D))
    print(col("  Verdict:   ", B) + col(r.get("verdict",""), c))
    print(col("  Risk:      ", B) + col(tier, c))
    print(col("  Phish Prob:", B) + col(f" {prob:.1f}%", c))
    print(col("  Latency:   ", B) + f"{r.get('latency_ms',0)}ms")
    sigs = r.get("signals",[])
    if sigs:
        print()
        print(col("  Signals:", B))
        icons = {"danger":"✗","warning":"!","safe":"✓","info":"i"}
        clrs  = {"danger":R, "warning":Y, "safe":G, "info":C}
        for s in sigs:
            ic = icons.get(s["type"],"·")
            print(f"    {col(ic, clrs.get(s['type'],D))}  {s['msg']}")
    top = r.get("top_features",[])
    if top:
        print()
        print(col("  Top Features:", B))
        for f in top:
            bar = "█"*int(f["importance"]*200) + "░"*max(0,12-int(f["importance"]*200))
            print(f"    {f['name']:<32} {col(bar,C)}  {f['value']}")
    print(col("─"*60, D))

def main():
    p = argparse.ArgumentParser(description="PhishGuard Pro CLI")
    p.add_argument("--url",  type=str)
    p.add_argument("--file", type=str)
    p.add_argument("--json", action="store_true")
    args = p.parse_args()

    if not args.url and not args.file:
        p.print_help(); sys.exit(1)

    model_path = os.path.join(os.path.dirname(__file__), "models", "model.pkl")
    if not os.path.exists(model_path):
        print(f"[ERROR] Model not found. Run: python train.py")
        sys.exit(1)

    from predictor import PhishingPredictor
    pred = PhishingPredictor()

    if args.url:
        print_result(pred.predict(args.url), args.json)

    elif args.file:
        if not os.path.exists(args.file):
            print(f"[ERROR] File not found: {args.file}"); sys.exit(1)
        with open(args.file) as f:
            urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        print(col(f"\nPhishGuard Pro — Batch ({len(urls)} URLs)\n", B))
        batch = pred.predict_batch(urls)
        if args.json:
            print(json.dumps(batch, indent=2))
        else:
            for r in batch["results"]: print_result(r)
            s = batch["summary"]
            print(col("SUMMARY", B))
            print(f"  Total:     {s['total']}")
            print(f"  Phishing:  {col(s['phishing'], R)}")
            print(f"  Legit:     {col(s['legitimate'], G)}")
            print(f"  High Risk: {col(s['high_risk'], R)}")

if __name__ == "__main__":
    main()
