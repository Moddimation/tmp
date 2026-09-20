import itertools
import sys
import os
import random
import argparse
import encodings.idna
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
from threading import Semaphore

# ── charset definitions ────────────────────────────────────────────────────────
ASCII_CHARSET    = "abcdefghijklmnopqrstuvwxyz0123456789-_"
HIRAGANA_CHARSET = [chr(c) for c in range(0x3041, 0x3097)]
KATAKANA_CHARSET = [chr(c) for c in range(0x30A1, 0x30F7)]
KANJI_CHARSET    = [chr(c) for c in range(0x4E00, 0xA000)]

RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112"]

# ── default threads: cores * 10, min 10, fallback if cpu_count returns None ───
_cores          = os.cpu_count() or 2
DEFAULT_THREADS = max(_cores * 10, 10)

# ── args ───────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="DNS subdomain bruteforcer")
parser.add_argument("domain",                                        help="target domain")
parser.add_argument("-l", "--length",   type=int,   default=3,       help="max subdomain length (default 3)")
parser.add_argument("-p", "--procs",    type=int,   default=DEFAULT_THREADS, help=f"thread count (default {DEFAULT_THREADS}, derived from {_cores} cores)")
parser.add_argument("-t", "--timeout",  type=float, default=0.5,     help="DNS timeout in seconds (default 0.5)")
parser.add_argument("-j", "--japanese", action="store_true",         help="use hiragana+katakana charset")
parser.add_argument("-k", "--kanji",    action="store_true",         help="add kanji to charset (enormous search space)")
parser.add_argument("-r", "--resume",   type=str,   default=None,    help="resume from this prefix")
args = parser.parse_args()

TARGET  = args.domain
MAX_LEN = args.length
THREADS = args.procs
TIMEOUT = args.timeout
CHARSET = []
if args.japanese: CHARSET += HIRAGANA_CHARSET + KATAKANA_CHARSET
if args.kanji:    CHARSET += KANJI_CHARSET
if not CHARSET:   CHARSET  = list(ASCII_CHARSET)
RESUME  = args.resume.lower() if args.resume and not (args.japanese or args.kanji) else args.resume
PAD     = 20 + len(TARGET)

# ── helpers ────────────────────────────────────────────────────────────────────
sem      = Semaphore(THREADS * 2)
last_sub = None

def get_resolver(exclude=None):
    pool = [r for r in RESOLVERS if r != exclude] or RESOLVERS
    res = dns.resolver.Resolver()
    res.nameservers = [random.choice(pool)]
    res.timeout     = TIMEOUT
    res.lifetime    = TIMEOUT
    return res

def to_fqdn(sub):
    if sub.isascii():
        return f"{sub}.{TARGET}"
    try:
        encoded = ".".join(
            encodings.idna.ToASCII(label).decode()
            for label in sub.split(".")
        )
        return f"{encoded}.{TARGET}"
    except Exception:
        return None

def charset_key(s):
    return tuple(CHARSET.index(c) for c in s if c in CHARSET)

def check(sub):
    global last_sub
    last_sub = sub
    try:
        fqdn = to_fqdn(sub)
        if fqdn is None:
            return None
        col = f"{sub}.{TARGET}"
        col = f"{col:<{PAD}}"

        last_ns = None
        for attempt in range(len(RESOLVERS)):
            r = get_resolver(exclude=last_ns)
            last_ns = r.nameservers[0]
            try:
                ans = r.resolve(fqdn, "A")
                ips = ", ".join(str(rr) for rr in ans)
                print(f"[+] {col} -> NOERROR A {ips} (TTL {ans.ttl})", flush=True)
                return fqdn
            except dns.resolver.NXDOMAIN:
                return None
            except dns.resolver.NoAnswer:
                print(f"[~] {col} -> NOERROR (no A record)", flush=True)
                return None
            except dns.resolver.NoNameservers:
                return None
            except dns.resolver.Timeout:
                continue  # retry with different resolver
            except dns.exception.DNSException as e:
                print(f"[d] {col} -> DNSException {type(e).__name__}: {e}", flush=True)
                return None
            except Exception as e:
                print(f"[!] {col} -> {type(e).__name__}: {e}", flush=True)
                return None

        # exhausted all resolvers
        print(f"[?] {col} -> TIMEOUT (all resolvers exhausted)", flush=True)
        return None
    finally:
        sem.release()

def gen_subs():
    resume_key = charset_key(RESUME) if RESUME else None
    resume_len = len(RESUME)         if RESUME else 0

    for length in range(1, MAX_LEN + 1):
        if resume_key and length < resume_len:
            continue

        for combo in itertools.product(CHARSET, repeat=length):
            s = "".join(combo)

            if resume_key and length == resume_len:
                if charset_key(s) < resume_key:
                    continue
                else:
                    resume_key = None

            yield s

# ── main ───────────────────────────────────────────────────────────────────────
print(f"[*] Target    : {TARGET}")
print(f"[*] Length    : 1-{MAX_LEN}")
print(f"[*] Threads   : {THREADS} (from {_cores} cores)")
print(f"[*] Timeout   : {TIMEOUT}s (retries across {len(RESOLVERS)} resolvers)")
print(f"[*] Resolvers : {', '.join(RESOLVERS)}")
charset_desc = "+".join(filter(None, [
    "hiragana+katakana" if args.japanese else "",
    "kanji"             if args.kanji    else "",
    ""                  if (args.japanese or args.kanji) else "ASCII"
]))
print(f"[*] Charset   : {charset_desc} ({len(CHARSET)} chars)")
if args.kanji and MAX_LEN > 1:
    print(f"[!] Warning   : kanji at length {MAX_LEN} = {len(KANJI_CHARSET)**MAX_LEN:,} combinations")
if RESUME:
    print(f"[*] Resuming from: {RESUME}")
print()

try:
    with ThreadPoolExecutor(max_workers=THREADS) as pool:
        for s in gen_subs():
            sem.acquire()
            pool.submit(check, s)
except KeyboardInterrupt:
    flags = ""
    if args.japanese: flags += " -j"
    if args.kanji:    flags += " -k"
    print(f"\n[~] Interrupted near : {last_sub}")
    print(f"[~] Resume with      : {sys.argv[0]} {TARGET} -l {MAX_LEN} -p {THREADS} -t {TIMEOUT}{flags} -r {last_sub}")
    sys.exit(0)
