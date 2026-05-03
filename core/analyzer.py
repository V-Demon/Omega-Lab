"""
╔════════════════════════════════════════════════════════════╗
║  OMEGA CORE — Moteur d'analyse multi-signaux (Streamlit)   ║
║  Adapté depuis Omega Leak Analyzer v3.0                    ║
╚════════════════════════════════════════════════════════════╝
"""
import re
import math
import hashlib
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Optional, Any
from functools import lru_cache
import pandas as pd
import numpy as np

# ─────────────────────────────────────────────────────────────
#  CORPUS & CONSTANTES
# ─────────────────────────────────────────────────────────────
TOP_PASSWORDS = [
    "123456","password","123456789","qwerty","abc123","111111","12345678","12345",
    "1234567","1234567890","admin","letmein","monkey","dragon","master","sunshine",
    "princess","welcome","shadow","superman","michael","football","charlie","donald",
    "password1","qwerty123","123123","654321","hello","freedom","whatever","qazwsx",
    "trustno1","baseball","batman","access","mustang","696969","ashley","bailey",
    "passw0rd","password123","hunter2","000000","pass","love","jessica","zxcvbn",
    "starwars","login","solo","qwertyuiop","robert","matthew","jordan","harley",
    "ranger","iwantu","thomas","andrew","sunshine1","angel1","babygirl1","daniel",
    "master1","password01","123qwe","111222333","1q2w3e","zxcvbnm","1qaz2wsx",
    "passer","pass1234","pass123","test","guest","root","toor","admin123","changeme",
    "Password1","P@ssw0rd","Pa$$w0rd","abc@123","Welcome1","qwerty1","asdfgh","azerty",
    "azerty123","soleil","bonjour","france","paris","marseille","amour","xxxxxx",
    "11111111","22222222","33333333","55555555","7777777","88888888","99999999","00000000"
]

_KNOWN_MD5 = {hashlib.md5(p.encode()).hexdigest(): p for p in TOP_PASSWORDS}
_KNOWN_SHA1 = {hashlib.sha1(p.encode()).hexdigest(): p for p in TOP_PASSWORDS}
_KNOWN_SHA256 = {hashlib.sha256(p.encode()).hexdigest(): p for p in TOP_PASSWORDS}

RE_EMAIL = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
RE_MD5 = re.compile(r'^[0-9a-fA-F]{32}$')
RE_SHA1 = re.compile(r'^[0-9a-fA-F]{40}$')
RE_SHA256 = re.compile(r'^[0-9a-fA-F]{64}$')
RE_BCRYPT = re.compile(r'^\$2[aby]\$\d{2}\$.{53}$')

COMMON_DOMAINS = frozenset([
    "gmail.com","yahoo.com","hotmail.com","outlook.com","icloud.com","aol.com",
    "live.com","orange.fr","free.fr","sfr.fr","laposte.net","protonmail.com"
])

# ─────────────────────────────────────────────────────────────
#  UTILITAIRES STATISTIQUES
# ─────────────────────────────────────────────────────────────
@lru_cache(maxsize=2048)
def cached_entropy(s: str) -> float:
    if not s: return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c/length) * math.log2(c/length) for c in freq.values())

def shannon_entropy_norm(counter: Counter) -> float:
    total = sum(counter.values())
    if total <= 1: return 0.0
    entropy = -sum((c/total) * math.log2(c/total) for c in counter.values() if c > 0)
    max_entropy = math.log2(len(counter))
    return entropy / max_entropy if max_entropy > 0 else 0.0

def detect_hash_type(h: str) -> str:
    h = h.strip()
    if not h: return "empty"
    if RE_BCRYPT.match(h): return "bcrypt"
    if RE_SHA256.match(h): return "sha256"
    if RE_SHA1.match(h): return "sha1"
    if RE_MD5.match(h): return "md5"
    if len(h) < 8: return "plaintext_short"
    if len(h) <= 50 and not re.match(r'^[0-9a-fA-F]+$', h): return "plaintext"
    return "unknown"

def is_sequential(s: str) -> bool:
    if len(s) < 3: return False
    if s.isdigit():
        diffs = [int(s[i+1]) - int(s[i]) for i in range(len(s)-1)]
        return len(set(diffs)) == 1 and abs(diffs[0]) <= 1
    if s.isalpha():
        diffs = [ord(s[i+1].lower()) - ord(s[i].lower()) for i in range(len(s)-1)]
        return len(set(diffs)) == 1 and abs(diffs[0]) == 1
    return False

# ─────────────────────────────────────────────────────────────
#  CLASSE ANALYZER
# ─────────────────────────────────────────────────────────────
class OmegaAnalyzer:
    def __init__(self, df: pd.DataFrame, config: Dict = None):
        self.df = df
        self.config = config or {}
        self.u_col = config.get('username_col', 0)
        self.e_col = config.get('email_col', 1)
        self.p_col = config.get('password_col', 2)

    def analyze(self, sample_size: int = 10000) -> Dict[str, Any]:
        df = self.df.head(sample_size) if sample_size else self.df
        results = {}
        results.update(self._basic_stats(df))
        results.update(self._analyze_hashes(df))
        results.update(self._analyze_emails(df))
        results.update(self._analyze_usernames(df))
        results.update(self._analyze_passwords(df))
        results.update(self._compute_scores(results))
        return results

    def _basic_stats(self, df: pd.DataFrame) -> Dict:
        return {
            "total_rows": len(df),
            "valid_rows": df.dropna(how='all').shape[0],
            "missing_ratio": round(df.isna().mean().mean(), 4),
            "duplicate_ratio": round(df.duplicated().mean(), 4),
        }

    def _analyze_hashes(self, df: pd.DataFrame) -> Dict:
        p_col = df.columns[self.p_col] if self.p_col < len(df.columns) else None
        if p_col is None: return {"hash_analysis": "No password column"}
        passwords = df[p_col].dropna().astype(str)
        hash_types = Counter()
        cracked = []
        for pwd in passwords.head(5000):
            htype = detect_hash_type(pwd)
            hash_types[htype] += 1
            lookup_map = {"md5": _KNOWN_MD5, "sha1": _KNOWN_SHA1, "sha256": _KNOWN_SHA256}
            if htype in lookup_map:
                plain = lookup_map[htype].get(pwd.lower())
                if plain: cracked.append((pwd[:18]+"...", plain))
        total = sum(hash_types.values()) or 1
        return {
            "hash_distribution": dict(hash_types),
            "cracked_count": len(cracked),
            "cracked_samples": cracked[:10],
            "pct_plaintext": hash_types.get("plaintext", 0) / total * 100,
            "pct_modern": sum(hash_types.get(h, 0) for h in ["bcrypt","argon2","scrypt"]) / total * 100,
        }

    def _analyze_emails(self, df: pd.DataFrame) -> Dict:
        e_col = df.columns[self.e_col] if self.e_col < len(df.columns) else None
        if e_col is None: return {"email_analysis": "No email column"}
        emails = df[e_col].dropna().astype(str)
        domains, tlds = Counter(), Counter()
        invalid, common_cnt = 0, 0
        for email in emails.head(5000):
            if RE_EMAIL.match(email):
                parts = email.split('@')
                if len(parts)==2:
                    domains[parts[1].lower()] += 1
                    tlds[parts[1].split('.')[-1]] += 1
                    if parts[1].lower() in COMMON_DOMAINS: common_cnt += 1
            else: invalid += 1
        total = len(emails) or 1
        return {
            "unique_emails": len(set(emails)),
            "domain_distribution": dict(domains.most_common(15)),
            "tld_distribution": dict(tlds.most_common(10)),
            "domain_entropy": round(shannon_entropy_norm(domains), 4),
            "pct_common_domains": round(common_cnt / total * 100, 2),
            "invalid_email_ratio": round(invalid / total, 4),
        }

    def _analyze_usernames(self, df: pd.DataFrame) -> Dict:
        u_col = df.columns[self.u_col] if self.u_col < len(df.columns) else None
        if u_col is None: return {"username_analysis": "No username column"}
        usernames = df[u_col].dropna().astype(str).head(3000)
        human = sum(1 for u in usernames if re.match(r'^[a-zA-Z]{2,}(?:\d{1,4})?$', u))
        generated = sum(1 for u in usernames if re.match(r'^[a-zA-Z0-9]{20,}$|^[0-9a-f]{12,}$|^user\d{5,}$', u))
        total = len(usernames) or 1
        return {
            "pct_human_usernames": round(human/total*100, 2),
            "pct_generated_usernames": round(generated/total*100, 2),
            "unique_usernames": len(set(usernames)),
        }

    def _analyze_passwords(self, df: pd.DataFrame) -> Dict:
        p_col = df.columns[self.p_col] if self.p_col < len(df.columns) else None
        if p_col is None: return {"password_analysis": "No password column"}
        passwords = df[p_col].dropna().astype(str).head(3000)
        plaintext = [p for p in passwords if len(p) <= 50 and p.isprintable()]
        if not plaintext: return {"avg_password_entropy": 0, "password_entropy_stats": {}}
        entropies = [cached_entropy(p) for p in plaintext]
        seq = sum(1 for p in plaintext if is_sequential(p))
        return {
            "password_entropy_stats": {
                "mean": round(np.mean(entropies), 2), "median": round(np.median(entropies), 2),
                "min": round(min(entropies), 2), "max": round(max(entropies), 2)
            },
            "avg_password_length": round(np.mean([len(p) for p in plaintext]), 2),
            "pct_sequential": round(seq/len(plaintext)*100, 2),
            "unique_passwords": len(set(plaintext))
        }

    def _compute_scores(self, results: Dict) -> Dict:
        w = {
            "cracked_ratio": 0.15, "domain_quality": 0.12, "username_naturalness": 0.10,
            "duplicate_realism": 0.08, "hash_modernity": 0.08, "entropy_plausibility": 0.08,
            "network_structure": 0.07, "cultural_consistency": 0.05, "canary_absence": 0.05,
            "temporal_patterns": 0.04, "tld_validity": 0.03, "sequentiality_balance": 0.03
        }
        scores = {}
        total = max(results.get("valid_rows", 1), 1)
        cracked_pct = results.get("cracked_count", 0) / total * 100
        scores["cracked_ratio"] = 85 if 0.5 <= cracked_pct <= 12 else 40
        pct_common = results.get("pct_common_domains", 0)
        scores["domain_quality"] = 70 + min(30, (pct_common - 40) * 0.6) if pct_common > 40 else 40
        pct_human = results.get("pct_human_usernames", 50)
        scores["username_naturalness"] = min(100, 50 + pct_human * 0.5)
        scores["entropy_plausibility"] = 75 if 20 <= results.get("password_entropy_stats", {}).get("mean", 0) <= 50 else 45
        scores["sequentiality_balance"] = 75 if 2 <= results.get("pct_sequential", 0) <= 15 else 45
        scores["hash_modernity"] = 80 if results.get("pct_modern", 0) > 20 else 50
        global_score = sum(scores.get(k, 50) * w[k] for k in w)
        if global_score >= 75: verdict, color, conf = "AUTHENTIC", "#00ff88", "HIGH"
        elif global_score >= 55: verdict, color, conf = "PROBABLE", "#ffcc00", "MEDIUM"
        elif global_score >= 35: verdict, color, conf = "SUSPICIOUS", "#ff8800", "LOW"
        else: verdict, color, conf = "FAKE", "#ff3333", "HIGH"
        return {
            "global_score": round(global_score, 1), "verdict": verdict,
            "verdict_color": color, "confidence": conf,
            "signal_scores": scores, "weights": w
        }