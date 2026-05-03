"""
╔════════════════════════════════════════════════════════════╗
║  ML MODULE — Anomaly Detection, XAI & Adversarial Testing  ║
╚════════════════════════════════════════════════════════════╝
"""
import numpy as np
import pandas as pd
import re
from sklearn.ensemble import IsolationForest
from typing import Dict, List

class DemonML:
    @staticmethod
    def detect_synthetic_patterns(df: pd.DataFrame, password_col: str) -> Dict:
        features = []
        passwords = df[password_col].dropna().astype(str).head(3000) if password_col in df.columns else []
        for pwd in passwords:
            features.append([
                len(pwd), sum(c.isdigit() for c in pwd), sum(c.islower() for c in pwd),
                sum(c.isupper() for c in pwd), sum(not c.isalnum() for c in pwd),
                len(re.findall(r'(.)\1{2,}', pwd)),
                1 if re.match(r'(123|abc|qwerty)', pwd.lower()) else 0
            ])
        if len(features) < 100: return {"naturality_score": 50, "anomalies": 0, "note": "Sample too small"}
        X = np.array(features)
        model = IsolationForest(contamination=0.1, random_state=42)
        preds = model.fit_predict(X)
        anomalies = (preds == -1).sum()
        naturality = max(0, 100 - anomalies / len(preds) * 200)
        return {"naturality_score": round(naturality, 1), "anomaly_count": int(anomalies), "anomaly_ratio": round(anomalies/len(preds)*100, 2)}

    @staticmethod
    def adversarial_robustness_test(results: Dict) -> Dict:
        robustness = 100
        vulns = []
        if results.get("cracked_count", 0) == 0:
            robustness -= 15; vulns.append("Aucun hash cracké — vulnérable aux faux négatifs")
        if results.get("pct_common_domains", 0) > 95:
            robustness -= 10; vulns.append("Trop de domaines communs — pattern suspect")
        ent = results.get("password_entropy_stats", {})
        if ent.get("max", 100) - ent.get("min", 0) < 5:
            robustness -= 20; vulns.append("Entropies trop uniformes — possible génération aléatoire")
        return {"robustness_score": max(0, robustness), "vulnerabilities": vulns, "recommendation": "Fiable" if robustness >= 70 else "À investiguer"}

class XAIExplainability:
    @staticmethod
    def explain_global_score(results: Dict) -> List[Dict]:
        signal_scores = results.get("signal_scores", {})
        weights = results.get("weights", {})
        contributions = []
        baseline = 50
        for signal, score in signal_scores.items():
            weight = weights.get(signal, 0.05)
            contribution = (score - baseline) * weight
            contributions.append({
                "signal": signal.replace("_", " ").title(),
                "score": score, "weight": round(weight * 100, 1),
                "contribution": round(contribution, 2),
                "direction": "▲" if contribution > 0 else "▼" if contribution < 0 else "●",
                "impact_abs": abs(contribution)
            })
        contributions.sort(key=lambda x: x["impact_abs"], reverse=True)
        return contributions[:5]

    @staticmethod
    def generate_narrative(results: Dict, explanations: List[Dict]) -> str:
        verdict = results.get("verdict", "UNKNOWN")
        score = results.get("global_score", 0)
        intro = {
            "AUTHENTIC": "🟢 Ce dataset présente des caractéristiques fortement cohérentes avec un leak authentique.",
            "PROBABLE": "🟡 Les indicateurs suggèrent une authenticité probable, mais certains signaux méritent vérification.",
            "SUSPICIOUS": "🟠 Plusieurs signaux d'alerte détectés — investigation manuelle recommandée.",
            "FAKE": "🔴 Le dataset présente des signatures typiques de fabrication artificielle."
        }
        top = [f"{e['direction']} {e['signal']} ({e['score']}/100)" for e in explanations[:3]]
        narrative = f"{intro.get(verdict, '')}\n\n"
        narrative += f"**Score global**: {score}/100 (confiance: {results.get('confidence', 'N/A')})\n\n"
        narrative += "**Facteurs clés influençant le verdict**:\n"
        for i, f in enumerate(top, 1): narrative += f"{i}. {f}\n"
        recs = {
            "AUTHENTIC": "✅ Dataset exploitable pour analyse threat intelligence.",
            "PROBABLE": "⚠️ Valider manuellement les signaux faibles avant exploitation.",
            "SUSPICIOUS": "🔍 Ne pas utiliser en production sans investigation approfondie.",
            "FAKE": "❌ Rejeter ce dataset — risque élevé de données synthétiques."
        }
        narrative += f"\n{recs.get(verdict, '')}"
        return narrative