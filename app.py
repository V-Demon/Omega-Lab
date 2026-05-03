"""
╔════════════════════════════════════════════════════════════╗
║  OMEGA LEAK LAB — Interface Streamlit                      ║
╚════════════════════════════════════════════════════════════╝
"""
import streamlit as st
import pandas as pd
from pathlib import Path
import json
import plotly.graph_objects as go

from core.analyzer import OmegaAnalyzer
from core.ml import DemonML, XAIExplainability
from ui.charts import create_radar, create_gauge, create_domain_bar, create_xai_waterfall

st.set_page_config(page_title="🔮 Omega Leak Lab", page_icon="🔮", layout="wide", initial_sidebar_state="expanded")

st.markdown("""<style>
.stApp { background: linear-gradient(135deg, #05080c 0%, #0a1018 100%); color: #b8c8d8; }
.signal-card { background: #0d1520; border-left: 3px solid #00aaff; padding: 10px 15px; margin: 5px 0; border-radius: 0 4px 4px 0; }
.verdict-banner { border: 2px solid var(--vcolor); border-radius: 12px; padding: 20px; text-align: center; box-shadow: 0 0 30px var(--vcolor)22; }
</style>""", unsafe_allow_html=True)

with st.sidebar:
    st.title("⚙️ Configuration")
    uploaded = st.file_uploader("📁 Charger un fichier de leak", type=["csv", "tsv", "txt", "json"])
    st.divider()
    sample_size = st.slider("📊 Lignes à analyser", 100, 100000, 10000, 100)
    auto_detect = st.checkbox("🔍 Auto-détection des colonnes", value=True)
    if not auto_detect:
        col1, col2, col3 = st.columns(3)
        u_col, e_col, p_col = col1.number_input("Username col", 0, 10, 0), col2.number_input("Email col", 0, 10, 1), col3.number_input("Password col", 0, 10, 2)
    else:
        u_col, e_col, p_col = 0, 1, 2
    st.divider()
    enable_ml = st.checkbox("🤖 Analyse ML (anomalies)", value=True)
    enable_xai = st.checkbox("🧠 Explicabilité (XAI)", value=True)

st.title("🔮 Omega Leak Lab")
st.markdown("*Analyse scientifique de leaks — 15+ signaux statistiques + IA explicable*")

if uploaded:
    progress_bar = st.progress(0)
    status_text = st.empty()
    try:
        status_text.text("📥 Chargement...")
        fname = uploaded.name.lower()
        if fname.endswith('.json'): df = pd.read_json(uploaded)
        elif fname.endswith('.tsv'): df = pd.read_csv(uploaded, sep='\t')
        else:
            sample = uploaded.readline().decode('utf-8', errors='ignore')
            uploaded.seek(0)
            delim = ',' if sample.count(',') > sample.count(';') else ';'
            df = pd.read_csv(uploaded, delimiter=delim, on_bad_lines='skip')
        progress_bar.progress(10)
        status_text.text(f"✅ {len(df):,} lignes chargées")

        with st.expander("👁️ Prévisualisation", expanded=False):
            st.dataframe(df.head(10), use_container_width=True)
            st.write(f"**Colonnes:** {list(df.columns)}")
        progress_bar.progress(20)

        status_text.text("🔮 Analyse Omega...")
        config = {'username_col': u_col, 'email_col': e_col, 'password_col': p_col}
        analyzer = OmegaAnalyzer(df, config)
        results = analyzer.analyze(sample_size=sample_size)
        progress_bar.progress(60)

        status_text.text("🧪 Modules ML...")
        if enable_ml:
            p_col_name = df.columns[p_col] if p_col < len(df.columns) else ''
            results["ml_analysis"] = DemonML.detect_synthetic_patterns(df, p_col_name)
            results["adversarial_test"] = DemonML.adversarial_robustness_test(results)
        if enable_xai:
            results["explanations"] = XAIExplainability.explain_global_score(results)
        progress_bar.progress(90)
        status_text.text("✨ Visualisations...")
        progress_bar.empty()
        status_text.empty()

        # VERDICT
        verdict, score, color, conf = results["verdict"], results["global_score"], results["verdict_color"], results["confidence"]
        st.markdown(f"""<div class="verdict-banner" style="--vcolor:{color};"><h1 style="color:{color};margin:0;font-size:48px;">{score}/100</h1><h2 style="color:{color};margin:5px 0;text-transform:uppercase;letter-spacing:3px;">{verdict}</h2><p style="color:#6a7a8a;">Confiance: {conf} • 15 signaux</p></div>""", unsafe_allow_html=True)
        st.plotly_chart(create_gauge(score, verdict, color), use_container_width=True)

        tab1, tab2, tab3, tab4 = st.tabs(["📊 Signaux", "🔐 Hashes", "📧 Emails", "🧠 ML & XAI"])
        with tab1:
            st.subheader("🎯 Radar des Signaux")
            st.plotly_chart(create_radar(results.get("signal_scores", {})), use_container_width=True)
            cols = st.columns(3)
            signals = [("🔓 Hashes Crackés", results.get("cracked_count", 0), "cracked_ratio"), ("🌐 Domaines Communs", f"{results.get('pct_common_domains',0):.1f}%", "domain_quality"), ("👤 Usernames Humains", f"{results.get('pct_human_usernames',0):.1f}%", "username_naturalness")]
            for i, (lbl, val, key) in enumerate(signals):
                s = results["signal_scores"].get(key, 50)
                c = "#00ff88" if s>=75 else "#ffcc00" if s>=55 else "#ff8800"
                with cols[i]: st.markdown(f"""<div class="signal-card" style="border-left-color:{c};"><div style="font-size:11px;color:#6a7a8a;">{lbl}</div><div style="font-size:24px;font-weight:bold;color:{c};">{val}</div><div style="font-size:10px;color:#6a7a8a;">Score: {s}/100</div></div>""", unsafe_allow_html=True)
        with tab2:
            st.subheader("🔐 Analyse des Hashes")
            hd = results.get("hash_distribution", {})
            if hd:
                fig = go.Figure(labels=list(hd.keys()), values=list(hd.values()), hole=0.4)
                fig.update_layout(paper_bgcolor='#05080c', font_color='#b8c8d8', height=350)
                st.plotly_chart(fig, use_container_width=True)
            for h, p in results.get("cracked_samples", []): st.code(f"{h} → {p}")
        with tab3:
            st.subheader("📧 Intelligence Emails")
            if results.get("domain_distribution"): st.plotly_chart(create_domain_bar(results["domain_distribution"]), use_container_width=True)
        with tab4:
            if enable_ml and "ml_analysis" in results:
                ml = results["ml_analysis"]
                st.metric("🎭 Naturality Score", f"{ml['naturality_score']:.1f}/100")
                st.metric("⚠️ Anomalies", ml["anomaly_count"])
            if "adversarial_test" in results:
                adv = results["adversarial_test"]
                st.warning(f"🛡️ Robustesse: {adv['robustness_score']}/100 | {len(adv['vulnerabilities'])} vulnérabilités")
            if enable_xai and "explanations" in results:
                st.plotly_chart(create_xai_waterfall(results["explanations"]), use_container_width=True)
                st.info(XAIExplainability.generate_narrative(results, results["explanations"]))
            
            if st.button("📄 Export JSON"):
                json_str = json.dumps(results, indent=2, default=str)
                st.download_button("⬇️ Télécharger", json_str, f"omega_report_{Path(uploaded.name).stem}.json", "application/json")
    except Exception as e:
        st.error(f"❌ Erreur: {str(e)}")
else:
    st.info("👆 Chargez un fichier CSV/TSV/TXT pour commencer")
    st.markdown("""### 🔮 Fonctionnalités\n✅ **15+ signaux statistiques** • ✅ **Détection hashes** • ✅ **Modules ML** • ✅ **Explicabilité XAI** • ✅ **100% local & privé**""")

st.markdown("<div style='text-align:center;color:#3a4a5a;font-size:10px;padding:20px;'>🔮 Omega Leak Lab v1.0 • Analyse statistique forensique • Usage légal uniquement</div>", unsafe_allow_html=True)
