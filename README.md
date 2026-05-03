# 🔮 Omega Leak Lab

> **Plateforme d'analyse forensique de leaks** — 15+ signaux statistiques + IA explicable

## ✨ Fonctionnalités
- 🎯 Scoring multi-signaux (entropie, Zipf, Benford, réseau...)
- 🔐 Détection MD5/SHA*/bcrypt + cracking rainbow tables
- 🧠 Modules ML : Isolation Forest, détection de datasets synthétiques
- 🧭 Explicabilité XAI : Comprendre *pourquoi* un verdict est donné
- 🎨 UI Cyberpunk + Visualisations Plotly interactives
- 📤 Export JSON/HTML prêt pour SOC/Threat Intel

## 🚀 Déploiement

### Local
```bash
git clone https://github.com/votre-user/omega-leak-lab
cd omega-leak-lab
pip install -r requirements.txt
streamlit run app.py