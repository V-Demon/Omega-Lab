"""
Visualisations interactives Plotly — Thème Omega Dark
"""
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

OMEGA = {'paper_bg': '#05080c', 'plot_bg': '#0a1018', 'font': '#b8c8d8', 'grid': '#1a2a3a', 'accent': '#00aaff'}

def create_radar(signal_scores: dict) -> go.Figure:
    cats = list(signal_scores.keys())[:12]
    vals = [signal_scores.get(c, 50) for c in cats] + [signal_scores.get(cats[0], 50)]
    fig = go.Figure(go.Scatterpolar(r=vals, theta=cats + [cats[0]], fill='toself', line_color=OMEGA['accent'], fillcolor='rgba(0,170,255,0.15)'))
    fig.update_layout(polar=dict(radialaxis=dict(visible=True, range=[0,100], gridcolor=OMEGA['grid']), bgcolor=OMEGA['plot_bg']), showlegend=False, paper_bgcolor=OMEGA['paper_bg'], font_color=OMEGA['font'], height=400)
    return fig

def create_gauge(score: float, verdict: str, color: str) -> go.Figure:
    fig = go.Figure(go.Indicator(mode="gauge+number+delta", value=score, domain={'x': [0, 1], 'y': [0, 1]}, title={'text': f"Verdict: {verdict}", 'font': {'size': 16, 'color': color}}, gauge={'axis': {'range': [0,100], 'tickwidth': 2, 'tickcolor': OMEGA['grid']}, 'bar': {'color': color}, 'bgcolor': OMEGA['plot_bg'], 'steps': [{'range':[0,35],'color':'rgba(255,51,51,0.1)'},{'range':[35,55],'color':'rgba(255,136,0,0.1)'},{'range':[55,75],'color':'rgba(255,204,0,0.1)'},{'range':[75,100],'color':'rgba(0,255,136,0.1)'}], 'threshold':{'line':{'color':color,'width':4},'thickness':0.75,'value':score}}))
    fig.update_layout(paper_bgcolor=OMEGA['paper_bg'], font_color=OMEGA['font'], height=250, margin=dict(l=20,r=20,t=40,b=20))
    return fig

def create_domain_bar(domain_dist: dict) -> go.Figure:
    df = pd.DataFrame([{"domain": k, "count": v} for k,v in list(domain_dist.items())[:15]])
    fig = px.bar(df, x="count", y="domain", orientation='h', title="📧 Top Domaines Email")
    fig.update_layout(paper_bgcolor=OMEGA['paper_bg'], plot_bgcolor=OMEGA['plot_bg'], font_color=OMEGA['font'], xaxis_gridcolor=OMEGA['grid'], yaxis_gridcolor=OMEGA['grid'], showlegend=False, height=400)
    return fig

def create_xai_waterfall(explanations: list) -> go.Figure:
    labels = [e['signal'] for e in explanations]
    contributions = [e['contribution'] for e in explanations]
    fig = go.Figure(go.Waterfall(orientation="v", measure=["relative"]*len(labels), x=labels, y=contributions, connector={"line":{"color":"#3a4a5a"}}, decreasing={"marker":{"color":"#ff3333"}}, increasing={"marker":{"color":"#00ff88"}}, textposition="outside", text=[f"{c:+.1f}" for c in contributions]))
    fig.update_layout(title="🧠 Contribution des signaux au score global", plot_bgcolor='#0a1018', paper_bgcolor='#05080c', font_color='#b8c8d8', height=300, yaxis=dict(gridcolor='#1a2a3a'), xaxis=dict(gridcolor='#1a2a3a'))
    return fig