from __future__ import annotations

import io
from pathlib import Path

import pandas as pd
import streamlit as st

from ip_utils import normalize_ip

st.set_page_config(page_title="AegisMap", page_icon="🛡️", layout="wide")

SAMPLE_PATH = Path(__file__).with_name("sample_ips.csv")


def init_state() -> None:
    defaults = {
        "theme_mode": "Dark",
        "preview_limit": 250,
        "drop_duplicates": True,
        "show_invalid_only": False,
        "connection_profile": "Draft",
        "validation_mode": "Normalize",
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


def theme() -> dict[str, str]:
    if st.session_state.get("theme_mode") == "Light":
        return {
            "bg": "#F3F7FB",
            "panel": "#FFFFFF",
            "panel_alt": "#ECF3FA",
            "text": "#0F172A",
            "muted": "#475569",
            "border": "#D6E0EA",
            "accent": "#0F766E",
            "accent_2": "#2563EB",
            "success": "#166534",
            "danger": "#B91C1C",
            "warn": "#9A3412",
        }
    return {
        "bg": "#07111F",
        "panel": "#0B1726",
        "panel_alt": "#0F1E30",
        "text": "#F8FAFC",
        "muted": "#94A3B8",
        "border": "#1E3A5F",
        "accent": "#14B8A6",
        "accent_2": "#38BDF8",
        "success": "#86EFAC",
        "danger": "#FCA5A5",
        "warn": "#FCD34D",
    }


def inject_css() -> None:
    colors = theme()
    st.markdown(
        f"""
<style>
[data-testid="stAppViewContainer"] {{
  background: {colors["bg"]};
}}
[data-testid="stHeader"] {{
  background: transparent;
}}
[data-testid="stSidebar"] {{
  background: {colors["panel"]};
  border-right: 1px solid {colors["border"]};
}}
.block-container {{
  padding-top: 1.1rem;
  padding-bottom: 2rem;
}}
.band {{
  background: {colors["panel"]};
  border: 1px solid {colors["border"]};
  border-radius: 8px;
  padding: 1rem 1.15rem;
  margin-bottom: 0.9rem;
}}
.header-grid {{
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 1rem;
  align-items: end;
}}
.brand {{
  color: {colors["accent"]};
  font-size: 0.8rem;
  font-weight: 700;
  text-transform: uppercase;
}}
.headline {{
  color: {colors["text"]};
  font-size: 1.9rem;
  font-weight: 700;
  margin: 0.15rem 0 0.35rem 0;
}}
.subtle {{
  color: {colors["muted"]};
  font-size: 0.95rem;
}}
.pill-row {{
  display: flex;
  flex-wrap: wrap;
  gap: 0.45rem;
  justify-content: flex-end;
}}
.pill {{
  border: 1px solid {colors["border"]};
  background: {colors["panel_alt"]};
  border-radius: 999px;
  padding: 0.38rem 0.7rem;
  color: {colors["text"]};
  font-size: 0.78rem;
  white-space: nowrap;
}}
.section-label {{
  color: {colors["muted"]};
  font-size: 0.78rem;
  text-transform: uppercase;
  font-weight: 700;
  margin-bottom: 0.5rem;
}}
.panel-title {{
  color: {colors["text"]};
  font-size: 1.15rem;
  font-weight: 700;
  margin-bottom: 0.3rem;
}}
.metric-note {{
  color: {colors["muted"]};
  font-size: 0.82rem;
}}
div[data-baseweb="tab-list"] {{
  gap: 0.35rem;
}}
button[data-baseweb="tab"] {{
  border-radius: 8px !important;
}}
</style>
        """,
        unsafe_allow_html=True,
    )


def read_input(uploaded) -> pd.DataFrame:
    name = uploaded.name.lower()
    if name.endswith(".csv"):
        return pd.read_csv(uploaded, dtype=str, keep_default_na=False)
    if name.endswith((".xlsx", ".xlsm", ".xls")):
        return pd.read_excel(uploaded, dtype=str, keep_default_na=False)
    raise ValueError("Upload only CSV or Excel files.")


def detect_ip_column(frame: pd.DataFrame) -> str:
    preferred = ("ip", "ip address", "ip_address", "host", "hostname", "asset ip", "server ip")
    lookup = {str(column).lower().strip(): column for column in frame.columns}
    for name in preferred:
        if name in lookup:
            return lookup[name]
    for column in frame.columns:
        if frame[column].map(normalize_ip).notna().any():
            return column
    return frame.columns[0]


def build_result_sets(frame: pd.DataFrame, ip_column: str, drop_duplicates: bool) -> tuple[pd.DataFrame, pd.DataFrame]:
    work = frame.copy()
    work["Input IP"] = work[ip_column].astype(str)
    work["Normalized IP"] = work["Input IP"].map(normalize_ip)
    valid = work[work["Normalized IP"].notna()].copy()
    invalid = work[work["Normalized IP"].isna()].copy()
    if drop_duplicates:
        valid = valid.drop_duplicates(subset=["Normalized IP"])
    return valid, invalid


def filtered_preview(frame: pd.DataFrame, query: str, limit: int) -> pd.DataFrame:
    if frame.empty:
        return frame
    output = frame
    term = query.strip().lower()
    if term:
        mask = output.astype(str).apply(lambda col: col.str.lower().str.contains(term, na=False))
        output = output[mask.any(axis=1)]
    return output.head(max(int(limit), 1)).copy()


def normalized_export(frame: pd.DataFrame) -> bytes:
    output = io.StringIO()
    frame.to_csv(output, index=False)
    return output.getvalue().encode("utf-8-sig")


def sample_export() -> bytes:
    return SAMPLE_PATH.read_bytes() if SAMPLE_PATH.exists() else b""


init_state()
inject_css()

with st.sidebar:
    st.subheader("Workspace")
    st.radio(
        "Theme",
        options=["Dark", "Light"],
        horizontal=True,
        key="theme_mode",
        label_visibility="collapsed",
    )
    st.divider()
    st.subheader("Connection")
    st.selectbox("Profile", ["Draft", "Primary", "Secondary"], key="connection_profile")
    st.text_input("Nessus / Tenable Base URL", placeholder="https://cloud.tenable.com")
    st.text_input("Access Key", type="password")
    st.text_input("Secret Key", type="password")
    st.checkbox("Verify SSL certificate", value=True)
    st.divider()
    st.subheader("Processing")
    st.radio("Mode", ["Normalize", "Review"], horizontal=True, key="validation_mode")
    st.number_input("Preview rows", min_value=50, max_value=5000, step=50, key="preview_limit")
    st.checkbox("Distinct normalized IPs", key="drop_duplicates")
    st.checkbox("Invalid rows only", key="show_invalid_only")

st.markdown(
    """
    <div class="band">
      <div class="header-grid">
        <div>
          <div class="brand">AEGISMAP</div>
          <div class="headline">IP Validation Workspace</div>
          <div class="subtle">Local intake and normalization</div>
        </div>
        <div class="pill-row">
          <div class="pill">Connection: Draft</div>
          <div class="pill">Source: Upload</div>
          <div class="pill">Mode: Normalize</div>
        </div>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

toolbar_left, toolbar_right = st.columns([0.68, 0.32], gap="large")

with toolbar_left:
    st.markdown('<div class="band"><div class="section-label">Input</div><div class="panel-title">Source File</div></div>', unsafe_allow_html=True)
    uploaded = st.file_uploader("Upload CSV or Excel", type=["csv", "xlsx", "xlsm", "xls"], label_visibility="collapsed")
    input_frame = None
    ip_column = None
    if uploaded:
        try:
            input_frame = read_input(uploaded)
            ip_column = st.selectbox(
                "IP column",
                input_frame.columns,
                index=list(input_frame.columns).index(detect_ip_column(input_frame)),
            )
        except Exception as exc:
            st.error(f"Input file error: {exc}")

with toolbar_right:
    st.markdown('<div class="band"><div class="section-label">Actions</div><div class="panel-title">Exports</div></div>', unsafe_allow_html=True)
    st.download_button(
        "Sample CSV",
        sample_export(),
        file_name="aegismap_sample_ips.csv",
        mime="text/csv",
        use_container_width=True,
    )

if uploaded and input_frame is not None and ip_column is not None:
    valid, invalid = build_result_sets(input_frame, ip_column, bool(st.session_state.get("drop_duplicates")))
    shown_frame = invalid if st.session_state.get("show_invalid_only") else valid
    search_left, search_right = st.columns([0.72, 0.28], gap="large")
    with search_left:
        query = st.text_input("Search", placeholder="Filter rows")
    with search_right:
        st.markdown('<div class="metric-note">&nbsp;</div>', unsafe_allow_html=True)
        st.download_button(
            "Download Normalized CSV",
            normalized_export(valid[["Input IP", "Normalized IP"]]),
            file_name="aegismap_normalized_ips.csv",
            mime="text/csv",
            use_container_width=True,
        )

    st.markdown('<div class="band">', unsafe_allow_html=True)
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Rows", len(input_frame))
    m2.metric("Valid", len(valid))
    m3.metric("Invalid", len(invalid))
    m4.metric("Distinct", valid["Normalized IP"].nunique() if not valid.empty else 0)
    st.markdown('</div>', unsafe_allow_html=True)

    tab_preview, tab_normalized, tab_invalid = st.tabs(["Source Preview", "Normalized", "Invalid"])

    with tab_preview:
        preview = filtered_preview(input_frame, query, int(st.session_state.get("preview_limit", 250)))
        st.dataframe(preview, use_container_width=True, height=420)

    with tab_normalized:
        normalized_view = filtered_preview(shown_frame[["Input IP", "Normalized IP"]] if not shown_frame.empty else shown_frame, query, int(st.session_state.get("preview_limit", 250)))
        st.dataframe(normalized_view, use_container_width=True, height=420)

    with tab_invalid:
        invalid_view = filtered_preview(invalid, query, int(st.session_state.get("preview_limit", 250)))
        st.dataframe(invalid_view, use_container_width=True, height=420)

else:
    st.markdown(
        """
        <div class="band">
          <div class="section-label">Queue</div>
          <div class="panel-title">Awaiting Input</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
