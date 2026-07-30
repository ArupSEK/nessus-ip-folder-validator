from __future__ import annotations

import io
import time as time_module
from datetime import datetime, time, timezone

import pandas as pd
import streamlit as st

from connection_config import ConnectionConfigError, validate_connection
from ip_utils import normalize_ip
from local_auth import LocalAuthError, LocalAuthManager
from nessus_fixed import NessusAPIError, make_scan_records, summarize_results, unix_from_date
from two_step_validation import (
    NessusClient,
    build_location_index,
    candidate_scan_records,
    deep_validate_selected,
)

st.set_page_config(page_title="Nessus IP Validator", page_icon="🛡️", layout="wide")


def init_session_state() -> None:
    defaults = {
        "theme_mode": "Dark",
        "preview_rows": 500,
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


def current_theme() -> dict[str, str]:
    if st.session_state.get("theme_mode", "Dark") == "Light":
        return {
            "bg": "#F3F7FB",
            "panel": "#FFFFFF",
            "panel_alt": "#E8F0FA",
            "hero": "#DCEAFE",
            "text": "#0F172A",
            "muted": "#475569",
            "accent": "#0891B2",
            "accent_2": "#2563EB",
            "border": "#CBD5E1",
            "success": "#166534",
            "warning": "#9A3412",
            "danger": "#B91C1C",
        }
    return {
        "bg": "#07111F",
        "panel": "#0B1726",
        "panel_alt": "#0F1E30",
        "hero": "#06111F",
        "text": "#F8FAFC",
        "muted": "#94A3B8",
        "accent": "#14B8A6",
        "accent_2": "#06B6D4",
        "border": "#1E3A5F",
        "success": "#86EFAC",
        "warning": "#FCD34D",
        "danger": "#FCA5A5",
    }


def inject_theme_css() -> None:
    theme = current_theme()
    st.markdown(
        f"""
<style>
:root {{
  --bg: {theme["bg"]};
  --panel: {theme["panel"]};
  --panel-alt: {theme["panel_alt"]};
  --hero: {theme["hero"]};
  --text: {theme["text"]};
  --muted: {theme["muted"]};
  --accent: {theme["accent"]};
  --accent-2: {theme["accent_2"]};
  --border: {theme["border"]};
  --success: {theme["success"]};
  --warning: {theme["warning"]};
  --danger: {theme["danger"]};
}}
[data-testid="stAppViewContainer"] {{
  background: var(--bg);
}}
[data-testid="stHeader"] {{
  background: transparent;
}}
[data-testid="stSidebar"] {{
  background: var(--panel);
  border-right: 1px solid var(--border);
}}
.block-container {{
  padding-top: 1.25rem;
  padding-bottom: 2rem;
}}
.app-shell {{
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.15rem 1.25rem;
  margin-bottom: 1rem;
}}
.login-shell {{
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 8px;
  min-height: 640px;
  overflow: hidden;
}}
.login-panel {{
  padding: 2.2rem 2rem 1.8rem 2rem;
}}
.hero-panel {{
  background:
    linear-gradient(140deg, rgba(6,182,212,0.20), rgba(37,99,235,0.08)),
    linear-gradient(180deg, var(--hero), var(--panel));
  min-height: 640px;
  padding: 2.6rem 2.2rem;
  border-left: 1px solid var(--border);
}}
.eyebrow {{
  color: var(--accent);
  font-size: 0.8rem;
  font-weight: 700;
  text-transform: uppercase;
}}
.hero-title {{
  color: var(--text);
  font-size: 2.35rem;
  line-height: 1.04;
  font-weight: 700;
  margin: 0.6rem 0 1rem 0;
}}
.hero-copy, .muted-copy {{
  color: var(--muted);
  font-size: 0.98rem;
}}
.brand-kicker {{
  color: var(--accent);
  font-size: 0.85rem;
  font-weight: 700;
  margin-bottom: 0.2rem;
}}
.login-title {{
  color: var(--text);
  font-size: 1.85rem;
  font-weight: 700;
  margin: 0.35rem 0 0.35rem 0;
}}
.status-grid {{
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.75rem;
  margin-top: 2rem;
}}
.status-card {{
  background: rgba(15, 30, 48, 0.44);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 0.95rem;
}}
.status-label {{
  font-size: 0.76rem;
  font-weight: 700;
  text-transform: uppercase;
  margin-bottom: 0.35rem;
}}
.status-value {{
  color: var(--text);
  font-size: 1rem;
  font-weight: 700;
}}
.note-band {{
  margin-top: 1.2rem;
  padding: 0.95rem 1rem;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: var(--panel-alt);
  color: var(--muted);
}}
</style>
        """,
        unsafe_allow_html=True,
    )


def render_theme_picker(location_key: str) -> None:
    selection = st.radio(
        "Theme",
        options=["Dark", "Light"],
        index=0 if st.session_state.get("theme_mode", "Dark") == "Dark" else 1,
        horizontal=True,
        key=location_key,
        label_visibility="collapsed",
    )
    st.session_state["theme_mode"] = selection


def clear_session() -> None:
    for key in (
        "authenticated", "authenticated_user", "vault_key", "saved_connection",
        "base_url", "access_key", "secret_key", "verify_ssl", "timeout",
        "connection_base_url", "connection_access_key", "connection_secret_key",
        "connection_verify_ssl", "connection_timeout",
        "summary", "details", "auth_rows", "invalid_rows", "work_df",
        "scan_records", "discovery_stats", "deep_stats", "deep_notice",
        "deep_selection_editor", "login_failed_attempts", "login_lockout_until",
        "reset_account_confirmation",
    ):
        st.session_state.pop(key, None)


def activate_connection(connection: dict) -> None:
    """Copy only verified, encrypted-at-rest settings into active session keys."""
    for key in ("base_url", "access_key", "secret_key", "verify_ssl", "timeout"):
        st.session_state[key] = connection[key]


def initialize_connection_form(connection: dict) -> None:
    defaults = {
        "connection_base_url": connection.get("base_url", ""),
        "connection_access_key": connection.get("access_key", ""),
        "connection_secret_key": connection.get("secret_key", ""),
        "connection_verify_ssl": connection.get("verify_ssl", True),
        "connection_timeout": int(connection.get("timeout", 90) or 90),
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


def lock_seconds() -> int:
    until = float(st.session_state.get("login_lockout_until", 0.0) or 0.0)
    return max(0, int(until - time_module.time()))


def require_login(auth: LocalAuthManager) -> None:
    if st.session_state.get("authenticated") and st.session_state.get("vault_key"):
        return
    if st.session_state.get("authenticated"):
        clear_session()

    setup = not auth.is_configured()
    theme = current_theme()
    remaining = lock_seconds()

    top_left, top_right = st.columns([0.8, 0.2])
    with top_left:
        st.markdown('<div class="brand-kicker">TRINETRA-STYLE ACCESS</div>', unsafe_allow_html=True)
    with top_right:
        render_theme_picker("login_theme_picker")

    left, right = st.columns([0.92, 1.08], gap="large")

    with left:
        st.markdown('<div class="login-shell"><div class="login-panel">', unsafe_allow_html=True)
        st.markdown('<div class="brand-kicker">AEGISMAP</div>', unsafe_allow_html=True)
        st.markdown(
            f'<div class="login-title">{"Create login" if setup else "Login"}</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            f'<div class="muted-copy">{"Set up local access for this workstation." if setup else "Sign in to open the validator dashboard."}</div>',
            unsafe_allow_html=True,
        )

        show_password = st.checkbox("Show password", key="login_show_password")
        password_type = "default" if show_password else "password"

        if setup:
            with st.form("create_login", clear_on_submit=False):
                username = st.text_input("Username", autocomplete="username")
                password = st.text_input("Password", type=password_type, autocomplete="new-password")
                confirm = st.text_input("Confirm password", type=password_type, autocomplete="new-password")
                submitted = st.form_submit_button("Create Login", type="primary", use_container_width=True)
            if submitted:
                try:
                    if password != confirm:
                        raise LocalAuthError("Passwords do not match.")
                    auth.configure(username, password)
                    vault_key, connection = auth.unlock(password)
                    st.session_state.update(
                        authenticated=True,
                        authenticated_user=username.strip(),
                        vault_key=vault_key,
                        saved_connection=connection,
                    )
                    if connection:
                        activate_connection(connection)
                    st.rerun()
                except Exception as exc:
                    st.error(str(exc))
        else:
            if remaining:
                st.warning(f"Too many failed attempts. Try again in {remaining} seconds.")
            with st.form("login", clear_on_submit=False):
                username = st.text_input("Username", autocomplete="username")
                password = st.text_input("Password", type=password_type, autocomplete="current-password")
                submitted = st.form_submit_button("Sign In", type="primary", disabled=remaining > 0, use_container_width=True)
            if submitted:
                if auth.verify(username, password):
                    try:
                        vault_key, connection = auth.unlock(password)
                    except LocalAuthError as exc:
                        st.error(str(exc))
                    else:
                        st.session_state.update(
                            authenticated=True,
                            authenticated_user=username.strip(),
                            vault_key=vault_key,
                            saved_connection=connection,
                            login_failed_attempts=0,
                            login_lockout_until=0.0,
                        )
                        if connection:
                            activate_connection(connection)
                        st.rerun()
                else:
                    failed = int(st.session_state.get("login_failed_attempts", 0)) + 1
                    if failed >= 5:
                        st.session_state["login_failed_attempts"] = 0
                        st.session_state["login_lockout_until"] = time_module.time() + 30
                        st.error("Invalid credentials. Login is locked for 30 seconds.")
                    else:
                        st.session_state["login_failed_attempts"] = failed
                        st.error(f"Invalid credentials. {5 - failed} attempt(s) remain.")

            with st.expander("Forgot Password / Reset Account"):
                st.warning(
                    "Resetting removes the local login and the saved encrypted Nessus "
                    "URL, Access Key, and Secret Key from this device."
                )
                confirmation = st.text_input(
                    "Type RESET to confirm",
                    key="reset_account_confirmation",
                    autocomplete="off",
                )
                if st.button(
                    "Reset Account and Forget Saved Connection",
                    disabled=confirmation.strip().upper() != "RESET",
                    use_container_width=True,
                ):
                    try:
                        auth.reset_account()
                        clear_session()
                        st.rerun()
                    except LocalAuthError as exc:
                        st.error(str(exc))

        st.markdown(
            """
            <div class="note-band">
              The local password is stored only as a salted PBKDF2 hash. Saved API credentials are encrypted with a separate password-derived key.
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown("</div></div>", unsafe_allow_html=True)

    with right:
        st.markdown(
            f"""
            <div class="hero-panel">
              <div class="eyebrow">Authentication visibility</div>
              <div class="hero-title">Credential<br>Trust Center</div>
              <div class="hero-copy">Validate Nessus IP coverage, exact folder placement, and authentication evidence from one controlled interface.</div>
              <div class="status-grid">
                <div class="status-card">
                  <div class="status-label" style="color:{theme["success"]};">Verified</div>
                  <div class="status-value">Locate assets in the right folder and scan history.</div>
                </div>
                <div class="status-card">
                  <div class="status-label" style="color:{theme["danger"]};">Needs action</div>
                  <div class="status-value">Surface missing assets and failed credential evidence quickly.</div>
                </div>
                <div class="status-card">
                  <div class="status-label" style="color:{theme["accent"]};">Low API discovery</div>
                  <div class="status-value">Open only candidate scan summaries for first-pass location checks.</div>
                </div>
                <div class="status-card">
                  <div class="status-label" style="color:{theme["warning"]};">Deep validation</div>
                  <div class="status-value">Use host details or CSV export only on selected IPs that need proof.</div>
                </div>
              </div>
              <div class="note-band">
                Built for controlled Nessus validation with local sign-in, encrypted saved connection, and switchable dark or light presentation.
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.stop()


def render_connection_form(auth: LocalAuthManager, *, required: bool = False) -> bool:
    """Render explicit connection setup and persist only after an API test."""
    saved = st.session_state.get("saved_connection", {}) or {}
    initialize_connection_form(saved)

    if required:
        st.subheader("Required Nessus / Tenable Connection")
        st.info(
            "Enter and verify all mandatory connection fields. The dashboard will "
            "open only after the API connection succeeds."
        )

    with st.form("connection_settings_form"):
        st.text_input(
            "Nessus / Tenable Base URL",
            key="connection_base_url",
            placeholder="https://cloud.tenable.com or https://server:8834",
            autocomplete="off",
        )
        st.text_input(
            "Access Key",
            type="password",
            key="connection_access_key",
            autocomplete="new-password",
        )
        st.text_input(
            "Secret Key",
            type="password",
            key="connection_secret_key",
            autocomplete="new-password",
        )
        st.checkbox(
            "Verify SSL certificate",
            key="connection_verify_ssl",
        )
        st.number_input(
            "API timeout seconds",
            min_value=15,
            max_value=300,
            step=15,
            key="connection_timeout",
        )
        submitted = st.form_submit_button(
            "Save and Verify Connection", type="primary", use_container_width=True
        )

    if not submitted:
        return False

    try:
        connection = validate_connection(
            st.session_state.get("connection_base_url"),
            st.session_state.get("connection_access_key"),
            st.session_state.get("connection_secret_key"),
            st.session_state.get("connection_verify_ssl", True),
            st.session_state.get("connection_timeout", 90),
        )
        client = NessusClient(**connection)
        folder_count, scan_count = client.test_connection()
        auth.save_connection(connection, st.session_state["vault_key"])
    except ConnectionConfigError as exc:
        st.error(str(exc))
        return False
    except Exception as exc:
        st.error(
            "Connection verification failed. Nothing was saved. "
            f"Check the URL, API keys, SSL setting, and network access. Details: {exc}"
        )
        return False

    st.session_state["saved_connection"] = connection
    activate_connection(connection)
    st.success(
        f"Connection verified and encrypted locally. Accessible folders: "
        f"{folder_count}; scans: {scan_count}."
    )
    st.rerun()
    return True


def build_client() -> NessusClient:
    required = ("base_url", "access_key", "secret_key", "verify_ssl", "timeout")
    missing = [key for key in required if key not in st.session_state]
    if missing:
        raise ConnectionConfigError(
            "No verified saved connection is active. Sign in and save the "
            "connection settings again."
        )
    return NessusClient(
        base_url=st.session_state["base_url"],
        access_key=st.session_state["access_key"],
        secret_key=st.session_state["secret_key"],
        verify_ssl=st.session_state["verify_ssl"],
        timeout=int(st.session_state["timeout"]),
    )


def read_input(uploaded) -> pd.DataFrame:
    name = uploaded.name.lower()
    if name.endswith(".csv"):
        return pd.read_csv(uploaded, dtype=str, keep_default_na=False)
    if name.endswith((".xlsx", ".xlsm", ".xls")):
        return pd.read_excel(uploaded, dtype=str, keep_default_na=False)
    raise ValueError("Upload only CSV or Excel files.")


def detect_ip_column(frame: pd.DataFrame) -> str:
    preferred = ("ip", "ip address", "ip_address", "host", "hostname", "asset ip")
    columns = {str(column).lower().strip(): column for column in frame.columns}
    for name in preferred:
        if name in columns:
            return columns[name]
    for column in frame.columns:
        if frame[column].map(normalize_ip).notna().any():
            return column
    return frame.columns[0]


def report_excel(summary: pd.DataFrame, details: pd.DataFrame, auth: pd.DataFrame) -> bytes:
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        for sheet, frame in (("Summary", summary), ("All_Matches", details), ("Auth_Evidence", auth)):
            frame.to_excel(writer, index=False, sheet_name=sheet)
            worksheet = writer.sheets[sheet]
            worksheet.freeze_panes(1, 0)
            worksheet.autofilter(0, 0, max(len(frame), 1), max(len(frame.columns) - 1, 0))
            for index, column in enumerate(frame.columns):
                width = min(max(len(str(column)) + 2, 14), 50)
                worksheet.set_column(index, index, width)
    return output.getvalue()


def preview_dataframe(frame: pd.DataFrame, max_rows: int) -> pd.DataFrame:
    if frame.empty:
        return frame
    return frame.head(max(int(max_rows), 1)).copy()


def latest_rows(details: pd.DataFrame) -> pd.DataFrame:
    if details.empty:
        return pd.DataFrame()
    frame = details.copy()
    ranks = {"Scan result": 3, "Configured target": 2, "Scan name only": 1}
    frame["__date"] = pd.to_datetime(frame["scan_date"], errors="coerce", utc=True)
    frame["__rank"] = frame["presence_type"].map(ranks).fillna(0)
    frame["__deep"] = frame["evidence_source"].astype(str).str.startswith("Deep")
    frame = frame.sort_values(
        ["__date", "__rank", "__deep"], ascending=[False, False, False],
        na_position="last",
    ).drop_duplicates("normalized_ip", keep="first")
    frame.insert(0, "Select", False)
    columns = (
        "Select", "normalized_ip", "folder_name", "scan_name", "scan_id",
        "history_id", "history_uuid", "scan_date", "scan_status",
        "presence_type", "result_note", "evidence_source", "host_id", "api_id",
    )
    return frame[[column for column in columns if column in frame.columns]]


AUTH = LocalAuthManager()
init_session_state()
inject_theme_css()
require_login(AUTH)

saved_connection = st.session_state.get("saved_connection", {}) or {}
if saved_connection:
    activate_connection(saved_connection)
else:
    st.title("🛡️ Nessus IP-to-Folder Validator")
    render_connection_form(AUTH, required=True)
    st.stop()

with st.sidebar:
    st.success(
        f"👤 {st.session_state.get('authenticated_user', AUTH.configured_username())}"
    )
    render_theme_picker("app_theme_picker")
    st.caption(f"Saved connection: {saved_connection.get('base_url', '')}")
    if st.button("Sign Out", use_container_width=True):
        clear_session()
        st.rerun()

    with st.expander("Edit Saved Connection"):
        render_connection_form(AUTH)

    st.header("Low API Discovery")
    fallback_all = st.checkbox(
        "Fallback search across all scans", value=False,
        help="Use only when candidate metadata cannot locate an IP; this uses more API calls.",
    )
    use_dates = st.checkbox("Use scan started date filter", value=False)
    start_date = end_date = None
    if use_dates:
        start_date = st.date_input("Started from")
        end_date = st.date_input("Started to")
    max_scans = st.number_input("Max scans (0 = all)", min_value=0, value=0, step=10)

    st.header("Deep Validation")
    deep_label = st.selectbox(
        "Method",
        ("Host details (lower API usage)", "CSV export (exact plugin output)"),
    )
    deep_method = "csv_export" if deep_label.startswith("CSV") else "host_details"
    st.number_input("Rows to preview in app", min_value=50, max_value=5000, value=500, step=50, key="preview_rows")

st.markdown(
    """
    <div class="app-shell">
      <div class="brand-kicker">AEGISMAP</div>
      <div class="login-title">Nessus IP-to-Folder Validator</div>
      <div class="muted-copy">First locate the exact folder and scan with low API use, then deep-validate only selected IPs.</div>
    </div>
    """,
    unsafe_allow_html=True,
)

left, right = st.columns([0.62, 0.38])
with left:
    uploaded = st.file_uploader("Upload IP list CSV/XLSX", type=["csv", "xlsx", "xlsm", "xls"])
    input_frame = None
    ip_column = None
    if uploaded:
        try:
            input_frame = read_input(uploaded)
            ip_column = st.selectbox(
                "Select IP column", input_frame.columns,
                index=list(input_frame.columns).index(detect_ip_column(input_frame)),
            )
            st.dataframe(input_frame.head(10), use_container_width=True)
        except Exception as exc:
            st.error(f"Input file error: {exc}")
with right:
    st.subheader("Two-step workflow")
    st.markdown(
        "1. **Find Folder and Scan** opens only candidate scan summaries.\n"
        "2. **Deep Validate Selected IPs** groups selected rows by scan/history.\n"
        "3. Use CSV only when exact plugin output is required."
    )

if st.button("🔍 Find Folder and Scan (Low API)", type="primary", disabled=not uploaded):
    if not st.session_state.get("access_key") or not st.session_state.get("secret_key"):
        st.error("Please enter Access Key and Secret Key.")
        st.stop()
    if input_frame is None or ip_column is None:
        st.error("Upload a valid file and select the IP column.")
        st.stop()

    work = input_frame.copy()
    work["Input IP"] = work[ip_column].astype(str)
    work["Normalized IP"] = work["Input IP"].map(normalize_ip)
    invalid = work[work["Normalized IP"].isna()]
    work = work[work["Normalized IP"].notna()][["Input IP", "Normalized IP"]].drop_duplicates()
    input_ips = set(work["Normalized IP"].astype(str))
    if not input_ips:
        st.error("No valid IP addresses were found.")
        st.stop()

    status = st.status("Discovering candidate scans...", expanded=True)
    progress = st.progress(0)
    try:
        client = build_client()
        folders = client.list_folders()
        started_from = started_to = None
        if use_dates and start_date and end_date:
            started_from = unix_from_date(datetime.combine(start_date, time.min, tzinfo=timezone.utc))
            started_to = unix_from_date(datetime.combine(end_date, time.max, tzinfo=timezone.utc))
        scans = client.list_scans(started_from=started_from, started_to=started_to)
        records = make_scan_records(scans, folders)
        if max_scans:
            records = records[: int(max_scans)]
        candidates = candidate_scan_records(input_ips, records)
        status.write(f"Available scans: {len(records)}; metadata candidates: {len(candidates)}")

        def on_progress(done, total, message):
            progress.progress(min(done / max(total, 1), 1.0), text=message)

        matches, auth_rows, stats = build_location_index(
            client, input_ips, records, fallback_all_scans=fallback_all,
            progress_callback=on_progress,
        )
        stats["api_calls"] = client.request_count
        summary, details = summarize_results(work, matches, auth_rows)
        st.session_state.update(
            summary=summary, details=details, auth_rows=auth_rows,
            invalid_rows=invalid, work_df=work, scan_records=records,
            discovery_stats=stats,
        )
        st.session_state.pop("deep_stats", None)
        st.session_state.pop("deep_selection_editor", None)
        status.update(label="Discovery complete", state="complete", expanded=False)
        progress.progress(1.0, text="Discovery complete")
    except NessusAPIError as exc:
        status.update(label="API error", state="error", expanded=True)
        st.error(str(exc))
        st.stop()
    except Exception as exc:
        status.update(label="Discovery error", state="error", expanded=True)
        st.exception(exc)
        st.stop()

if "summary" in st.session_state:
    summary = st.session_state["summary"]
    details = st.session_state.get("details", pd.DataFrame())
    auth_rows = st.session_state.get("auth_rows", pd.DataFrame())
    invalid = st.session_state.get("invalid_rows", pd.DataFrame())
    preview_rows = int(st.session_state.get("preview_rows", 500))
    discovery = st.session_state.get("discovery_stats", {})
    deep = st.session_state.get("deep_stats", {})
    notice = st.session_state.pop("deep_notice", None)
    if notice:
        st.success(notice)

    st.divider()
    total = len(summary)
    located = int((summary["Present in Nessus"] == "Yes").sum()) if total else 0
    auth_ok = int(summary["Authentication Status"].isin(["Authenticated", "Valid with limitations"]).sum()) if total else 0
    auth_failed = int((summary["Authentication Status"] == "Failed").sum()) if total else 0
    api_calls = int(discovery.get("api_calls", 0)) + int(deep.get("api_calls", 0))
    columns = st.columns(6)
    for column, label, value in zip(
        columns,
        ("Input IPs", "Located", "Not Located", "Auth OK / Limited", "Auth Failed", "API Calls"),
        (total, located, total - located, auth_ok, auth_failed, api_calls),
    ):
        column.metric(label, value)
    st.caption(
        f"Discovery opened {discovery.get('scans_opened', 0)} scan summaries from "
        f"{discovery.get('scans_available', 0)} available scans."
    )
    if total - located and not fallback_all:
        st.warning("Enable fallback search and run discovery again only for IPs not located from candidate metadata.")
    summary_preview = preview_dataframe(summary, preview_rows)
    if len(summary_preview) < len(summary):
        st.caption(f"Showing first {len(summary_preview)} of {len(summary)} summary rows. Use the downloads for the full result set.")
    st.dataframe(summary_preview, use_container_width=True, height=420)

    st.subheader("Deep Validate Selected Results")
    selection = latest_rows(details)
    if selection.empty:
        selected = pd.DataFrame()
        st.info("No located results are available for deep validation.")
    else:
        edited = st.data_editor(
            selection, key="deep_selection_editor", use_container_width=True,
            hide_index=True, height=min(420, 80 + 35 * len(selection)),
            disabled=[column for column in selection.columns if column != "Select"],
            column_config={"Select": st.column_config.CheckboxColumn("Select", default=False)},
        )
        selected = edited[edited["Select"]].copy()

    if st.button("🔬 Deep Validate Selected IPs", disabled=selection.empty):
        if selected.empty:
            st.warning("Select at least one IP.")
            st.stop()
        status = st.status("Deep validation started...", expanded=True)
        progress = st.progress(0)
        try:
            client = build_client()

            def on_deep_progress(done, total_groups, message):
                progress.progress(min(done / max(total_groups, 1), 1.0), text=message)

            deep_matches, new_auth, stats = deep_validate_selected(
                client, selected, st.session_state.get("scan_records", []),
                method=deep_method, progress_callback=on_deep_progress,
            )
            stats["api_calls"] = client.request_count
            combined_details = pd.concat([details, deep_matches], ignore_index=True).drop_duplicates()
            combined_auth = pd.concat([auth_rows, new_auth], ignore_index=True).drop_duplicates()
            new_summary, new_details = summarize_results(
                st.session_state["work_df"], combined_details, combined_auth
            )
            st.session_state.update(
                summary=new_summary, details=new_details, auth_rows=combined_auth,
                deep_stats=stats,
                deep_notice=(
                    f"Deep validation completed for {stats['selected_ips']} IP(s) across "
                    f"{stats['scan_groups']} scan group(s) using {client.request_count} logical API request(s)."
                ),
            )
            status.update(label="Deep validation complete", state="complete", expanded=False)
            progress.progress(1.0, text="Deep validation complete")
            st.rerun()
        except Exception as exc:
            status.update(label="Deep validation error", state="error", expanded=True)
            st.exception(exc)
            st.stop()

    csv_data = summary.to_csv(index=False).encode("utf-8-sig")
    excel_data = report_excel(summary, details, auth_rows)
    csv_col, excel_col = st.columns(2)
    csv_col.download_button("⬇️ Download Summary CSV", csv_data, "nessus_ip_validation_summary.csv", "text/csv")
    excel_col.download_button(
        "⬇️ Download Full Excel Report", excel_data, "nessus_ip_validation_report.xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    with st.expander("All folder/scan and deep-validation matches"):
        details_preview = preview_dataframe(details, preview_rows)
        if len(details_preview) < len(details):
            st.caption(f"Showing first {len(details_preview)} of {len(details)} match rows.")
        st.dataframe(details_preview, use_container_width=True, height=360)
    with st.expander("Authentication evidence rows"):
        auth_preview = preview_dataframe(auth_rows, preview_rows)
        if len(auth_preview) < len(auth_rows):
            st.caption(f"Showing first {len(auth_preview)} of {len(auth_rows)} authentication evidence rows.")
        st.dataframe(auth_preview, use_container_width=True, height=360)
    if not invalid.empty:
        with st.expander("Invalid input rows"):
            invalid_preview = preview_dataframe(invalid, preview_rows)
            if len(invalid_preview) < len(invalid):
                st.caption(f"Showing first {len(invalid_preview)} of {len(invalid)} invalid rows.")
            st.dataframe(invalid_preview, use_container_width=True)
