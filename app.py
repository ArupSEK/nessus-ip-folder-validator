from __future__ import annotations

import io
import time as time_module
from datetime import datetime, time, timezone

import pandas as pd
import streamlit as st

from ip_utils import normalize_ip
from local_auth import LocalAuthManager
from nessus_fixed import (
    NessusAPIError,
    NessusClient,
    build_index_csv_export,
    build_index_fast_api,
    make_scan_records,
    summarize_results,
    unix_from_date,
)

st.set_page_config(
    page_title="Nessus IP Validator",
    page_icon="🛡️",
    layout="wide",
)

CUSTOM_CSS = """
<style>
.block-container {padding-top: 1.5rem;}
.metric-card {border: 1px solid #263238; border-radius: 14px; padding: 1rem; background: #111827;}
.small-muted {color: #9CA3AF; font-size: 0.9rem;}
.success-pill {padding: 0.2rem 0.55rem; border-radius: 999px; background: #064E3B; color: #A7F3D0;}
.warn-pill {padding: 0.2rem 0.55rem; border-radius: 999px; background: #78350F; color: #FDE68A;}
.fail-pill {padding: 0.2rem 0.55rem; border-radius: 999px; background: #7F1D1D; color: #FECACA;}
.login-brand {
    color: #0F766E;
    font-size: 1.7rem;
    font-weight: 800;
    letter-spacing: 0.02em;
    margin-bottom: 0;
}
.login-subbrand {
    color: #475569;
    font-size: 0.9rem;
    font-weight: 700;
    margin-top: -0.35rem;
    margin-bottom: 2rem;
}
.login-hero {
    min-height: 540px;
    border-radius: 22px;
    padding: 54px 52px;
    color: #F8FAFC;
    background:
        radial-gradient(circle at 92% 92%, rgba(14, 165, 233, .45) 0 18%, transparent 19%),
        radial-gradient(circle at 86% 88%, rgba(15, 118, 110, .55) 0 28%, transparent 29%),
        linear-gradient(rgba(255,255,255,.035) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,.035) 1px, transparent 1px),
        #111827;
    background-size: auto, auto, 28px 28px, 28px 28px, auto;
    box-shadow: 0 20px 55px rgba(15, 23, 42, .25);
}
.login-kicker {
    color: #5EEAD4;
    font-size: 0.9rem;
    font-weight: 800;
    letter-spacing: .12em;
    text-transform: uppercase;
}
.login-headline {
    font-size: 2.45rem;
    line-height: 1.08;
    font-weight: 900;
    margin: 36px 0 24px;
    max-width: 530px;
}
.login-copy {
    color: #CBD5E1;
    font-size: 1.04rem;
    line-height: 1.65;
    max-width: 540px;
}
.login-quote {
    color: #A7F3D0;
    font-style: italic;
    font-weight: 700;
    margin-top: 58px;
}
.login-footer {
    color: #94A3B8;
    font-size: .82rem;
    margin-top: 18px;
}
div[data-testid="stForm"] {
    border: 1px solid #E2E8F0;
    border-radius: 18px;
    padding: 1.25rem 1.25rem .4rem;
    background: #FFFFFF;
    box-shadow: 0 14px 38px rgba(15, 23, 42, .08);
}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


def _clear_sensitive_session_state() -> None:
    keys_to_clear = {
        "authenticated",
        "authenticated_user",
        "access_key",
        "secret_key",
        "summary",
        "details",
        "auth_rows",
        "invalid_rows",
        "login_failed_attempts",
        "login_lockout_until",
    }
    for key in keys_to_clear:
        st.session_state.pop(key, None)


def _login_lock_seconds() -> int:
    lockout_until = float(
        st.session_state.get("login_lockout_until", 0.0) or 0.0
    )
    return max(0, int(lockout_until - time_module.time()))


def require_login(auth: LocalAuthManager) -> bool:
    if st.session_state.get("authenticated"):
        return True

    st.markdown(
        """
        <style>
        [data-testid="stSidebar"] {display: none;}
        [data-testid="stHeader"] {background: transparent;}
        .block-container {max-width: 1180px; padding-top: 3rem;}
        </style>
        """,
        unsafe_allow_html=True,
    )

    form_column, hero_column = st.columns([0.43, 0.57], gap="large")

    with form_column:
        st.markdown(
            '<div class="login-brand">N-IPV</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            '<div class="login-subbrand">Nessus IP Validation Platform</div>',
            unsafe_allow_html=True,
        )

        setup_mode = not auth.is_configured()
        if setup_mode:
            st.header("Create secure access")
            st.caption(
                "First launch setup. Create the local administrator account "
                "used to protect this dashboard."
            )
            with st.form("create_local_login", clear_on_submit=False):
                username = st.text_input(
                    "Username",
                    autocomplete="username",
                )
                password = st.text_input(
                    "Password",
                    type="password",
                    autocomplete="new-password",
                    help="Use at least 8 characters.",
                )
                confirm_password = st.text_input(
                    "Confirm password",
                    type="password",
                    autocomplete="new-password",
                )
                submitted = st.form_submit_button(
                    "Create Login",
                    type="primary",
                    use_container_width=True,
                )

            if submitted:
                try:
                    if password != confirm_password:
                        raise ValueError("Passwords do not match.")
                    auth.configure(username, password)
                    st.session_state["authenticated"] = True
                    st.session_state["authenticated_user"] = (
                        username.strip()
                    )
                    st.session_state["login_failed_attempts"] = 0
                    st.session_state["login_lockout_until"] = 0.0
                    st.rerun()
                except Exception as exc:
                    st.error(str(exc))
        else:
            st.header("Welcome back")
            st.caption(
                "Sign in to continue Nessus validation and remediation work."
            )

            remaining_lock = _login_lock_seconds()
            if remaining_lock:
                st.warning(
                    "Too many failed attempts. Try again in about "
                    f"{remaining_lock} seconds."
                )

            with st.form("local_login", clear_on_submit=False):
                username = st.text_input(
                    "Username",
                    autocomplete="username",
                )
                password = st.text_input(
                    "Password",
                    type="password",
                    autocomplete="current-password",
                )
                submitted = st.form_submit_button(
                    "Sign In",
                    type="primary",
                    use_container_width=True,
                    disabled=remaining_lock > 0,
                )

            if submitted:
                if auth.verify(username, password):
                    st.session_state["authenticated"] = True
                    st.session_state["authenticated_user"] = (
                        username.strip()
                    )
                    st.session_state["login_failed_attempts"] = 0
                    st.session_state["login_lockout_until"] = 0.0
                    st.rerun()

                failed_attempts = int(
                    st.session_state.get("login_failed_attempts", 0)
                ) + 1
                st.session_state["login_failed_attempts"] = failed_attempts
                if failed_attempts >= 5:
                    st.session_state["login_failed_attempts"] = 0
                    st.session_state["login_lockout_until"] = (
                        time_module.time() + 30
                    )
                    st.error(
                        "Invalid username or password. Login is temporarily "
                        "locked for 30 seconds."
                    )
                else:
                    remaining_attempts = 5 - failed_attempts
                    st.error(
                        "Invalid username or password. "
                        f"{remaining_attempts} attempt(s) remain before "
                        "temporary lockout."
                    )

        st.info(
            "The password is stored only as a salted PBKDF2 hash in your "
            "local user profile. Nessus API keys are not saved by this login."
        )

    with hero_column:
        st.markdown(
            """
            <div class="login-hero">
                <div class="login-kicker">Nessus Asset Assurance</div>
                <div class="login-headline">
                    KNOW WHERE EVERY ASSET WAS SCANNED
                </div>
                <div class="login-copy">
                    Validate IP lists across folders, configured targets,
                    latest scan histories, host results, and authentication
                    evidence. Separate successful, partial, failed, and
                    not-yet-scanned assets before reporting.
                </div>
                <div class="login-quote">
                    “Visibility becomes useful when every missing result has a reason.”
                </div>
                <div class="login-footer">
                    Local dashboard access protection inspired by Trinetra.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    return False


AUTH_MANAGER = LocalAuthManager()
if not require_login(AUTH_MANAGER):
    st.stop()

st.title("🛡️ Nessus IP-to-Folder Validator")
st.caption(
    "Validate Excel/CSV IP lists across Nessus scan folders, latest scan "
    "history, configured targets, host results, and authentication evidence."
)


def read_input_file(uploaded) -> pd.DataFrame:
    name = uploaded.name.lower()
    if name.endswith(".csv"):
        return pd.read_csv(uploaded, dtype=str, keep_default_na=False)
    if name.endswith((".xlsx", ".xlsm", ".xls")):
        return pd.read_excel(uploaded, dtype=str, keep_default_na=False)
    raise ValueError("Upload only CSV or Excel file.")


def auto_ip_column(df: pd.DataFrame) -> str:
    preferred = [
        "ip",
        "ip address",
        "ip_address",
        "host",
        "hostname",
        "asset",
        "asset ip",
        "server ip",
    ]
    lower_map = {column.lower().strip(): column for column in df.columns}
    for preferred_name in preferred:
        if preferred_name in lower_map:
            return lower_map[preferred_name]
    for column in df.columns:
        if df[column].map(normalize_ip).notna().any():
            return column
    return df.columns[0]


def to_excel_bytes(
    summary: pd.DataFrame,
    details: pd.DataFrame,
    auth: pd.DataFrame,
) -> bytes:
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        summary.to_excel(writer, index=False, sheet_name="Summary")
        details.to_excel(writer, index=False, sheet_name="All_Matches")
        auth.to_excel(writer, index=False, sheet_name="Auth_Evidence")
        workbook = writer.book
        header_format = workbook.add_format(
            {
                "bold": True,
                "bg_color": "#1F4E78",
                "font_color": "white",
                "border": 1,
            }
        )
        wrap_format = workbook.add_format(
            {"text_wrap": True, "valign": "top"}
        )
        for sheet_name, frame in (
            ("Summary", summary),
            ("All_Matches", details),
            ("Auth_Evidence", auth),
        ):
            worksheet = writer.sheets[sheet_name]
            for column_number, column_name in enumerate(frame.columns):
                worksheet.write(
                    0,
                    column_number,
                    column_name,
                    header_format,
                )
                width = min(max(len(str(column_name)) + 2, 14), 45)
                if not frame.empty:
                    width = min(
                        max(
                            width,
                            int(
                                frame[column_name]
                                .astype(str)
                                .map(len)
                                .quantile(0.9)
                            )
                            + 2,
                        ),
                        55,
                    )
                worksheet.set_column(
                    column_number,
                    column_number,
                    width,
                    wrap_format,
                )
            worksheet.freeze_panes(1, 0)
            worksheet.autofilter(
                0,
                0,
                max(len(frame), 1),
                max(len(frame.columns) - 1, 0),
            )
    return output.getvalue()


def build_client() -> NessusClient:
    return NessusClient(
        base_url=st.session_state["base_url"],
        access_key=st.session_state["access_key"],
        secret_key=st.session_state["secret_key"],
        verify_ssl=st.session_state["verify_ssl"],
        timeout=int(st.session_state["timeout"]),
    )


with st.sidebar:
    st.header("Signed in")
    signed_in_user = st.session_state.get(
        "authenticated_user",
        AUTH_MANAGER.configured_username(),
    )
    st.success(f"👤 {signed_in_user}")
    if st.button("Sign Out", use_container_width=True):
        _clear_sensitive_session_state()
        st.rerun()

    st.divider()
    st.header("Connection")
    st.text_input(
        "Nessus / Tenable Base URL",
        value="https://cloud.tenable.com",
        key="base_url",
        help="For standalone Nessus, use https://<nessus-ip>:8834",
    )
    st.text_input("Access Key", type="password", key="access_key")
    st.text_input("Secret Key", type="password", key="secret_key")
    st.checkbox("Verify SSL certificate", value=True, key="verify_ssl")
    st.number_input(
        "API timeout seconds",
        min_value=15,
        max_value=300,
        value=90,
        step=15,
        key="timeout",
    )

    st.header("Collection Mode")
    mode = st.selectbox(
        "Mode",
        [
            "Fast API mode",
            "Fast API + host details",
            "Reliable CSV export mode",
        ],
        index=0,
        help=(
            "Fast mode automatically opens host details when a host is "
            "returned only as a DNS name. CSV export remains best for "
            "exact Plugin Output."
        ),
    )
    include_history = st.checkbox(
        "Include older scan histories",
        value=False,
        help=(
            "Disabled: check only the latest scan run. "
            "Enabled: also search older runs."
        ),
    )
    st.caption(
        "Recommended: leave disabled so authentication is based only on "
        "the latest run."
    )

    use_date_filter = st.checkbox(
        "Use scan started date filter",
        value=False,
    )
    start_date = end_date = None
    if use_date_filter:
        start_date = st.date_input("Started from")
        end_date = st.date_input("Started to")

    max_scans = st.number_input(
        "Max scans to process (0 = all)",
        min_value=0,
        value=0,
        step=10,
    )

main_left, main_right = st.columns([0.62, 0.38])

with main_left:
    uploaded = st.file_uploader(
        "Upload IP list CSV/XLSX",
        type=["csv", "xlsx", "xlsm", "xls"],
    )
    input_df = None
    ip_column = None
    if uploaded:
        try:
            input_df = read_input_file(uploaded)
            st.success(f"Loaded {len(input_df)} rows from {uploaded.name}")
            auto_column = auto_ip_column(input_df)
            ip_column = st.selectbox(
                "Select IP column",
                input_df.columns,
                index=list(input_df.columns).index(auto_column),
            )
            st.dataframe(
                input_df.head(10).copy(),
                use_container_width=True,
            )
        except Exception as exc:
            st.error(f"Input file error: {exc}")

with main_right:
    st.subheader("Output fields")
    st.markdown(
        """
        - Present in Nessus
        - Presence type: scan result, configured target, or scan-name fallback
        - Folder and scan details
        - Latest-history availability and result note
        - Authentication status and exact failure evidence
        - Match count and evidence source
        """
    )
    st.info(
        "An IP configured in a scan is no longer marked Not Found just "
        "because Nessus returned an empty host list or a hostname instead "
        "of the IP."
    )

run = st.button(
    "🚀 Validate IPs in Nessus",
    type="primary",
    disabled=not uploaded,
)

if run:
    if (
        not st.session_state.get("access_key")
        or not st.session_state.get("secret_key")
    ):
        st.error("Please enter Access Key and Secret Key.")
        st.stop()

    if input_df is None or ip_column is None:
        st.error(
            "Please upload a valid CSV/XLSX file and select IP column."
        )
        st.stop()

    work_df = input_df.copy()
    work_df["Input IP"] = work_df[ip_column].astype(str)
    work_df["Normalized IP"] = work_df["Input IP"].map(normalize_ip)
    invalid = work_df[work_df["Normalized IP"].isna()]
    work_df = (
        work_df[work_df["Normalized IP"].notna()][
            ["Input IP", "Normalized IP"]
        ]
        .drop_duplicates()
    )
    input_ips = set(work_df["Normalized IP"].astype(str))

    if not input_ips:
        st.error("No valid IP addresses found in selected column.")
        st.stop()

    status_box = st.status("Connecting to Nessus API...", expanded=True)
    progress = st.progress(0)

    def progress_callback(done, total, message):
        progress.progress(
            min(done / max(total, 1), 1.0),
            text=message,
        )

    try:
        client = build_client()
        folder_map = client.list_folders()
        started_from = started_to = None

        if use_date_filter and start_date and end_date:
            started_from = unix_from_date(
                datetime.combine(
                    start_date,
                    time.min,
                    tzinfo=timezone.utc,
                )
            )
            started_to = unix_from_date(
                datetime.combine(
                    end_date,
                    time.max,
                    tzinfo=timezone.utc,
                )
            )

        status_box.write(f"Folders found: {len(folder_map)}")
        scans = client.list_scans(
            started_from=started_from,
            started_to=started_to,
        )
        scan_records = make_scan_records(scans, folder_map)

        if max_scans and max_scans > 0:
            scan_records = scan_records[: int(max_scans)]

        status_box.write(f"Scans selected: {len(scan_records)}")
        if not scan_records:
            st.warning("No scans found for selected filters.")
            st.stop()

        if mode == "Reliable CSV export mode":
            matches, auth_rows = build_index_csv_export(
                client,
                input_ips,
                scan_records,
                include_history=include_history,
                progress_callback=progress_callback,
            )
        else:
            matches, auth_rows = build_index_fast_api(
                client,
                input_ips,
                scan_records,
                include_history=include_history,
                fetch_host_details=mode == "Fast API + host details",
                progress_callback=progress_callback,
            )

        summary, details = summarize_results(
            work_df,
            matches,
            auth_rows,
        )
        status_box.update(
            label="Validation complete",
            state="complete",
            expanded=False,
        )
        progress.progress(1.0, text="Done")

        st.session_state["summary"] = summary
        st.session_state["details"] = details
        st.session_state["auth_rows"] = auth_rows
        st.session_state["invalid_rows"] = invalid

    except NessusAPIError as exc:
        status_box.update(
            label="API error",
            state="error",
            expanded=True,
        )
        st.error(str(exc))
        st.stop()

    except Exception as exc:
        status_box.update(
            label="Unexpected error",
            state="error",
            expanded=True,
        )
        st.exception(exc)
        st.stop()

if "summary" in st.session_state:
    summary = st.session_state["summary"]
    details = st.session_state.get("details", pd.DataFrame())
    auth_rows = st.session_state.get("auth_rows", pd.DataFrame())
    invalid_rows = st.session_state.get(
        "invalid_rows",
        pd.DataFrame(),
    )

    st.divider()
    st.subheader("Validation Summary")

    total = len(summary)
    found = (
        int((summary["Present in Nessus"] == "Yes").sum())
        if total
        else 0
    )
    not_found = total - found
    auth_ok = (
        int(
            summary["Authentication Status"]
            .isin(["Authenticated", "Valid with limitations"])
            .sum()
        )
        if total
        else 0
    )
    auth_failed = (
        int((summary["Authentication Status"] == "Failed").sum())
        if total
        else 0
    )
    target_only = (
        int((summary["Presence Type"] == "Configured target").sum())
        if total
        else 0
    )

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Input IPs", total)
    c2.metric("Found", found)
    c3.metric("Not Found", not_found)
    c4.metric("Configured Only", target_only)
    c5.metric("Auth OK / Limited", auth_ok)
    c6.metric("Auth Failed", auth_failed)

    st.dataframe(
        summary,
        use_container_width=True,
        height=460,
    )

    csv_bytes = summary.to_csv(index=False).encode("utf-8-sig")
    excel_bytes = to_excel_bytes(summary, details, auth_rows)
    download_csv, download_excel = st.columns(2)

    download_csv.download_button(
        "⬇️ Download Summary CSV",
        csv_bytes,
        file_name="nessus_ip_validation_summary.csv",
        mime="text/csv",
    )
    download_excel.download_button(
        "⬇️ Download Full Excel Report",
        excel_bytes,
        file_name="nessus_ip_validation_report.xlsx",
        mime=(
            "application/vnd.openxmlformats-officedocument."
            "spreadsheetml.sheet"
        ),
    )

    with st.expander("All scan/folder matches"):
        st.dataframe(
            details,
            use_container_width=True,
            height=360,
        )

    with st.expander("Authentication evidence rows"):
        st.dataframe(
            auth_rows,
            use_container_width=True,
            height=360,
        )

    if not invalid_rows.empty:
        with st.expander("Invalid input rows"):
            st.dataframe(
                invalid_rows,
                use_container_width=True,
            )
