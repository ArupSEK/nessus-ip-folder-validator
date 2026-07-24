from __future__ import annotations

import io
import time as time_module
from datetime import datetime, time, timezone

import pandas as pd
import streamlit as st

from ip_utils import normalize_ip
from local_auth import LocalAuthManager
from nessus_fixed import NessusAPIError, make_scan_records, summarize_results, unix_from_date
from two_step_validation import (
    NessusClient,
    build_location_index,
    candidate_scan_records,
    deep_validate_selected,
)

st.set_page_config(page_title="Nessus IP Validator", page_icon="🛡️", layout="wide")


def clear_session() -> None:
    for key in (
        "authenticated", "authenticated_user", "access_key", "secret_key",
        "summary", "details", "auth_rows", "invalid_rows", "work_df",
        "scan_records", "discovery_stats", "deep_stats", "deep_notice",
        "deep_selection_editor", "login_failed_attempts", "login_lockout_until",
    ):
        st.session_state.pop(key, None)


def lock_seconds() -> int:
    until = float(st.session_state.get("login_lockout_until", 0.0) or 0.0)
    return max(0, int(until - time_module.time()))


def require_login(auth: LocalAuthManager) -> None:
    if st.session_state.get("authenticated"):
        return
    st.title("🛡️ Nessus IP Validation Platform")
    setup = not auth.is_configured()
    if setup:
        st.subheader("Create local administrator login")
        with st.form("create_login"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            confirm = st.text_input("Confirm password", type="password")
            submitted = st.form_submit_button("Create Login", type="primary")
        if submitted:
            try:
                if password != confirm:
                    raise ValueError("Passwords do not match.")
                auth.configure(username, password)
                st.session_state["authenticated"] = True
                st.session_state["authenticated_user"] = username.strip()
                st.rerun()
            except Exception as exc:
                st.error(str(exc))
    else:
        remaining = lock_seconds()
        if remaining:
            st.warning(f"Too many failed attempts. Try again in {remaining} seconds.")
        with st.form("login"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button(
                "Sign In", type="primary", disabled=remaining > 0
            )
        if submitted:
            if auth.verify(username, password):
                st.session_state["authenticated"] = True
                st.session_state["authenticated_user"] = username.strip()
                st.session_state["login_failed_attempts"] = 0
                st.session_state["login_lockout_until"] = 0.0
                st.rerun()
            failed = int(st.session_state.get("login_failed_attempts", 0)) + 1
            if failed >= 5:
                st.session_state["login_failed_attempts"] = 0
                st.session_state["login_lockout_until"] = time_module.time() + 30
                st.error("Invalid credentials. Login is locked for 30 seconds.")
            else:
                st.session_state["login_failed_attempts"] = failed
                st.error(f"Invalid credentials. {5 - failed} attempt(s) remain.")
    st.caption("The local password is stored only as a salted PBKDF2 hash.")
    st.stop()


def build_client() -> NessusClient:
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
require_login(AUTH)

with st.sidebar:
    st.success(f"👤 {st.session_state.get('authenticated_user', AUTH.configured_username())}")
    if st.button("Sign Out", use_container_width=True):
        clear_session()
        st.rerun()
    st.header("Connection")
    st.text_input("Nessus / Tenable Base URL", value="https://cloud.tenable.com", key="base_url")
    st.text_input("Access Key", type="password", key="access_key")
    st.text_input("Secret Key", type="password", key="secret_key")
    st.checkbox("Verify SSL certificate", value=True, key="verify_ssl")
    st.number_input("API timeout seconds", min_value=15, max_value=300, value=90, step=15, key="timeout")

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

st.title("🛡️ Nessus IP-to-Folder Validator")
st.caption("First locate the exact folder and scan with low API use, then deep-validate only selected IPs.")

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
    st.dataframe(summary, use_container_width=True, height=420)

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
        st.dataframe(details, use_container_width=True, height=360)
    with st.expander("Authentication evidence rows"):
        st.dataframe(auth_rows, use_container_width=True, height=360)
    if not invalid.empty:
        with st.expander("Invalid input rows"):
            st.dataframe(invalid, use_container_width=True)
