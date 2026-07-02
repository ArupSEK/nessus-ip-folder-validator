from __future__ import annotations

import io
from datetime import datetime, time, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

from ip_utils import normalize_ip
from nessus_client import (
    NessusAPIError,
    NessusClient,
    build_index_csv_export,
    build_index_fast_api,
    make_scan_records,
    summarize_results,
    unix_from_date,
)

st.set_page_config(page_title="Nessus IP Validator", page_icon="🛡️", layout="wide")

CUSTOM_CSS = """
<style>
.block-container {padding-top: 1.5rem;}
.metric-card {border: 1px solid #263238; border-radius: 14px; padding: 1rem; background: #111827;}
.small-muted {color: #9CA3AF; font-size: 0.9rem;}
.success-pill {padding: 0.2rem 0.55rem; border-radius: 999px; background: #064E3B; color: #A7F3D0;}
.warn-pill {padding: 0.2rem 0.55rem; border-radius: 999px; background: #78350F; color: #FDE68A;}
.fail-pill {padding: 0.2rem 0.55rem; border-radius: 999px; background: #7F1D1D; color: #FECACA;}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

st.title("🛡️ Nessus IP-to-Folder Validator")
st.caption("Validate Excel/CSV IP lists across Nessus scan folders, scan histories, and authentication evidence.")


def read_input_file(uploaded) -> pd.DataFrame:
    name = uploaded.name.lower()
    if name.endswith(".csv"):
        df = pd.read_csv(uploaded, dtype=str, keep_default_na=False)
    elif name.endswith((".xlsx", ".xlsm", ".xls")):
        df = pd.read_excel(uploaded, dtype=str, keep_default_na=False)
    else:
        raise ValueError("Upload only CSV or Excel file.")
    return df


def auto_ip_column(df: pd.DataFrame) -> str:
    preferred = ["ip", "ip address", "ip_address", "host", "hostname", "asset", "asset ip", "server ip"]
    lower_map = {c.lower().strip(): c for c in df.columns}
    for p in preferred:
        if p in lower_map:
            return lower_map[p]
    # Pick first column with at least one valid IP.
    for c in df.columns:
        if df[c].map(normalize_ip).notna().any():
            return c
    return df.columns[0]


def to_excel_bytes(summary: pd.DataFrame, details: pd.DataFrame, auth: pd.DataFrame) -> bytes:
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        summary.to_excel(writer, index=False, sheet_name="Summary")
        details.to_excel(writer, index=False, sheet_name="All_Matches")
        auth.to_excel(writer, index=False, sheet_name="Auth_Evidence")
        workbook = writer.book
        header_fmt = workbook.add_format({"bold": True, "bg_color": "#1F4E78", "font_color": "white", "border": 1})
        wrap_fmt = workbook.add_format({"text_wrap": True, "valign": "top"})
        for sheet_name, df in [("Summary", summary), ("All_Matches", details), ("Auth_Evidence", auth)]:
            ws = writer.sheets[sheet_name]
            for col_num, col_name in enumerate(df.columns):
                ws.write(0, col_num, col_name, header_fmt)
                width = min(max(len(str(col_name)) + 2, 14), 45)
                if not df.empty:
                    width = min(max(width, int(df[col_name].astype(str).map(len).quantile(0.9)) + 2), 55)
                ws.set_column(col_num, col_num, width, wrap_fmt)
            ws.freeze_panes(1, 0)
            ws.autofilter(0, 0, max(len(df), 1), max(len(df.columns) - 1, 0))
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
    st.header("Connection")
    st.text_input("Nessus / Tenable Base URL", value="https://cloud.tenable.com", key="base_url", help="For standalone Nessus, use https://<nessus-ip>:8834")
    st.text_input("Access Key", type="password", key="access_key")
    st.text_input("Secret Key", type="password", key="secret_key")
    st.checkbox("Verify SSL certificate", value=True, key="verify_ssl")
    st.number_input("API timeout seconds", min_value=15, max_value=300, value=90, step=15, key="timeout")

    st.header("Collection Mode")
    mode = st.selectbox(
        "Mode",
        [
            "Fast API mode",
            "Fast API + host details",
            "Reliable CSV export mode",
        ],
        index=0,
        help="CSV export mode is slower but gives the best authentication reason because it parses Plugin Output.",
    )
    include_history = st.checkbox("Check scan history / older runs", value=True)
    st.caption("Disable history only when you need the latest run only.")

    use_date_filter = st.checkbox("Use scan started date filter", value=False)
    start_date = end_date = None
    if use_date_filter:
        start_date = st.date_input("Started from")
        end_date = st.date_input("Started to")

    max_scans = st.number_input("Max scans to process (0 = all)", min_value=0, value=0, step=10)

main_left, main_right = st.columns([0.62, 0.38])

with main_left:
    uploaded = st.file_uploader("Upload IP list CSV/XLSX", type=["csv", "xlsx", "xlsm", "xls"])
    input_df = None
    ip_col = None
    if uploaded:
        try:
            input_df = read_input_file(uploaded)
            st.success(f"Loaded {len(input_df)} rows from {uploaded.name}")
            ip_col = st.selectbox("Select IP column", input_df.columns, index=list(input_df.columns).index(auto_ip_column(input_df)))
            preview_df = input_df.head(10).copy()
            st.dataframe(preview_df, use_container_width=True)
        except Exception as exc:
            st.error(f"Input file error: {exc}")

with main_right:
    st.subheader("Output fields")
    st.markdown(
        """
        - Present in Nessus
        - Folder name and all folders
        - Scan name, date, and status
        - Authentication status
        - Failure reason from plugin evidence
        - All match count and evidence source
        """
    )
    st.info("CSV export mode is best when you need exact authentication failure reason from Plugin Output.")

run = st.button("🚀 Validate IPs in Nessus", type="primary", disabled=not uploaded)

if run:
    if not st.session_state.get("access_key") or not st.session_state.get("secret_key"):
        st.error("Please enter Access Key and Secret Key.")
        st.stop()
    if input_df is None or ip_col is None:
        st.error("Please upload a valid CSV/XLSX file and select IP column.")
        st.stop()

    work_df = input_df.copy()
    work_df["Input IP"] = work_df[ip_col].astype(str)
    work_df["Normalized IP"] = work_df["Input IP"].map(normalize_ip)
    invalid = work_df[work_df["Normalized IP"].isna()]
    work_df = work_df[work_df["Normalized IP"].notna()][["Input IP", "Normalized IP"]].drop_duplicates()
    input_ips = set(work_df["Normalized IP"].astype(str))

    if not input_ips:
        st.error("No valid IP addresses found in selected column.")
        st.stop()

    status_box = st.status("Connecting to Nessus API...", expanded=True)
    progress = st.progress(0)

    def progress_callback(done, total, message):
        progress.progress(min(done / max(total, 1), 1.0), text=message)

    try:
        client = build_client()
        folder_map = client.list_folders()
        started_from = started_to = None
        if use_date_filter and start_date and end_date:
            started_from = unix_from_date(datetime.combine(start_date, time.min, tzinfo=timezone.utc))
            started_to = unix_from_date(datetime.combine(end_date, time.max, tzinfo=timezone.utc))
        status_box.write(f"Folders found: {len(folder_map)}")
        scans = client.list_scans(started_from=started_from, started_to=started_to)
        scan_records = make_scan_records(scans, folder_map)
        if max_scans and max_scans > 0:
            scan_records = scan_records[: int(max_scans)]
        status_box.write(f"Scans selected: {len(scan_records)}")
        if not scan_records:
            st.warning("No scans found for selected filters.")
            st.stop()

        if mode == "Reliable CSV export mode":
            matches, auth_rows = build_index_csv_export(client, input_ips, scan_records, include_history=include_history, progress_callback=progress_callback)
        else:
            matches, auth_rows = build_index_fast_api(
                client,
                input_ips,
                scan_records,
                include_history=include_history,
                fetch_host_details=(mode == "Fast API + host details"),
                progress_callback=progress_callback,
            )
        summary, details = summarize_results(work_df, matches, auth_rows)
        status_box.update(label="Validation complete", state="complete", expanded=False)
        progress.progress(1.0, text="Done")

        st.session_state["summary"] = summary
        st.session_state["details"] = details
        st.session_state["auth_rows"] = auth_rows
        st.session_state["invalid_rows"] = invalid
    except NessusAPIError as exc:
        status_box.update(label="API error", state="error", expanded=True)
        st.error(str(exc))
        st.stop()
    except Exception as exc:
        status_box.update(label="Unexpected error", state="error", expanded=True)
        st.exception(exc)
        st.stop()

if "summary" in st.session_state:
    summary = st.session_state["summary"]
    details = st.session_state.get("details", pd.DataFrame())
    auth_rows = st.session_state.get("auth_rows", pd.DataFrame())
    invalid_rows = st.session_state.get("invalid_rows", pd.DataFrame())

    st.divider()
    st.subheader("Validation Summary")
    total = len(summary)
    found = int((summary["Present in Nessus"] == "Yes").sum()) if total else 0
    not_found = total - found
    auth_ok = int(summary["Authentication Status"].isin(["Authenticated", "Valid with limitations"]).sum()) if total else 0
    auth_failed = int((summary["Authentication Status"] == "Failed").sum()) if total else 0

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Input IPs", total)
    c2.metric("Found", found)
    c3.metric("Not Found", not_found)
    c4.metric("Auth OK / Limited", auth_ok)
    c5.metric("Auth Failed", auth_failed)

    st.dataframe(summary, use_container_width=True, height=460)

    csv_bytes = summary.to_csv(index=False).encode("utf-8-sig")
    excel_bytes = to_excel_bytes(summary, details, auth_rows)
    d1, d2 = st.columns(2)
    d1.download_button("⬇️ Download Summary CSV", csv_bytes, file_name="nessus_ip_validation_summary.csv", mime="text/csv")
    d2.download_button("⬇️ Download Full Excel Report", excel_bytes, file_name="nessus_ip_validation_report.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

    with st.expander("All scan/folder matches"):
        st.dataframe(details, use_container_width=True, height=360)
    with st.expander("Authentication evidence rows"):
        st.dataframe(auth_rows, use_container_width=True, height=360)
    if not invalid_rows.empty:
        with st.expander("Invalid / skipped input rows"):
            st.dataframe(invalid_rows, use_container_width=True)

st.divider()
st.caption("Tip: Start with Fast API mode. Use Reliable CSV export mode for final VAPT evidence and exact auth-failure reason.")
