import { afterEach, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { CssBaseline, ThemeProvider, createTheme } from "@mui/material";
import App from "./App";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

test("renders login screen when no active session is available", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify({ detail: "Authentication required." }), {
          status: 401,
          headers: { "Content-Type": "application/json" }
        })
      )
    )
  );

  render(
    <ThemeProvider theme={createTheme({ palette: { mode: "dark" } })}>
      <CssBaseline />
      <App mode="dark" />
    </ThemeProvider>
  );

  await waitFor(() => expect(screen.getAllByText("Nessus Lifecycle Console")[0]).toBeTruthy());
  expect(screen.getByRole("button", { name: "toggle color mode" })).toBeTruthy();
  expect(screen.getByRole("button", { name: "Sign in" })).toBeTruthy();
  expect(screen.getByLabelText("Username")).toBeTruthy();
  expect(screen.getByLabelText("Password")).toBeTruthy();
});

test("renders Nessus settings for an administrator session", async () => {
  vi.stubGlobal(
    "fetch",
    vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            username: "admin",
            roles: ["Administrator"],
            permissions: [],
            csrf_token: "csrf-1"
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" }
          }
        )
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            configured: true,
            base_url: "https://scanner.example.com:8834",
            verify_tls: true,
            timeout_seconds: 15,
            approved_hosts: ["scanner.example.com"],
            masked_access_key: "ACCE...2345",
            masked_secret_key: "SECR...2345",
            server_info: { server_version: "10.8.3" },
            api_permissions: ["SCAN_MANAGER"],
            capabilities: { "folders.list": true },
            validated_at: "2026-07-30T10:00:00+00:00"
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" }
          }
        )
      )
  );

  render(
    <ThemeProvider theme={createTheme({ palette: { mode: "dark" } })}>
      <CssBaseline />
      <App mode="dark" />
    </ThemeProvider>
  );

  await waitFor(() => expect(screen.getAllByText("Nessus Lifecycle Console")[0]).toBeTruthy());
  fireEvent.click(screen.getAllByRole("button", { name: "Nessus" })[0]);
  await waitFor(() => expect(screen.getByText("Nessus Connection")).toBeTruthy());
  expect(screen.getByDisplayValue("https://scanner.example.com:8834")).toBeTruthy();
  expect(screen.getByText("SCAN_MANAGER")).toBeTruthy();
});

test("renders folder management for an authorized session", async () => {
  vi.stubGlobal(
    "fetch",
    vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            username: "analyst",
            roles: ["Administrator"],
            permissions: ["folders.view", "folders.create", "folders.rename", "folders.delete"],
            csrf_token: "csrf-2"
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" }
          }
        )
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            folders: [
              {
                id: "folder-1",
                nessus_folder_id: "8",
                name: "Ops Team",
                folder_type: "custom",
                is_custom: true,
                owner: "admin",
                permission_status: "available",
                scan_count: 2,
                last_synchronized_at: "2026-07-30T10:00:00+00:00",
                deleted_at: null
              }
            ]
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" }
          }
        )
      )
  );

  render(
    <ThemeProvider theme={createTheme({ palette: { mode: "dark" } })}>
      <CssBaseline />
      <App mode="dark" />
    </ThemeProvider>
  );

  await waitFor(() => expect(screen.getAllByText("Nessus Lifecycle Console")[0]).toBeTruthy());
  fireEvent.click(screen.getAllByRole("button", { name: "Folders" })[0]);
  await waitFor(() => expect(screen.getAllByText("Create Folder")[0]).toBeTruthy());
  expect(screen.getAllByText("Ops Team")[0]).toBeTruthy();
});

test("renders the scan creation wizard for an authorized scan manager", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn((input) => {
      const url = typeof input === "string" ? input : input instanceof Request ? input.url : String(input);
      const path = url.startsWith("http") ? new URL(url).pathname + new URL(url).search : url;

      if (path === "/api/v1/auth/me") {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              username: "scan-admin",
              roles: ["Administrator"],
              permissions: ["scans.view", "scans.create", "folders.view"],
              csrf_token: "csrf-3"
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          )
        );
      }

      if (path === "/api/v1/dashboard/summary") {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              comparison_run_id: "cmp-1",
              previous_total: 0,
              latest_total: 0,
              new: 0,
              existing: 0,
              closed: 0,
              reopened: 0,
              not_validated: 0,
              severity_changed: 0,
              accepted_risk: 0,
              false_positive: 0,
              exceptions: 0,
              sla_overdue: 0,
              severity_breakdown: {},
              asset_coverage: {}
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          )
        );
      }

      if (path === "/api/v1/folders") {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              folders: [
                {
                  id: "folder-1",
                  nessus_folder_id: "4",
                  name: "abc",
                  folder_type: "custom",
                  is_custom: true,
                  owner: "admin",
                  permission_status: "available",
                  scan_count: 1,
                  last_synchronized_at: "2026-07-30T10:00:00+00:00",
                  deleted_at: null
                }
              ]
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          )
        );
      }

      if (path === "/api/v1/scans/templates") {
        return Promise.resolve(
          new Response(JSON.stringify({ templates: [{ uuid: "tmpl-1", title: "Basic Network Scan" }] }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          })
        );
      }

      if (path === "/api/v1/scans/policies") {
        return Promise.resolve(
          new Response(JSON.stringify({ policies: [{ id: "pol-1", name: "Hardened Policy", template_uuid: "tmpl-1", owner: "admin", has_credentials: true }] }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          })
        );
      }

      if (path === "/api/v1/scans/scanners") {
        return Promise.resolve(
          new Response(JSON.stringify({ scanners: [{ id: "scanner-1", name: "Local Scanner", type: "managed", status: "on" }] }), {
            status: 200,
            headers: { "Content-Type": "application/json" }
          })
        );
      }

      if (path === "/api/v1/scans") {
        return Promise.resolve(
          new Response(
            JSON.stringify({
              scans: [
                {
                  id: "scan-1",
                  nessus_scan_id: "15",
                  nessus_uuid: "uuid-15",
                  name: "Master Template",
                  folder_record_id: "folder-1",
                  folder_nessus_id: "4",
                  folder_name: "abc",
                  template_uuid: "tmpl-1",
                  scanner_id: "scanner-1",
                  targets: ["10.0.0.1"],
                  target_count: 1,
                  schedule_type: "on_demand",
                  owner: "admin",
                  status: "empty",
                  history_count: 0,
                  permission_status: "available",
                  last_launch_at: null,
                  last_completion_at: null,
                  last_synchronized_at: "2026-07-30T10:00:00+00:00",
                  deleted_at: null
                }
              ]
            }),
            { status: 200, headers: { "Content-Type": "application/json" } }
          )
        );
      }

      return Promise.resolve(
        new Response(JSON.stringify({ detail: `Unhandled path: ${path}` }), {
          status: 404,
          headers: { "Content-Type": "application/json" }
        })
      );
    })
  );

  render(
    <ThemeProvider theme={createTheme({ palette: { mode: "dark" } })}>
      <CssBaseline />
      <App mode="dark" />
    </ThemeProvider>
  );

  await waitFor(() => expect(screen.getAllByText("Nessus Lifecycle Console")[0]).toBeTruthy());
  fireEvent.click(screen.getAllByRole("button", { name: "Scans" })[0]);
  await waitFor(() => expect(screen.getByText("Create Scan Wizard")).toBeTruthy());
  expect(screen.getByText("Basic Details")).toBeTruthy();
  expect(screen.getByText("Target Scope")).toBeTruthy();
  expect(screen.getByText("Execution")).toBeTruthy();
  expect(screen.getByText("Review")).toBeTruthy();
});
