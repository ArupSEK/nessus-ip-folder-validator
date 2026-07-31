import React from "react";
import {
  Alert,
  AppBar,
  Box,
  Button,
  CardActionArea,
  Chip,
  CircularProgress,
  Divider,
  FormControl,
  FormControlLabel,
  Grid,
  IconButton,
  InputAdornment,
  InputLabel,
  LinearProgress,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  MenuItem,
  Paper,
  Select,
  Snackbar,
  Stack,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Toolbar,
  Tooltip,
  Typography
} from "@mui/material";
import type { PaletteMode } from "@mui/material";
import ShieldOutlinedIcon from "@mui/icons-material/ShieldOutlined";
import SpaceDashboardOutlinedIcon from "@mui/icons-material/SpaceDashboardOutlined";
import BugReportOutlinedIcon from "@mui/icons-material/BugReportOutlined";
import AssessmentOutlinedIcon from "@mui/icons-material/AssessmentOutlined";
import LoginOutlinedIcon from "@mui/icons-material/LoginOutlined";
import LogoutOutlinedIcon from "@mui/icons-material/LogoutOutlined";
import RefreshOutlinedIcon from "@mui/icons-material/RefreshOutlined";
import SaveOutlinedIcon from "@mui/icons-material/SaveOutlined";
import DownloadOutlinedIcon from "@mui/icons-material/DownloadOutlined";
import WbSunnyOutlinedIcon from "@mui/icons-material/WbSunnyOutlined";
import DarkModeOutlinedIcon from "@mui/icons-material/DarkModeOutlined";
import SearchOutlinedIcon from "@mui/icons-material/SearchOutlined";
import FactCheckOutlinedIcon from "@mui/icons-material/FactCheckOutlined";
import HistoryOutlinedIcon from "@mui/icons-material/HistoryOutlined";
import SettingsOutlinedIcon from "@mui/icons-material/SettingsOutlined";
import FolderOpenOutlinedIcon from "@mui/icons-material/FolderOpenOutlined";
import DnsOutlinedIcon from "@mui/icons-material/DnsOutlined";
import TravelExploreOutlinedIcon from "@mui/icons-material/TravelExploreOutlined";
import AddOutlinedIcon from "@mui/icons-material/AddOutlined";
import DeleteOutlineOutlinedIcon from "@mui/icons-material/DeleteOutlineOutlined";
import PlayArrowOutlinedIcon from "@mui/icons-material/PlayArrowOutlined";
import StopOutlinedIcon from "@mui/icons-material/StopOutlined";
import ContentCopyOutlinedIcon from "@mui/icons-material/ContentCopyOutlined";
import DriveFileMoveOutlinedIcon from "@mui/icons-material/DriveFileMoveOutlined";
import CloudUploadOutlinedIcon from "@mui/icons-material/CloudUploadOutlined";
import ScanCreateWizard from "./components/ScanCreateWizard";

type AppProps = {
  mode?: PaletteMode;
  onToggleColorMode?: () => void;
};

type SessionResponse = {
  username: string;
  roles: string[];
  permissions: string[];
  csrf_token: string;
};

type DashboardSummary = {
  comparison_run_id: string;
  previous_total: number;
  latest_total: number;
  new: number;
  existing: number;
  closed: number;
  reopened: number;
  not_validated: number;
  severity_changed: number;
  accepted_risk: number;
  false_positive: number;
  exceptions: number;
  sla_overdue: number;
  severity_breakdown: Record<string, number>;
  asset_coverage: Record<string, number>;
};

type DashboardFinding = {
  result_id: string;
  asset_key: string;
  finding_key: string;
  lifecycle_status: string;
  comparison_eligibility: string;
  severity: number;
  plugin_id: number;
  plugin_name: string;
  port: number;
  protocol: string;
  reason: string;
};

type DashboardFindingList = {
  comparison_run_id: string;
  total: number;
  findings: DashboardFinding[];
};

type WorkflowResponse = {
  id: string;
  finding_key: string;
  asset_key: string;
  workflow_status: string;
  owner: string;
  remediation_team: string;
  sla_start_date: string | null;
  due_date: string | null;
  days_overdue: number;
  target_date: string | null;
  actual_remediation_date: string | null;
  ticket_number: string;
  ticket_url: string;
  comments: string;
  evidence: string;
  rescan_requested: boolean;
  validation_status: string;
  is_technically_open: boolean;
};

type WorkflowDecision = {
  id: string;
  finding_workflow_id: string;
  decision_type: string;
  reason: string;
  business_justification: string;
  compensating_controls: string;
  start_date: string | null;
  expiry_date: string | null;
  review_date: string | null;
  evidence: string;
  status: string;
  renewal_history: string;
  approved_at: string | null;
};

type WorkflowDecisionList = {
  finding_key: string;
  decisions: WorkflowDecision[];
};

type AssetReviewAssetSummary = {
  stable_asset_key: string;
  hostname: string;
  fqdn: string;
  ipv4_address: string;
  ipv6_address: string;
  tenable_asset_uuid: string;
  agent_uuid: string;
};

type AssetReviewResponse = {
  id: string;
  left_asset: AssetReviewAssetSummary;
  right_asset: AssetReviewAssetSummary;
  match_basis: string[];
  status: string;
  canonical_asset_key: string;
  notes: string;
  resolved_at: string | null;
};

type AssetReviewListResponse = {
  total: number;
  reviews: AssetReviewResponse[];
};

type AuditEventResponse = {
  id: string;
  actor_username: string;
  timestamp: string;
  source_ip: string;
  action: string;
  object_type: string;
  object_id: string;
  object_name: string;
  result: string;
  justification: string;
  previous_state: string;
  new_state: string;
};

type AuditEventList = {
  total: number;
  events: AuditEventResponse[];
};

type NessusConfigurationResponse = {
  configured: boolean;
  base_url: string | null;
  verify_tls: boolean;
  timeout_seconds: number | null;
  approved_hosts: string[];
  masked_access_key: string | null;
  masked_secret_key: string | null;
  server_info: Record<string, string>;
  api_permissions: string[];
  capabilities: Record<string, boolean>;
  validated_at: string | null;
};

type NessusValidationResponse = {
  base_url: string;
  verify_tls: boolean;
  timeout_seconds: number;
  approved_hosts: string[];
  server_info: Record<string, string>;
  api_permissions: string[];
  capabilities: Record<string, boolean>;
};

type FolderResponse = {
  id: string;
  nessus_folder_id: string;
  name: string;
  folder_type: string;
  is_custom: boolean;
  owner: string;
  permission_status: string;
  scan_count: number;
  last_synchronized_at: string | null;
  deleted_at: string | null;
};

type FolderListResponse = {
  folders: FolderResponse[];
};

type FolderPreviewScan = {
  id?: string | number;
  uuid?: string;
  name?: string;
  status?: string;
  folder_id?: string | number;
};

type FolderDeletePreviewResponse = {
  folder: FolderResponse;
  affected_scans: FolderPreviewScan[];
  deletion_behavior: string;
};

type ScanResponse = {
  id: string;
  nessus_scan_id: string;
  nessus_uuid: string;
  name: string;
  folder_record_id: string | null;
  folder_nessus_id: string;
  folder_name: string;
  template_uuid: string;
  scanner_id: string;
  targets: string[];
  target_count: number;
  schedule_type: string;
  owner: string;
  status: string;
  history_count: number;
  permission_status: string;
  last_launch_at: string | null;
  last_completion_at: string | null;
  last_synchronized_at: string | null;
  deleted_at: string | null;
  permanently_deleted_at: string | null;
  is_restorable: boolean;
  is_permanently_deleted: boolean;
};

type ScanListResponse = {
  scans: ScanResponse[];
};

type ScanTemplateResponse = {
  uuid: string;
  title: string;
};

type TemplateListResponse = {
  templates: ScanTemplateResponse[];
};

type ScanPolicyResponse = {
  id: string;
  name: string;
  template_uuid: string;
  owner: string;
  has_credentials: boolean;
};

type PolicyListResponse = {
  policies: ScanPolicyResponse[];
};

type ScannerResponse = {
  id: string;
  name: string;
  type: string;
  status: string;
};

type ScannerListResponse = {
  scanners: ScannerResponse[];
};

type ScanHistoryResponse = {
  id: string;
  nessus_history_id: string;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  finding_count: number;
  is_baseline_locked: boolean;
  is_evidence_locked: boolean;
  deleted_at: string | null;
};

type ScanHistoryListResponse = {
  histories: ScanHistoryResponse[];
};

type IpSearchMatch = {
  query: string;
  normalized_ip: string;
  folder_name: string;
  scan_name: string;
  scan_status: string;
  reachability: string;
  authentication_status: string;
  credentialed_checks_status: string;
  last_scan_date: string | null;
};

type IpSearchResultItem = {
  query: string;
  normalized_ip: string | null;
  matches: IpSearchMatch[];
};

type IpSearchResponse = {
  total_inputs: number;
  unique_inputs: number;
  invalid_inputs: string[];
  results: IpSearchResultItem[];
};

type WorkflowDraft = {
  owner: string;
  remediation_team: string;
  workflow_status: string;
  sla_start_date: string;
  target_date: string;
  actual_remediation_date: string;
  ticket_number: string;
  ticket_url: string;
  comments: string;
  evidence: string;
  rescan_requested: boolean;
  validation_status: string;
};

type DecisionDraft = {
  decision_type: string;
  reason: string;
  business_justification: string;
  compensating_controls: string;
  start_date: string;
  expiry_date: string;
  review_date: string;
  evidence: string;
};

type NessusFormDraft = {
  base_url: string;
  access_key: string;
  secret_key: string;
  verify_tls: boolean;
  timeout_seconds: string;
  approved_hosts: string;
};

type NessusResetDraft = {
  current_password: string;
  confirmation_text: string;
};

type FolderDeleteDraft = {
  confirmation_name: string;
  current_password: string;
};

type ScanCreateDraft = {
  creation_mode: "template" | "policy" | "master_template";
  name: string;
  folder_record_id: string;
  template_uuid: string;
  policy_id: string;
  clone_from_scan_record_id: string;
  scanner_id: string;
  targets: string;
  schedule_type: string;
  launch_now: boolean;
};

type ScanUpdateDraft = {
  name: string;
  folder_record_id: string;
  scanner_id: string;
  targets: string;
  schedule_type: string;
};

type ScanCloneDraft = {
  name: string;
  folder_record_id: string;
  scanner_id: string;
  launch_now: boolean;
};

type AssetReviewDraft = {
  canonical_asset_key: string;
  notes: string;
};

type ActiveSection = "dashboard" | "findings" | "folders" | "scans" | "ip-search" | "audit" | "reports" | "settings";

type ReportTypeOption = {
  value: string;
  label: string;
  description: string;
  comparisonScoped?: boolean;
  requiresEntries?: boolean;
  supportsDaysUntilExpiry?: boolean;
};

const sections: Array<{ id: ActiveSection; label: string; icon: React.ReactNode }> = [
  { id: "dashboard", label: "Overview", icon: <SpaceDashboardOutlinedIcon fontSize="small" /> },
  { id: "findings", label: "Findings", icon: <BugReportOutlinedIcon fontSize="small" /> },
  { id: "folders", label: "Folders", icon: <FolderOpenOutlinedIcon fontSize="small" /> },
  { id: "scans", label: "Scans", icon: <DnsOutlinedIcon fontSize="small" /> },
  { id: "ip-search", label: "IP Search", icon: <TravelExploreOutlinedIcon fontSize="small" /> },
  { id: "audit", label: "Audit", icon: <HistoryOutlinedIcon fontSize="small" /> },
  { id: "reports", label: "Reports", icon: <AssessmentOutlinedIcon fontSize="small" /> },
  { id: "settings", label: "Nessus", icon: <SettingsOutlinedIcon fontSize="small" /> }
];

const lifecycleCards: Array<{ key: keyof DashboardSummary; label: string; color: "primary" | "success" | "warning" | "info" | "default"; filter?: string }> = [
  { key: "new", label: "New", color: "primary", filter: "New" },
  { key: "existing", label: "Existing", color: "info", filter: "Existing" },
  { key: "closed", label: "Closed", color: "success", filter: "Closed" },
  { key: "reopened", label: "Reopened", color: "warning", filter: "Reopened" },
  { key: "not_validated", label: "Not Validated", color: "warning", filter: "Not Validated" },
  { key: "severity_changed", label: "Severity Changed", color: "default", filter: "Severity Changed" }
];

const severityLabels = [
  { value: "", label: "All severities" },
  { value: "4", label: "Critical" },
  { value: "3", label: "High" },
  { value: "2", label: "Medium" },
  { value: "1", label: "Low" },
  { value: "0", label: "Informational" }
];

const workflowStatuses = [
  "Open",
  "Assigned",
  "Analysis in progress",
  "Remediation in progress",
  "Pending patch",
  "Pending vendor",
  "Pending change",
  "Ready for rescan",
  "Rescan scheduled",
  "Validation in progress",
  "Closed",
  "Reopened",
  "Risk accepted",
  "Exception Approved",
  "False positive"
];

const scanScheduleOptions = [
  { value: "on_demand", label: "On demand" },
  { value: "once", label: "One time" },
  { value: "daily", label: "Daily" },
  { value: "weekly", label: "Weekly" },
  { value: "monthly", label: "Monthly" }
];

const reportTypes: ReportTypeOption[] = [
  { value: "scan_comparison", label: "Scan Comparison", description: "Lifecycle delta for the latest or selected comparison run.", comparisonScoped: true },
  { value: "new_findings", label: "New Findings", description: "Findings introduced in the current comparison run.", comparisonScoped: true },
  { value: "existing_findings", label: "Existing Findings", description: "Findings that remain open across runs.", comparisonScoped: true },
  { value: "closed_findings", label: "Closed Findings", description: "Findings that disappeared in the latest comparison.", comparisonScoped: true },
  { value: "reopened_findings", label: "Reopened Findings", description: "Findings that returned after previously closing.", comparisonScoped: true },
  { value: "not_validated_findings", label: "Not Validated Findings", description: "Findings awaiting analyst validation.", comparisonScoped: true },
  { value: "global_ip_search", label: "Global IP Search", description: "Export matches for manual IP or CIDR queries.", requiresEntries: true },
  { value: "scan_authentication_status", label: "Scan Authentication Status", description: "Credentialed reachability and authentication outcomes from completed imports." },
  { value: "sla_overdue", label: "SLA Overdue", description: "Open findings that are currently beyond SLA due date." },
  { value: "risk_acceptance", label: "Risk Acceptance", description: "Approved risk acceptance decisions with workflow context." },
  { value: "expiring_exceptions", label: "Expiring Exceptions", description: "Approved exceptions that expire within the selected window.", supportsDaysUntilExpiry: true },
  { value: "folder_inventory", label: "Folder Inventory", description: "Current synchronized folder inventory." },
  { value: "scan_inventory", label: "Scan Inventory", description: "Current synchronized scan inventory, including trash state." },
  { value: "audit_events", label: "Audit Events", description: "Administrative and operational audit history." },
  { value: "deleted_objects_audit", label: "Deleted Objects Audit", description: "Deletion and trash lifecycle audit trail." }
];

const decisionTypeLabels: Record<string, string> = {
  exception: "Exception",
  risk_acceptance: "Risk Acceptance",
  false_positive: "False Positive"
};

function severityName(value: number): string {
  if (value >= 4) return "Critical";
  if (value === 3) return "High";
  if (value === 2) return "Medium";
  if (value === 1) return "Low";
  return "Informational";
}

function emptyWorkflowDraft(): WorkflowDraft {
  return {
    owner: "",
    remediation_team: "",
    workflow_status: "Open",
    sla_start_date: "",
    target_date: "",
    actual_remediation_date: "",
    ticket_number: "",
    ticket_url: "",
    comments: "",
    evidence: "",
    rescan_requested: false,
    validation_status: ""
  };
}

function draftFromWorkflow(value: WorkflowResponse): WorkflowDraft {
  return {
    owner: value.owner,
    remediation_team: value.remediation_team,
    workflow_status: value.workflow_status,
    sla_start_date: value.sla_start_date ?? "",
    target_date: value.target_date ?? "",
    actual_remediation_date: value.actual_remediation_date ?? "",
    ticket_number: value.ticket_number,
    ticket_url: value.ticket_url,
    comments: value.comments,
    evidence: value.evidence,
    rescan_requested: value.rescan_requested,
    validation_status: value.validation_status
  };
}

function emptyDecisionDraft(): DecisionDraft {
  return {
    decision_type: "exception",
    reason: "",
    business_justification: "",
    compensating_controls: "",
    start_date: "",
    expiry_date: "",
    review_date: "",
    evidence: ""
  };
}

function emptyAssetReviewDraft(): AssetReviewDraft {
  return {
    canonical_asset_key: "",
    notes: ""
  };
}

function emptyNessusForm(): NessusFormDraft {
  return {
    base_url: "",
    access_key: "",
    secret_key: "",
    verify_tls: true,
    timeout_seconds: "15",
    approved_hosts: ""
  };
}

function emptyNessusResetDraft(): NessusResetDraft {
  return {
    current_password: "",
    confirmation_text: ""
  };
}

function draftFromNessusConfig(value: NessusConfigurationResponse | null): NessusFormDraft {
  if (!value) {
    return emptyNessusForm();
  }
  return {
    base_url: value.base_url ?? "",
    access_key: "",
    secret_key: "",
    verify_tls: value.verify_tls,
    timeout_seconds: String(value.timeout_seconds ?? 15),
    approved_hosts: value.approved_hosts.join(", ")
  };
}

function parseApprovedHosts(value: string): string[] {
  return Array.from(
    new Set(
      value
        .split(/[\n,]/)
        .map((item) => item.trim())
        .filter(Boolean)
    )
  );
}

function formatTimestamp(value: string | null | undefined): string {
  if (!value) {
    return "-";
  }
  return value.replace("T", " ").replace("+00:00", " UTC");
}

function parseTargetsInput(value: string): string[] {
  return Array.from(
    new Set(
      value
        .split(/[\n,]/)
        .map((item) => item.trim())
        .filter(Boolean)
    )
  );
}

function targetsToText(value: string[]): string {
  return value.join("\n");
}

function emptyFolderDeleteDraft(): FolderDeleteDraft {
  return {
    confirmation_name: "",
    current_password: ""
  };
}

function emptyScanCreateDraft(): ScanCreateDraft {
  return {
    creation_mode: "template",
    name: "",
    folder_record_id: "",
    template_uuid: "",
    policy_id: "",
    clone_from_scan_record_id: "",
    scanner_id: "",
    targets: "",
    schedule_type: "on_demand",
    launch_now: false
  };
}

function emptyScanUpdateDraft(): ScanUpdateDraft {
  return {
    name: "",
    folder_record_id: "",
    scanner_id: "",
    targets: "",
    schedule_type: "on_demand"
  };
}

function emptyScanCloneDraft(): ScanCloneDraft {
  return {
    name: "",
    folder_record_id: "",
    scanner_id: "",
    launch_now: false
  };
}

function draftFromScan(value: ScanResponse | null): ScanUpdateDraft {
  if (!value) {
    return emptyScanUpdateDraft();
  }
  return {
    name: value.name,
    folder_record_id: value.folder_record_id || "",
    scanner_id: value.scanner_id,
    targets: targetsToText(value.targets),
    schedule_type: value.schedule_type
  };
}

function cloneDraftFromScan(value: ScanResponse | null): ScanCloneDraft {
  if (!value) {
    return emptyScanCloneDraft();
  }
  return {
    name: `${value.name} Copy`,
    folder_record_id: value.folder_record_id || "",
    scanner_id: value.scanner_id,
    launch_now: false
  };
}

async function parseError(response: Response): Promise<string> {
  try {
    const payload = (await response.json()) as { detail?: string };
    return payload.detail || response.statusText || "Request failed.";
  } catch {
    return response.statusText || "Request failed.";
  }
}

export default function App({ mode = "dark", onToggleColorMode = () => undefined }: AppProps) {
  const [session, setSession] = React.useState<SessionResponse | null>(null);
  const [sessionLoading, setSessionLoading] = React.useState(true);
  const [activeSection, setActiveSection] = React.useState<ActiveSection>("dashboard");
  const [loginForm, setLoginForm] = React.useState({ username: "admin", password: "" });
  const [loginBusy, setLoginBusy] = React.useState(false);
  const [summary, setSummary] = React.useState<DashboardSummary | null>(null);
  const [summaryLoading, setSummaryLoading] = React.useState(false);
  const [findings, setFindings] = React.useState<DashboardFinding[]>([]);
  const [findingsLoading, setFindingsLoading] = React.useState(false);
  const [lifecycleFilter, setLifecycleFilter] = React.useState("");
  const [severityFilter, setSeverityFilter] = React.useState("");
  const [search, setSearch] = React.useState("");
  const [selectedFinding, setSelectedFinding] = React.useState<DashboardFinding | null>(null);
  const [assetReviews, setAssetReviews] = React.useState<AssetReviewResponse[]>([]);
  const [assetReviewsLoading, setAssetReviewsLoading] = React.useState(false);
  const [selectedAssetReviewId, setSelectedAssetReviewId] = React.useState("");
  const [assetReviewDraft, setAssetReviewDraft] = React.useState<AssetReviewDraft>(emptyAssetReviewDraft());
  const [assetReviewBusy, setAssetReviewBusy] = React.useState("");
  const [workflow, setWorkflow] = React.useState<WorkflowResponse | null>(null);
  const [workflowDraft, setWorkflowDraft] = React.useState<WorkflowDraft>(emptyWorkflowDraft());
  const [workflowLoading, setWorkflowLoading] = React.useState(false);
  const [workflowSaving, setWorkflowSaving] = React.useState(false);
  const [decisions, setDecisions] = React.useState<WorkflowDecision[]>([]);
  const [decisionsLoading, setDecisionsLoading] = React.useState(false);
  const [decisionDraft, setDecisionDraft] = React.useState<DecisionDraft>(emptyDecisionDraft());
  const [decisionBusy, setDecisionBusy] = React.useState(false);
  const [decisionApproval, setDecisionApproval] = React.useState(false);
  const [auditEvents, setAuditEvents] = React.useState<AuditEventResponse[]>([]);
  const [auditLoading, setAuditLoading] = React.useState(false);
  const [auditActionFilter, setAuditActionFilter] = React.useState("");
  const [auditObjectTypeFilter, setAuditObjectTypeFilter] = React.useState("");
  const [auditResultFilter, setAuditResultFilter] = React.useState("");
  const [auditSearch, setAuditSearch] = React.useState("");
  const [nessusConfig, setNessusConfig] = React.useState<NessusConfigurationResponse | null>(null);
  const [nessusValidation, setNessusValidation] = React.useState<NessusValidationResponse | null>(null);
  const [nessusForm, setNessusForm] = React.useState<NessusFormDraft>(emptyNessusForm());
  const [nessusReset, setNessusReset] = React.useState<NessusResetDraft>(emptyNessusResetDraft());
  const [nessusLoading, setNessusLoading] = React.useState(false);
  const [nessusTesting, setNessusTesting] = React.useState(false);
  const [nessusSaving, setNessusSaving] = React.useState(false);
  const [nessusResetting, setNessusResetting] = React.useState(false);
  const [folders, setFolders] = React.useState<FolderResponse[]>([]);
  const [foldersLoading, setFoldersLoading] = React.useState(false);
  const [folderSearch, setFolderSearch] = React.useState("");
  const [selectedFolderId, setSelectedFolderId] = React.useState("");
  const [folderCreateName, setFolderCreateName] = React.useState("");
  const [folderRenameName, setFolderRenameName] = React.useState("");
  const [folderDeleteDraft, setFolderDeleteDraft] = React.useState<FolderDeleteDraft>(emptyFolderDeleteDraft());
  const [folderDeletePreview, setFolderDeletePreview] = React.useState<FolderDeletePreviewResponse | null>(null);
  const [folderCreateBusy, setFolderCreateBusy] = React.useState(false);
  const [folderRenameBusy, setFolderRenameBusy] = React.useState(false);
  const [folderPreviewBusy, setFolderPreviewBusy] = React.useState(false);
  const [folderDeleteBusy, setFolderDeleteBusy] = React.useState(false);
  const [scans, setScans] = React.useState<ScanResponse[]>([]);
  const [scansLoading, setScansLoading] = React.useState(false);
  const [scanSearch, setScanSearch] = React.useState("");
  const [selectedScanId, setSelectedScanId] = React.useState("");
  const [scanTemplates, setScanTemplates] = React.useState<ScanTemplateResponse[]>([]);
  const [scanPolicies, setScanPolicies] = React.useState<ScanPolicyResponse[]>([]);
  const [scanners, setScanners] = React.useState<ScannerResponse[]>([]);
  const [scanDependenciesLoading, setScanDependenciesLoading] = React.useState(false);
  const [scanCreateDraft, setScanCreateDraft] = React.useState<ScanCreateDraft>(emptyScanCreateDraft());
  const [scanUpdateDraft, setScanUpdateDraft] = React.useState<ScanUpdateDraft>(emptyScanUpdateDraft());
  const [scanCloneDraft, setScanCloneDraft] = React.useState<ScanCloneDraft>(emptyScanCloneDraft());
  const [scanCreateBusy, setScanCreateBusy] = React.useState(false);
  const [scanCreateWizardVersion, setScanCreateWizardVersion] = React.useState(0);
  const [scanUpdateBusy, setScanUpdateBusy] = React.useState(false);
  const [scanCloneBusy, setScanCloneBusy] = React.useState(false);
  const [scanActionBusy, setScanActionBusy] = React.useState("");
  const [scanHistories, setScanHistories] = React.useState<ScanHistoryResponse[]>([]);
  const [scanHistoryLoading, setScanHistoryLoading] = React.useState(false);
  const [scanHistoryDeleteJustification, setScanHistoryDeleteJustification] = React.useState("");
  const [scanHistoryDeleteBusy, setScanHistoryDeleteBusy] = React.useState("");
  const [ipSearchEntries, setIpSearchEntries] = React.useState("");
  const [ipSearchExpandCidr, setIpSearchExpandCidr] = React.useState(false);
  const [ipSearchBusy, setIpSearchBusy] = React.useState(false);
  const [ipSearchUploadBusy, setIpSearchUploadBusy] = React.useState(false);
  const [ipSearchFile, setIpSearchFile] = React.useState<File | null>(null);
  const [ipSearchResponse, setIpSearchResponse] = React.useState<IpSearchResponse | null>(null);
  const [reportType, setReportType] = React.useState("scan_comparison");
  const [reportFormat, setReportFormat] = React.useState("csv");
  const [reportEntries, setReportEntries] = React.useState("");
  const [reportExpandCidr, setReportExpandCidr] = React.useState(false);
  const [reportDaysUntilExpiry, setReportDaysUntilExpiry] = React.useState("30");
  const [exportBusy, setExportBusy] = React.useState(false);
  const [banner, setBanner] = React.useState<{ tone: "success" | "error"; message: string } | null>(null);
  const isAdministrator = Boolean(session?.roles?.includes("Administrator"));

  const navigationSections = React.useMemo(() => {
    if (isAdministrator) {
      return sections;
    }
    return sections.filter((section) => section.id !== "settings");
  }, [isAdministrator]);

  const hasPermission = React.useCallback(
    (permission: string) => Boolean(session?.permissions?.includes(permission)),
    [session]
  );

  const selectedFolder = React.useMemo(
    () => folders.find((item) => item.id === selectedFolderId) || null,
    [folders, selectedFolderId]
  );

  const selectedScan = React.useMemo(
    () => scans.find((item) => item.id === selectedScanId) || null,
    [scans, selectedScanId]
  );

  const selectedAssetReview = React.useMemo(
    () => assetReviews.find((item) => item.id === selectedAssetReviewId) || null,
    [assetReviews, selectedAssetReviewId]
  );

  const availableMasterTemplates = React.useMemo(
    () => scans.filter((item) => !item.deleted_at),
    [scans]
  );

  const selectedReport = React.useMemo(
    () => reportTypes.find((item) => item.value === reportType) || reportTypes[0],
    [reportType]
  );

  const scanApiUnavailable = React.useMemo(
    () => nessusConfig?.capabilities?.["scans.api"] === false,
    [nessusConfig]
  );

  const fetchJson = React.useCallback(
    async <T,>(path: string, init: RequestInit = {}, requireCsrf = false): Promise<T> => {
      const headers = new Headers(init.headers || {});
      if (init.body && !(init.body instanceof FormData) && !headers.has("Content-Type")) {
        headers.set("Content-Type", "application/json");
      }
      if (requireCsrf && session?.csrf_token) {
        headers.set("X-CSRF-Token", session.csrf_token);
      }
      const response = await fetch(path, {
        ...init,
        headers,
        credentials: "include"
      });
      if (!response.ok) {
        throw new Error(await parseError(response));
      }
      return (await response.json()) as T;
    },
    [session]
  );

  const refreshSummary = React.useCallback(async () => {
    if (!session || !hasPermission("findings.view")) return;
    setSummaryLoading(true);
    try {
      const payload = await fetchJson<DashboardSummary>("/api/v1/dashboard/summary");
      setSummary(payload);
    } catch (error) {
      setSummary(null);
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Dashboard load failed." });
    } finally {
      setSummaryLoading(false);
    }
  }, [fetchJson, hasPermission, session]);

  const refreshFindings = React.useCallback(async () => {
    if (!session || !hasPermission("findings.view")) return;
    setFindingsLoading(true);
    try {
      const params = new URLSearchParams();
      if (summary?.comparison_run_id) params.set("comparison_run_id", summary.comparison_run_id);
      if (lifecycleFilter) params.set("lifecycle_status", lifecycleFilter);
      if (severityFilter) params.set("severity", severityFilter);
      if (search.trim()) params.set("search", search.trim());
      const payload = await fetchJson<DashboardFindingList>(`/api/v1/dashboard/findings?${params.toString()}`);
      setFindings(payload.findings);
      if (payload.findings.length > 0) {
        const nextSelection = payload.findings.find((item) => item.finding_key === selectedFinding?.finding_key) || payload.findings[0];
        setSelectedFinding(nextSelection);
      } else {
        setSelectedFinding(null);
      }
    } catch (error) {
      setFindings([]);
      setSelectedFinding(null);
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Finding list load failed." });
    } finally {
      setFindingsLoading(false);
    }
  }, [fetchJson, hasPermission, lifecycleFilter, search, selectedFinding?.finding_key, session, severityFilter, summary?.comparison_run_id]);

  const refreshAssetReviews = React.useCallback(async () => {
    if (!session || !hasPermission("findings.view")) return;
    setAssetReviewsLoading(true);
    try {
      const payload = await fetchJson<AssetReviewListResponse>("/api/v1/workflows/asset-reviews?status=pending");
      setAssetReviews(payload.reviews);
    } catch (error) {
      setAssetReviews([]);
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Asset review queue load failed." });
    } finally {
      setAssetReviewsLoading(false);
    }
  }, [fetchJson, hasPermission, session]);

  const refreshWorkflow = React.useCallback(
    async (findingKey: string) => {
      if (!session || !hasPermission("findings.view")) return;
      setWorkflowLoading(true);
      setDecisionsLoading(true);
      try {
        const [workflowPayload, decisionPayload] = await Promise.all([
          fetchJson<WorkflowResponse>(`/api/v1/workflows/findings/${encodeURIComponent(findingKey)}`),
          fetchJson<WorkflowDecisionList>(`/api/v1/workflows/findings/${encodeURIComponent(findingKey)}/decisions`)
        ]);
        setWorkflow(workflowPayload);
        setWorkflowDraft(draftFromWorkflow(workflowPayload));
        setDecisions(decisionPayload.decisions);
      } catch (error) {
        setWorkflow(null);
        setDecisions([]);
        setBanner({ tone: "error", message: error instanceof Error ? error.message : "Workflow load failed." });
      } finally {
        setWorkflowLoading(false);
        setDecisionsLoading(false);
      }
    },
    [fetchJson, hasPermission, session]
  );

  const refreshAudit = React.useCallback(async () => {
    if (!session || !hasPermission("audit.view")) return;
    setAuditLoading(true);
    try {
      const params = new URLSearchParams();
      if (auditActionFilter.trim()) params.set("action", auditActionFilter.trim());
      if (auditObjectTypeFilter.trim()) params.set("object_type", auditObjectTypeFilter.trim());
      if (auditResultFilter.trim()) params.set("result", auditResultFilter.trim());
      if (auditSearch.trim()) params.set("search", auditSearch.trim());
      params.set("limit", "100");
      const payload = await fetchJson<AuditEventList>(`/api/v1/audit/events?${params.toString()}`);
      setAuditEvents(payload.events);
    } catch (error) {
      setAuditEvents([]);
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Audit load failed." });
    } finally {
      setAuditLoading(false);
    }
  }, [auditActionFilter, auditObjectTypeFilter, auditResultFilter, auditSearch, fetchJson, hasPermission, session]);

  const refreshFolders = React.useCallback(
    async (remote = false) => {
      if (!session || !hasPermission("folders.view")) return;
      setFoldersLoading(true);
      try {
        const path = remote
          ? "/api/v1/folders/refresh"
          : `/api/v1/folders?${new URLSearchParams({ search: folderSearch.trim() }).toString()}`;
        const payload = remote
          ? await fetchJson<FolderListResponse>(path, { method: "POST" }, true)
          : await fetchJson<FolderListResponse>(path);
        setFolders(payload.folders);
      } catch (error) {
        setFolders([]);
        setBanner({ tone: "error", message: error instanceof Error ? error.message : "Folder load failed." });
      } finally {
        setFoldersLoading(false);
      }
    },
    [fetchJson, folderSearch, hasPermission, session]
  );

  const loadFolderDeletePreview = React.useCallback(
    async (folderId: string) => {
      if (!session || !hasPermission("folders.delete")) return;
      setFolderPreviewBusy(true);
      try {
        const payload = await fetchJson<FolderDeletePreviewResponse>(`/api/v1/folders/${encodeURIComponent(folderId)}/delete-preview`);
        setFolderDeletePreview(payload);
        setFolderDeleteDraft(emptyFolderDeleteDraft());
      } catch (error) {
        setFolderDeletePreview(null);
        setBanner({ tone: "error", message: error instanceof Error ? error.message : "Folder preview failed." });
      } finally {
        setFolderPreviewBusy(false);
      }
    },
    [fetchJson, hasPermission, session]
  );

  const refreshScanDependencies = React.useCallback(async () => {
    if (!session || !hasPermission("scans.create")) return;
    setScanDependenciesLoading(true);
    try {
      const [templatePayload, policyPayload, scannerPayload] = await Promise.all([
        fetchJson<TemplateListResponse>("/api/v1/scans/templates"),
        fetchJson<PolicyListResponse>("/api/v1/scans/policies"),
        fetchJson<ScannerListResponse>("/api/v1/scans/scanners")
      ]);
      setScanTemplates(templatePayload.templates);
      setScanPolicies(policyPayload.policies);
      setScanners(scannerPayload.scanners);
    } catch (error) {
      setScanTemplates([]);
      setScanPolicies([]);
      setScanners([]);
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Scan dependencies load failed." });
    } finally {
      setScanDependenciesLoading(false);
    }
  }, [fetchJson, hasPermission, session]);

  const refreshScans = React.useCallback(
    async (remote = false) => {
      if (!session || !hasPermission("scans.view")) return;
      setScansLoading(true);
      try {
        const path = remote
          ? "/api/v1/scans/refresh"
          : `/api/v1/scans?${new URLSearchParams({ search: scanSearch.trim() }).toString()}`;
        const payload = remote
          ? await fetchJson<ScanListResponse>(path, { method: "POST" }, true)
          : await fetchJson<ScanListResponse>(path);
        setScans(payload.scans);
      } catch (error) {
        setScans([]);
        setBanner({ tone: "error", message: error instanceof Error ? error.message : "Scan load failed." });
      } finally {
        setScansLoading(false);
      }
    },
    [fetchJson, hasPermission, scanSearch, session]
  );

  const refreshScanHistory = React.useCallback(
    async (scanId: string) => {
      if (!session || !hasPermission("scan_history.view")) return;
      setScanHistoryLoading(true);
      try {
        const payload = await fetchJson<ScanHistoryListResponse>(`/api/v1/scans/${encodeURIComponent(scanId)}/history`);
        setScanHistories(payload.histories);
      } catch (error) {
        setScanHistories([]);
        setBanner({ tone: "error", message: error instanceof Error ? error.message : "Scan history load failed." });
      } finally {
        setScanHistoryLoading(false);
      }
    },
    [fetchJson, hasPermission, session]
  );

  const refreshNessusConfig = React.useCallback(async () => {
    if (!session || !isAdministrator) return;
    setNessusLoading(true);
    try {
      const payload = await fetchJson<NessusConfigurationResponse>("/api/v1/nessus/configuration");
      setNessusConfig(payload);
      setNessusForm(draftFromNessusConfig(payload));
    } catch (error) {
      setNessusConfig(null);
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Nessus configuration load failed." });
    } finally {
      setNessusLoading(false);
    }
  }, [fetchJson, isAdministrator, session]);

  const loadSession = React.useCallback(async () => {
    setSessionLoading(true);
    try {
      const response = await fetch("/api/v1/auth/me", {
        credentials: "include"
      });
      if (!response.ok) {
        throw new Error("No active session.");
      }
      const payload = (await response.json()) as SessionResponse;
      setSession(payload);
    } catch {
      setSession(null);
    } finally {
      setSessionLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void loadSession();
  }, [loadSession]);

  React.useEffect(() => {
    if (!session) return;
    void refreshSummary();
  }, [refreshSummary, session]);

  React.useEffect(() => {
    if (!session || !summary) return;
    void refreshFindings();
  }, [refreshFindings, session, summary]);

  React.useEffect(() => {
    if (!session || activeSection !== "findings") return;
    void refreshAssetReviews();
  }, [activeSection, refreshAssetReviews, session]);

  React.useEffect(() => {
    if (selectedFinding) {
      void refreshWorkflow(selectedFinding.finding_key);
    } else {
      setWorkflow(null);
      setDecisions([]);
      setWorkflowDraft(emptyWorkflowDraft());
    }
  }, [refreshWorkflow, selectedFinding]);

  React.useEffect(() => {
    if (!session || activeSection !== "audit") return;
    void refreshAudit();
  }, [activeSection, refreshAudit, session]);

  React.useEffect(() => {
    if (!session || activeSection !== "folders") return;
    void refreshFolders();
  }, [activeSection, refreshFolders, session]);

  React.useEffect(() => {
    if (!session || activeSection !== "scans") return;
    void refreshScans();
    if (folders.length === 0 && hasPermission("folders.view")) {
      void refreshFolders();
    }
    if (scanTemplates.length === 0 || scanners.length === 0) {
      void refreshScanDependencies();
    }
  }, [activeSection, folders.length, hasPermission, refreshFolders, refreshScanDependencies, refreshScans, scanTemplates.length, scanners.length, session]);

  React.useEffect(() => {
    if (!session || activeSection !== "settings") return;
    void refreshNessusConfig();
  }, [activeSection, refreshNessusConfig, session]);

  React.useEffect(() => {
    if (folders.length === 0) {
      setSelectedFolderId("");
      return;
    }
    if (!folders.some((item) => item.id === selectedFolderId)) {
      setSelectedFolderId(folders[0].id);
    }
  }, [folders, selectedFolderId]);

  React.useEffect(() => {
    if (selectedFolder) {
      setFolderRenameName(selectedFolder.name);
      setFolderDeletePreview(null);
      setFolderDeleteDraft(emptyFolderDeleteDraft());
    }
  }, [selectedFolder]);

  React.useEffect(() => {
    if (scans.length === 0) {
      setSelectedScanId("");
      return;
    }
    if (!scans.some((item) => item.id === selectedScanId)) {
      setSelectedScanId(scans[0].id);
    }
  }, [scans, selectedScanId]);

  React.useEffect(() => {
    if (assetReviews.length === 0) {
      setSelectedAssetReviewId("");
      setAssetReviewDraft(emptyAssetReviewDraft());
      return;
    }
    if (!assetReviews.some((item) => item.id === selectedAssetReviewId)) {
      setSelectedAssetReviewId(assetReviews[0].id);
    }
  }, [assetReviews, selectedAssetReviewId]);

  React.useEffect(() => {
    if (!selectedAssetReview) {
      setAssetReviewDraft(emptyAssetReviewDraft());
      return;
    }
    setAssetReviewDraft({
      canonical_asset_key: selectedAssetReview.canonical_asset_key || selectedAssetReview.left_asset.stable_asset_key,
      notes: selectedAssetReview.notes
    });
  }, [selectedAssetReview]);

  React.useEffect(() => {
    if (folders.length === 0) return;
    setScanCreateDraft((current) => {
      const nextFolder = current.folder_record_id || folders[0].id;
      return nextFolder === current.folder_record_id ? current : { ...current, folder_record_id: nextFolder };
    });
  }, [folders]);

  React.useEffect(() => {
    setScanUpdateDraft(draftFromScan(selectedScan));
    setScanCloneDraft(cloneDraftFromScan(selectedScan));
    setScanHistoryDeleteJustification("");
    if (selectedScan && activeSection === "scans") {
      void refreshScanHistory(selectedScan.id);
    } else {
      setScanHistories([]);
    }
  }, [activeSection, refreshScanHistory, selectedScan]);

  async function handleLogin(): Promise<void> {
    setLoginBusy(true);
    try {
      const payload = await fetchJson<SessionResponse>("/api/v1/auth/login", {
        method: "POST",
        body: JSON.stringify(loginForm)
      });
      setSession(payload);
      setBanner({ tone: "success", message: `Signed in as ${payload.username}.` });
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Login failed." });
    } finally {
      setLoginBusy(false);
    }
  }

  async function handleLogout(): Promise<void> {
    try {
      await fetchJson<{ message: string }>(
        "/api/v1/auth/logout",
        {
          method: "POST"
        },
        true
      );
      setSession(null);
      setSummary(null);
      setFindings([]);
      setSelectedFinding(null);
      setWorkflow(null);
      setDecisions([]);
      setAuditEvents([]);
      setNessusConfig(null);
      setNessusValidation(null);
      setNessusForm(emptyNessusForm());
      setNessusReset(emptyNessusResetDraft());
      setFolders([]);
      setSelectedFolderId("");
      setFolderCreateName("");
      setFolderRenameName("");
      setFolderDeletePreview(null);
      setFolderDeleteDraft(emptyFolderDeleteDraft());
      setScans([]);
      setSelectedScanId("");
      setScanTemplates([]);
      setScanners([]);
      setScanCreateDraft(emptyScanCreateDraft());
      setScanUpdateDraft(emptyScanUpdateDraft());
      setScanCloneDraft(emptyScanCloneDraft());
      setScanHistories([]);
      setScanHistoryDeleteJustification("");
      setIpSearchEntries("");
      setIpSearchExpandCidr(false);
      setIpSearchFile(null);
      setIpSearchResponse(null);
      setBanner({ tone: "success", message: "Logged out." });
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Logout failed." });
    }
  }

  async function handleFolderCreate(): Promise<void> {
    setFolderCreateBusy(true);
    try {
      const payload = await fetchJson<FolderResponse>(
        "/api/v1/folders",
        { method: "POST", body: JSON.stringify({ name: folderCreateName }) },
        true
      );
      setFolderCreateName("");
      setSelectedFolderId(payload.id);
      await refreshFolders();
      setBanner({ tone: "success", message: "Folder created." });
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Folder creation failed." });
    } finally {
      setFolderCreateBusy(false);
    }
  }

  async function handleFolderRename(): Promise<void> {
    if (!selectedFolder) return;
    setFolderRenameBusy(true);
    try {
      const payload = await fetchJson<FolderResponse>(
        `/api/v1/folders/${encodeURIComponent(selectedFolder.id)}`,
        { method: "PUT", body: JSON.stringify({ name: folderRenameName }) },
        true
      );
      setSelectedFolderId(payload.id);
      await refreshFolders();
      setBanner({ tone: "success", message: "Folder renamed." });
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Folder rename failed." });
    } finally {
      setFolderRenameBusy(false);
    }
  }

  async function handleFolderDelete(): Promise<void> {
    if (!selectedFolder) return;
    setFolderDeleteBusy(true);
    try {
      await fetchJson<{ message: string }>(
        `/api/v1/folders/${encodeURIComponent(selectedFolder.id)}/delete`,
        { method: "POST", body: JSON.stringify(folderDeleteDraft) },
        true
      );
      setFolderDeleteDraft(emptyFolderDeleteDraft());
      setFolderDeletePreview(null);
      await refreshFolders();
      setBanner({ tone: "success", message: "Folder deleted." });
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Folder delete failed." });
    } finally {
      setFolderDeleteBusy(false);
    }
  }

  async function handleScanCreate(): Promise<void> {
    setScanCreateBusy(true);
    try {
      const payload = await fetchJson<ScanResponse>(
        "/api/v1/scans",
        {
          method: "POST",
          body: JSON.stringify({
            name: scanCreateDraft.name,
            folder_record_id: scanCreateDraft.folder_record_id,
            template_uuid: scanCreateDraft.creation_mode === "template" ? scanCreateDraft.template_uuid : null,
            policy_id: scanCreateDraft.creation_mode === "policy" ? scanCreateDraft.policy_id : null,
            clone_from_scan_record_id: scanCreateDraft.creation_mode === "master_template" ? scanCreateDraft.clone_from_scan_record_id : null,
            scanner_id: scanCreateDraft.scanner_id || null,
            targets: scanCreateDraft.creation_mode === "master_template" ? [] : parseTargetsInput(scanCreateDraft.targets),
            schedule_type: scanCreateDraft.schedule_type,
            launch_now: scanCreateDraft.launch_now
          })
        },
        true
      );
      setSelectedScanId(payload.id);
      setScanCreateDraft((current) => ({ ...emptyScanCreateDraft(), folder_record_id: current.folder_record_id, creation_mode: current.creation_mode }));
      setScanCreateWizardVersion((current) => current + 1);
      await refreshScans();
      setBanner({ tone: "success", message: "Scan created." });
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Scan creation failed." });
    } finally {
      setScanCreateBusy(false);
    }
  }

  async function handleScanUpdate(): Promise<void> {
    if (!selectedScan) return;
    setScanUpdateBusy(true);
    try {
      const payload = await fetchJson<ScanResponse>(
        `/api/v1/scans/${encodeURIComponent(selectedScan.id)}`,
        {
          method: "PUT",
          body: JSON.stringify({
            name: scanUpdateDraft.name,
            folder_record_id: scanUpdateDraft.folder_record_id || null,
            scanner_id: scanUpdateDraft.scanner_id || null,
            targets: parseTargetsInput(scanUpdateDraft.targets),
            schedule_type: scanUpdateDraft.schedule_type
          })
        },
        true
      );
      setSelectedScanId(payload.id);
      await refreshScans();
      setBanner({ tone: "success", message: "Scan updated." });
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Scan update failed." });
    } finally {
      setScanUpdateBusy(false);
    }
  }

  async function handleScanClone(): Promise<void> {
    if (!selectedScan) return;
    setScanCloneBusy(true);
    try {
      const payload = await fetchJson<ScanResponse>(
        `/api/v1/scans/${encodeURIComponent(selectedScan.id)}/clone`,
        {
          method: "POST",
          body: JSON.stringify({
            name: scanCloneDraft.name,
            folder_record_id: scanCloneDraft.folder_record_id || null,
            scanner_id: scanCloneDraft.scanner_id || null,
            launch_now: scanCloneDraft.launch_now
          })
        },
        true
      );
      setSelectedScanId(payload.id);
      await refreshScans();
      setBanner({ tone: "success", message: "Scan cloned." });
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Scan clone failed." });
    } finally {
      setScanCloneBusy(false);
    }
  }

  async function handleScanMove(): Promise<void> {
    if (!selectedScan || !scanUpdateDraft.folder_record_id) return;
    setScanActionBusy("move");
    try {
      const payload = await fetchJson<ScanResponse>(
        `/api/v1/scans/${encodeURIComponent(selectedScan.id)}/move`,
        { method: "POST", body: JSON.stringify({ folder_record_id: scanUpdateDraft.folder_record_id }) },
        true
      );
      setSelectedScanId(payload.id);
      await refreshScans();
      setBanner({ tone: "success", message: "Scan moved." });
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Scan move failed." });
    } finally {
      setScanActionBusy("");
    }
  }

  async function handleScanLaunch(): Promise<void> {
    if (!selectedScan) return;
    setScanActionBusy("launch");
    try {
      const payload = await fetchJson<ScanResponse>(
        `/api/v1/scans/${encodeURIComponent(selectedScan.id)}/launch`,
        { method: "POST" },
        true
      );
      setSelectedScanId(payload.id);
      await refreshScans();
      setBanner({ tone: "success", message: "Scan launched." });
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Scan launch failed." });
    } finally {
      setScanActionBusy("");
    }
  }

  async function handleScanPause(): Promise<void> {
    if (!selectedScan) return;
    setScanActionBusy("pause");
    try {
      const payload = await fetchJson<ScanResponse>(
        `/api/v1/scans/${encodeURIComponent(selectedScan.id)}/pause`,
        { method: "POST" },
        true
      );
      setSelectedScanId(payload.id);
      await refreshScans();
      setBanner({ tone: "success", message: "Scan paused." });
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Scan pause failed." });
    } finally {
      setScanActionBusy("");
    }
  }

  async function handleScanResume(): Promise<void> {
    if (!selectedScan) return;
    setScanActionBusy("resume");
    try {
      const payload = await fetchJson<ScanResponse>(
        `/api/v1/scans/${encodeURIComponent(selectedScan.id)}/resume`,
        { method: "POST" },
        true
      );
      setSelectedScanId(payload.id);
      await refreshScans();
      setBanner({ tone: "success", message: "Scan resumed." });
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Scan resume failed." });
    } finally {
      setScanActionBusy("");
    }
  }

  async function handleScanStop(): Promise<void> {
    if (!selectedScan) return;
    setScanActionBusy("stop");
    try {
      const payload = await fetchJson<ScanResponse>(
        `/api/v1/scans/${encodeURIComponent(selectedScan.id)}/stop`,
        { method: "POST" },
        true
      );
      setSelectedScanId(payload.id);
      await refreshScans();
      setBanner({ tone: "success", message: "Scan stopped." });
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Scan stop failed." });
    } finally {
      setScanActionBusy("");
    }
  }

  async function handleScanTrash(): Promise<void> {
    if (!selectedScan) return;
    setScanActionBusy("trash");
    try {
      await fetchJson<{ message: string }>(
        `/api/v1/scans/${encodeURIComponent(selectedScan.id)}/trash`,
        { method: "POST" },
        true
      );
      await refreshScans();
      setBanner({ tone: "success", message: "Scan moved to Trash." });
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Scan delete failed." });
    } finally {
      setScanActionBusy("");
    }
  }

  async function handleScanRestore(): Promise<void> {
    if (!selectedScan) return;
    setScanActionBusy("restore");
    try {
      const payload = await fetchJson<ScanResponse>(
        `/api/v1/scans/${encodeURIComponent(selectedScan.id)}/restore`,
        { method: "POST" },
        true
      );
      setSelectedScanId(payload.id);
      await refreshScans();
      setBanner({ tone: "success", message: "Scan restored from Trash." });
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Scan restore failed." });
    } finally {
      setScanActionBusy("");
    }
  }

  async function handleScanPermanentDelete(): Promise<void> {
    if (!selectedScan) return;
    setScanActionBusy("permanent-delete");
    try {
      await fetchJson<{ message: string }>(
        `/api/v1/scans/${encodeURIComponent(selectedScan.id)}/permanent-delete`,
        {
          method: "POST",
          body: JSON.stringify({ justification: "Confirmed from console after remote trash validation." })
        },
        true
      );
      await refreshScans();
      setBanner({ tone: "success", message: "Scan permanently deleted." });
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Permanent delete failed." });
    } finally {
      setScanActionBusy("");
    }
  }

  async function handleScanHistoryDelete(historyId: string): Promise<void> {
    if (!selectedScan) return;
    setScanHistoryDeleteBusy(historyId);
    try {
      await fetchJson<{ message: string }>(
        `/api/v1/scans/${encodeURIComponent(selectedScan.id)}/history/${encodeURIComponent(historyId)}/delete`,
        { method: "POST", body: JSON.stringify({ justification: scanHistoryDeleteJustification }) },
        true
      );
      await refreshScanHistory(selectedScan.id);
      await refreshScans();
      setScanHistoryDeleteJustification("");
      setBanner({ tone: "success", message: "Scan history deleted." });
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Scan history delete failed." });
    } finally {
      setScanHistoryDeleteBusy("");
    }
  }

  async function handleIpSearch(): Promise<void> {
    setIpSearchBusy(true);
    try {
      const payload = await fetchJson<IpSearchResponse>("/api/v1/ip-search/query", {
        method: "POST",
        body: JSON.stringify({
          entries: ipSearchEntries.split(/\r?\n/).flatMap((line) => line.split(",")).map((item) => item.trim()).filter(Boolean),
          expand_cidr: ipSearchExpandCidr
        })
      });
      setIpSearchResponse(payload);
      setBanner({ tone: "success", message: "IP search completed." });
    } catch (error) {
      setIpSearchResponse(null);
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "IP search failed." });
    } finally {
      setIpSearchBusy(false);
    }
  }

  async function handleIpUploadSearch(): Promise<void> {
    if (!ipSearchFile) return;
    setIpSearchUploadBusy(true);
    try {
      const form = new FormData();
      form.append("file", ipSearchFile);
      const payload = await fetchJson<IpSearchResponse>(`/api/v1/ip-search/upload?expand_cidr=${ipSearchExpandCidr ? "true" : "false"}`, {
        method: "POST",
        body: form
      });
      setIpSearchResponse(payload);
      setBanner({ tone: "success", message: "IP file processed." });
    } catch (error) {
      setIpSearchResponse(null);
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "IP upload failed." });
    } finally {
      setIpSearchUploadBusy(false);
    }
  }

  async function handleAssetReviewMerge(canonicalAssetKey: string): Promise<void> {
    if (!selectedAssetReview) return;
    setAssetReviewBusy(`merge:${canonicalAssetKey}`);
    try {
      await fetchJson<AssetReviewResponse>(
        `/api/v1/workflows/asset-reviews/${encodeURIComponent(selectedAssetReview.id)}/merge`,
        {
          method: "POST",
          body: JSON.stringify({
            canonical_asset_key: canonicalAssetKey,
            notes: assetReviewDraft.notes
          })
        },
        true
      );
      setBanner({ tone: "success", message: "Asset review merged." });
      await refreshAssetReviews();
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Asset merge failed." });
    } finally {
      setAssetReviewBusy("");
    }
  }

  async function handleAssetReviewSplit(): Promise<void> {
    if (!selectedAssetReview) return;
    setAssetReviewBusy("split");
    try {
      await fetchJson<AssetReviewResponse>(
        `/api/v1/workflows/asset-reviews/${encodeURIComponent(selectedAssetReview.id)}/split`,
        {
          method: "POST",
          body: JSON.stringify({ notes: assetReviewDraft.notes })
        },
        true
      );
      setBanner({ tone: "success", message: "Asset review marked as split." });
      await refreshAssetReviews();
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Asset split failed." });
    } finally {
      setAssetReviewBusy("");
    }
  }

  async function handleWorkflowSave(): Promise<void> {
    if (!selectedFinding) return;
    setWorkflowSaving(true);
    try {
      const payload = await fetchJson<WorkflowResponse>(
        `/api/v1/workflows/findings/${encodeURIComponent(selectedFinding.finding_key)}`,
        {
          method: "PUT",
          body: JSON.stringify({
            ...workflowDraft,
            sla_start_date: workflowDraft.sla_start_date || null,
            target_date: workflowDraft.target_date || null,
            actual_remediation_date: workflowDraft.actual_remediation_date || null
          })
        },
        true
      );
      setWorkflow(payload);
      setWorkflowDraft(draftFromWorkflow(payload));
      setBanner({ tone: "success", message: "Workflow updated." });
      void refreshSummary();
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Workflow update failed." });
    } finally {
      setWorkflowSaving(false);
    }
  }

  async function handleDecisionRequest(): Promise<void> {
    if (!selectedFinding) return;
    setDecisionBusy(true);
    try {
      await fetchJson<WorkflowDecision>(
        "/api/v1/workflows/decisions",
        {
          method: "POST",
          body: JSON.stringify({
            finding_key: selectedFinding.finding_key,
            ...decisionDraft,
            start_date: decisionDraft.start_date || null,
            expiry_date: decisionDraft.expiry_date || null,
            review_date: decisionDraft.review_date || null
          })
        },
        true
      );
      setDecisionDraft(emptyDecisionDraft());
      setBanner({ tone: "success", message: "Decision requested." });
      await refreshWorkflow(selectedFinding.finding_key);
      await refreshSummary();
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Decision request failed." });
    } finally {
      setDecisionBusy(false);
    }
  }

  async function handleDecisionApprove(decisionId: string): Promise<void> {
    if (!selectedFinding) return;
    setDecisionApproval(true);
    try {
      await fetchJson<WorkflowDecision>(
        `/api/v1/workflows/decisions/${decisionId}/approve`,
        {
          method: "POST",
          body: JSON.stringify({ justification: "Approved from console." })
        },
        true
      );
      setBanner({ tone: "success", message: "Decision approved." });
      await refreshWorkflow(selectedFinding.finding_key);
      await refreshSummary();
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Decision approval failed." });
    } finally {
      setDecisionApproval(false);
    }
  }

  async function handleExpireDecisions(): Promise<void> {
    setDecisionApproval(true);
    try {
      const payload = await fetchJson<{ expired_count: number }>(
        "/api/v1/workflows/maintenance/expire",
        { method: "POST" },
        true
      );
      setBanner({ tone: "success", message: `${payload.expired_count} expired decisions processed.` });
      if (selectedFinding) {
        await refreshWorkflow(selectedFinding.finding_key);
      }
      await refreshSummary();
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Decision maintenance failed." });
    } finally {
      setDecisionApproval(false);
    }
  }

  async function handleExport(): Promise<void> {
    setExportBusy(true);
    try {
      const params = new URLSearchParams({ report_type: reportType, export_format: reportFormat });
      if (selectedReport.comparisonScoped && summary?.comparison_run_id) {
        params.set("comparison_run_id", summary.comparison_run_id);
      }
      if (selectedReport.requiresEntries) {
        const entries = reportEntries.trim();
        if (!entries) {
          throw new Error("Enter one or more IP addresses, host IPs, or CIDR ranges for this export.");
        }
        params.set("entries", entries);
        params.set("expand_cidr", reportExpandCidr ? "true" : "false");
      }
      if (selectedReport.supportsDaysUntilExpiry) {
        params.set("days_until_expiry", String(Math.max(0, Number(reportDaysUntilExpiry || 30))));
      }
      const response = await fetch(`/api/v1/reports/export?${params.toString()}`, {
        credentials: "include"
      });
      if (!response.ok) {
        throw new Error(await parseError(response));
      }
      const blob = await response.blob();
      const disposition = response.headers.get("Content-Disposition") || "";
      const fileNameMatch = disposition.match(/filename="([^"]+)"/);
      const fileName = fileNameMatch?.[1] || `report.${reportFormat}`;
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = fileName;
      anchor.click();
      URL.revokeObjectURL(url);
      setBanner({ tone: "success", message: "Export ready." });
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Export failed." });
    } finally {
      setExportBusy(false);
    }
  }

  async function handleNessusTest(): Promise<void> {
    setNessusTesting(true);
    try {
      const payload = await fetchJson<NessusValidationResponse>(
        "/api/v1/nessus/configuration/test",
        {
          method: "POST",
          body: JSON.stringify({
            base_url: nessusForm.base_url,
            access_key: nessusForm.access_key,
            secret_key: nessusForm.secret_key,
            verify_tls: nessusForm.verify_tls,
            timeout_seconds: Number(nessusForm.timeout_seconds || 15),
            approved_hosts: parseApprovedHosts(nessusForm.approved_hosts)
          })
        },
        true
      );
      setNessusValidation(payload);
      setBanner({ tone: "success", message: "Nessus connection verified." });
    } catch (error) {
      setNessusValidation(null);
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Nessus test failed." });
    } finally {
      setNessusTesting(false);
    }
  }

  async function handleNessusSave(): Promise<void> {
    setNessusSaving(true);
    try {
      const payload = await fetchJson<NessusConfigurationResponse>(
        "/api/v1/nessus/configuration",
        {
          method: "PUT",
          body: JSON.stringify({
            base_url: nessusForm.base_url,
            access_key: nessusForm.access_key,
            secret_key: nessusForm.secret_key,
            verify_tls: nessusForm.verify_tls,
            timeout_seconds: Number(nessusForm.timeout_seconds || 15),
            approved_hosts: parseApprovedHosts(nessusForm.approved_hosts)
          })
        },
        true
      );
      setNessusConfig(payload);
      setNessusValidation({
        base_url: payload.base_url || "",
        verify_tls: payload.verify_tls,
        timeout_seconds: payload.timeout_seconds || 15,
        approved_hosts: payload.approved_hosts,
        server_info: payload.server_info,
        api_permissions: payload.api_permissions,
        capabilities: payload.capabilities
      });
      setNessusForm(draftFromNessusConfig(payload));
      setBanner({ tone: "success", message: "Nessus configuration saved." });
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Nessus save failed." });
    } finally {
      setNessusSaving(false);
    }
  }

  async function handleNessusReset(): Promise<void> {
    setNessusResetting(true);
    try {
      await fetchJson<{ message: string }>(
        "/api/v1/nessus/configuration/reset",
        {
          method: "POST",
          body: JSON.stringify(nessusReset)
        },
        true
      );
      setNessusConfig({
        configured: false,
        base_url: null,
        verify_tls: true,
        timeout_seconds: null,
        approved_hosts: [],
        masked_access_key: null,
        masked_secret_key: null,
        server_info: {},
        api_permissions: [],
        capabilities: {},
        validated_at: null
      });
      setNessusValidation(null);
      setNessusForm(emptyNessusForm());
      setNessusReset(emptyNessusResetDraft());
      setBanner({ tone: "success", message: "Nessus credentials reset." });
    } catch (error) {
      setBanner({ tone: "error", message: error instanceof Error ? error.message : "Nessus reset failed." });
    } finally {
      setNessusResetting(false);
    }
  }

  const summaryCards = React.useMemo(
    () =>
      summary
        ? lifecycleCards.map((card) => ({
            ...card,
            value: Number(summary[card.key] || 0)
          }))
        : [],
    [summary]
  );

  async function handleSectionRefresh(): Promise<void> {
    if (activeSection === "dashboard" || activeSection === "findings") {
      await refreshSummary();
      return;
    }
    if (activeSection === "folders") {
      await refreshFolders();
      return;
    }
    if (activeSection === "scans") {
      await refreshScans();
      return;
    }
    if (activeSection === "audit") {
      await refreshAudit();
      return;
    }
    if (activeSection === "settings") {
      await refreshNessusConfig();
    }
  }

  if (sessionLoading) {
    return (
      <Stack minHeight="100vh" alignItems="center" justifyContent="center" spacing={2}>
        <CircularProgress size={28} />
        <Typography color="text.secondary">Loading session</Typography>
      </Stack>
    );
  }

  if (!session) {
    return (
      <Box sx={{ minHeight: "100vh", bgcolor: "background.default", px: 2, py: 3 }}>
        <Stack minHeight="100vh" alignItems="center" justifyContent="center">
          <Paper sx={{ width: "100%", maxWidth: 1080, overflow: "hidden" }}>
            <Grid container>
              <Grid size={{ xs: 12, lg: 6 }}>
                <Box sx={{ p: { xs: 3, md: 4 }, height: "100%", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
                  <Stack spacing={3}>
                    <Stack direction="row" spacing={1.5} alignItems="center">
                      <Box
                        sx={{
                          width: 42,
                          height: 42,
                          borderRadius: 2,
                          display: "grid",
                          placeItems: "center",
                          bgcolor: "primary.main",
                          color: "primary.contrastText"
                        }}
                      >
                        <ShieldOutlinedIcon fontSize="small" />
                      </Box>
                      <Box>
                        <Typography variant="h5">Nessus Lifecycle Console</Typography>
                        <Typography variant="body2" color="text.secondary">
                          Operations workspace
                        </Typography>
                      </Box>
                    </Stack>
                    <Stack spacing={2}>
                      <TextField
                        label="Username"
                        value={loginForm.username}
                        onChange={(event) => setLoginForm((current) => ({ ...current, username: event.target.value }))}
                        fullWidth
                      />
                      <TextField
                        label="Password"
                        type="password"
                        value={loginForm.password}
                        onChange={(event) => setLoginForm((current) => ({ ...current, password: event.target.value }))}
                        fullWidth
                        onKeyDown={(event) => {
                          if (event.key === "Enter") {
                            void handleLogin();
                          }
                        }}
                      />
                      <Button
                        variant="contained"
                        size="large"
                        startIcon={loginBusy ? <CircularProgress size={16} color="inherit" /> : <LoginOutlinedIcon />}
                        onClick={() => void handleLogin()}
                        disabled={loginBusy || !loginForm.username.trim() || !loginForm.password}
                      >
                        Sign in
                      </Button>
                    </Stack>
                  </Stack>
                </Box>
              </Grid>
              <Grid size={{ xs: 12, lg: 6 }}>
                <Box
                  sx={{
                    p: { xs: 3, md: 4 },
                    minHeight: { xs: 280, lg: 560 },
                    bgcolor: mode === "dark" ? "#0f1724" : "#f5f8fb",
                    borderLeft: { lg: 1 },
                    borderColor: "divider"
                  }}
                >
                  <Stack spacing={2.5}>
                    <Stack direction="row" justifyContent="space-between" alignItems="center">
                      <Chip label="Session-based" size="small" color="primary" variant="outlined" />
                      <Tooltip title={mode === "dark" ? "Switch to light mode" : "Switch to dark mode"}>
                        <IconButton color="inherit" onClick={onToggleColorMode} aria-label="toggle color mode">
                          {mode === "dark" ? <WbSunnyOutlinedIcon /> : <DarkModeOutlinedIcon />}
                        </IconButton>
                      </Tooltip>
                    </Stack>
                    <Grid container spacing={1.5}>
                      {[
                        ["Dashboard", "Comparison metrics"],
                        ["Workflow", "SLA and ownership"],
                        ["Exports", "CSV and Excel"],
                        ["Controls", "Session and approvals"]
                      ].map(([label, value]) => (
                        <Grid key={label} size={{ xs: 12, sm: 6 }}>
                          <Paper sx={{ p: 2, minHeight: 108 }}>
                            <Typography variant="subtitle2">{label}</Typography>
                            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.8 }}>
                              {value}
                            </Typography>
                          </Paper>
                        </Grid>
                      ))}
                    </Grid>
                  </Stack>
                </Box>
              </Grid>
            </Grid>
          </Paper>
        </Stack>
        <Snackbar open={Boolean(banner)} autoHideDuration={4500} onClose={() => setBanner(null)}>
          <Alert severity={banner?.tone || "success"} variant="filled">
            {banner?.message}
          </Alert>
        </Snackbar>
      </Box>
    );
  }

  return (
    <Box sx={{ minHeight: "100vh", bgcolor: "background.default" }}>
      <AppBar
        position="sticky"
        color="transparent"
        elevation={0}
        sx={{ backdropFilter: "blur(16px)", borderBottom: 1, borderColor: "divider" }}
      >
        <Toolbar sx={{ minHeight: 68 }}>
          <Stack direction="row" spacing={1.5} alignItems="center" sx={{ flexGrow: 1 }}>
            <Box
              sx={{
                width: 38,
                height: 38,
                borderRadius: 2,
                display: "grid",
                placeItems: "center",
                bgcolor: "primary.main",
                color: "primary.contrastText"
              }}
            >
              <ShieldOutlinedIcon fontSize="small" />
            </Box>
            <Box>
              <Typography variant="h6">Nessus Lifecycle Console</Typography>
              <Typography variant="body2" color="text.secondary">
                {session.roles?.join(", ") || ""}
              </Typography>
            </Box>
          </Stack>
          <Stack direction="row" spacing={1} alignItems="center">
            <Chip label={session.username} color="primary" size="small" />
            <Tooltip title={mode === "dark" ? "Switch to light mode" : "Switch to dark mode"}>
              <IconButton color="inherit" onClick={onToggleColorMode} aria-label="toggle color mode">
                {mode === "dark" ? <WbSunnyOutlinedIcon /> : <DarkModeOutlinedIcon />}
              </IconButton>
            </Tooltip>
            <Tooltip title="Logout">
              <IconButton color="inherit" onClick={() => void handleLogout()}>
                <LogoutOutlinedIcon />
              </IconButton>
            </Tooltip>
          </Stack>
        </Toolbar>
      </AppBar>

      <Box sx={{ px: { xs: 2, lg: 3 }, py: 2.5 }}>
        <Grid container spacing={2}>
          <Grid size={{ xs: 12, lg: 2.2 }}>
            <Paper sx={{ p: 1.25, height: "100%" }}>
              <List disablePadding>
                {navigationSections.map((section) => (
                  <ListItemButton
                    key={section.id}
                    selected={activeSection === section.id}
                    onClick={() => setActiveSection(section.id)}
                    sx={{ minHeight: 44, borderRadius: 1.5, mb: 0.5 }}
                  >
                    <ListItemIcon sx={{ minWidth: 34 }}>{section.icon}</ListItemIcon>
                    <ListItemText primary={section.label} />
                  </ListItemButton>
                ))}
              </List>
              <Divider sx={{ my: 1.25 }} />
              <Stack spacing={1}>
                <Button startIcon={<RefreshOutlinedIcon />} variant="outlined" onClick={() => void handleSectionRefresh()}>
                  Refresh
                </Button>
                {hasPermission("exceptions.approve") ? (
                  <Button startIcon={<FactCheckOutlinedIcon />} variant="outlined" onClick={() => void handleExpireDecisions()} disabled={decisionApproval}>
                    Expire Decisions
                  </Button>
                ) : null}
                {isAdministrator ? (
                  <Button startIcon={<SettingsOutlinedIcon />} variant="outlined" onClick={() => setActiveSection("settings")}>
                    Nessus
                  </Button>
                ) : null}
              </Stack>
            </Paper>
          </Grid>

          <Grid size={{ xs: 12, lg: 9.8 }}>
            <Stack spacing={2}>
              {activeSection === "dashboard" ? (
                <>
                  <Paper sx={{ p: 2.25 }}>
                    <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
                      <Box>
                        <Typography variant="h6">Lifecycle Summary</Typography>
                        <Typography variant="body2" color="text.secondary">
                          Comparison run {summary?.comparison_run_id ?? "Unavailable"}
                        </Typography>
                      </Box>
                      {summaryLoading ? <CircularProgress size={20} /> : null}
                    </Stack>
                    {summary ? (
                      <Grid container spacing={1.5}>
                        {summaryCards.map((card) => (
                          <Grid key={card.label} size={{ xs: 12, sm: 6, xl: 2 }}>
                            <Paper sx={{ border: 1, borderColor: "divider" }}>
                              <CardActionArea
                                onClick={() => {
                                  if (card.filter) {
                                    setLifecycleFilter(card.filter);
                                    setActiveSection("findings");
                                  }
                                }}
                                sx={{ p: 2, minHeight: 120, alignItems: "flex-start" }}
                              >
                                <Stack spacing={1}>
                                  <Chip label={card.label} size="small" color={card.color} variant="outlined" sx={{ alignSelf: "flex-start" }} />
                                  <Typography variant="h4">{card.value}</Typography>
                                </Stack>
                              </CardActionArea>
                            </Paper>
                          </Grid>
                        ))}
                      </Grid>
                    ) : (
                      <Alert severity="info">No comparison data is available yet.</Alert>
                    )}
                  </Paper>

                  <Grid container spacing={2}>
                    <Grid size={{ xs: 12, xl: 6 }}>
                      <Paper sx={{ p: 2.25, height: "100%" }}>
                        <Typography variant="h6">Severity Mix</Typography>
                        <Stack spacing={1.5} sx={{ mt: 2 }}>
                          {summary
                            ? Object.entries(summary.severity_breakdown).map(([label, value]) => {
                                const total = Math.max(summary.latest_total || 0, 1);
                                const pct = Math.round((value / total) * 100);
                                return (
                                  <Box key={label}>
                                    <Stack direction="row" justifyContent="space-between" sx={{ mb: 0.5 }}>
                                      <Typography variant="body2" sx={{ textTransform: "capitalize" }}>
                                        {label}
                                      </Typography>
                                      <Typography variant="body2" color="text.secondary">
                                        {value}
                                      </Typography>
                                    </Stack>
                                    <LinearProgress variant="determinate" value={pct} />
                                  </Box>
                                );
                              })
                            : null}
                        </Stack>
                      </Paper>
                    </Grid>
                    <Grid size={{ xs: 12, xl: 6 }}>
                      <Paper sx={{ p: 2.25, height: "100%" }}>
                        <Typography variant="h6">Asset Coverage</Typography>
                        <Grid container spacing={1.25} sx={{ mt: 0.5 }}>
                          {summary
                            ? [
                                ["Total assets", summary.asset_coverage.total_assets],
                                ["Assets found", summary.asset_coverage.assets_found],
                                ["Assets not found", summary.asset_coverage.assets_not_found],
                                ["Reachable", summary.asset_coverage.reachable_assets],
                                ["Unreachable", summary.asset_coverage.unreachable_assets],
                                ["Auth passed", summary.asset_coverage.authentication_passed],
                                ["Auth failed", summary.asset_coverage.authentication_failed],
                                ["Comparable", summary.asset_coverage.comparable_assets],
                                ["Non-comparable", summary.asset_coverage.non_comparable_assets]
                              ].map(([label, value]) => (
                                <Grid key={String(label)} size={{ xs: 6, sm: 4 }}>
                                  <Box sx={{ border: 1, borderColor: "divider", borderRadius: 1.5, px: 1.5, py: 1.25, minHeight: 96 }}>
                                    <Typography variant="body2" color="text.secondary">
                                      {label}
                                    </Typography>
                                    <Typography variant="h5" sx={{ mt: 1 }}>
                                      {value}
                                    </Typography>
                                  </Box>
                                </Grid>
                              ))
                            : null}
                        </Grid>
                      </Paper>
                    </Grid>
                  </Grid>
                </>
              ) : null}

              {activeSection === "findings" ? (
                <Grid container spacing={2}>
                  <Grid size={{ xs: 12, xl: 7.2 }}>
                    <Paper sx={{ p: 2.25 }}>
                      <Stack direction={{ xs: "column", lg: "row" }} spacing={1.25} justifyContent="space-between">
                        <Stack direction={{ xs: "column", sm: "row" }} spacing={1}>
                          <FormControl sx={{ minWidth: 220 }}>
                            <InputLabel id="lifecycle-filter-label">Lifecycle</InputLabel>
                            <Select
                              labelId="lifecycle-filter-label"
                              label="Lifecycle"
                              value={lifecycleFilter}
                              onChange={(event) => setLifecycleFilter(event.target.value)}
                            >
                              <MenuItem value="">All</MenuItem>
                              {["New", "Existing", "Closed", "Reopened", "Not Validated", "Severity Changed", "Port Changed"].map((item) => (
                                <MenuItem key={item} value={item}>
                                  {item}
                                </MenuItem>
                              ))}
                            </Select>
                          </FormControl>
                          <FormControl sx={{ minWidth: 180 }}>
                            <InputLabel id="severity-filter-label">Severity</InputLabel>
                            <Select
                              labelId="severity-filter-label"
                              label="Severity"
                              value={severityFilter}
                              onChange={(event) => setSeverityFilter(event.target.value)}
                            >
                              {severityLabels.map((item) => (
                                <MenuItem key={item.value || "all"} value={item.value}>
                                  {item.label}
                                </MenuItem>
                              ))}
                            </Select>
                          </FormControl>
                        </Stack>
                        <TextField
                          value={search}
                          onChange={(event) => setSearch(event.target.value)}
                          label="Search"
                          sx={{ minWidth: { xs: "100%", lg: 260 } }}
                          InputProps={{
                            startAdornment: (
                              <InputAdornment position="start">
                                <SearchOutlinedIcon fontSize="small" />
                              </InputAdornment>
                            )
                          }}
                        />
                      </Stack>
                      <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mt: 2, mb: 1 }}>
                        <Typography variant="body2" color="text.secondary">
                          {findings.length} records
                        </Typography>
                        {findingsLoading ? <CircularProgress size={18} /> : null}
                      </Stack>
                      <TableContainer sx={{ maxHeight: 640 }}>
                        <Table stickyHeader size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell>Asset</TableCell>
                              <TableCell>Plugin</TableCell>
                              <TableCell>Severity</TableCell>
                              <TableCell>Lifecycle</TableCell>
                              <TableCell>Eligibility</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {findings.map((row) => (
                              <TableRow
                                key={row.result_id}
                                hover
                                selected={selectedFinding?.result_id === row.result_id}
                                onClick={() => setSelectedFinding(row)}
                                sx={{ cursor: "pointer" }}
                              >
                                <TableCell>
                                  <Stack spacing={0.3}>
                                    <Typography variant="body2">{row.asset_key}</Typography>
                                    <Typography variant="caption" color="text.secondary">
                                      {row.port}/{row.protocol}
                                    </Typography>
                                  </Stack>
                                </TableCell>
                                <TableCell>
                                  <Stack spacing={0.3}>
                                    <Typography variant="body2">{row.plugin_id}</Typography>
                                    <Typography variant="caption" color="text.secondary">
                                      {row.plugin_name || row.finding_key}
                                    </Typography>
                                  </Stack>
                                </TableCell>
                                <TableCell>{severityName(row.severity)}</TableCell>
                                <TableCell>
                                  <Chip label={row.lifecycle_status} size="small" variant="outlined" />
                                </TableCell>
                                <TableCell>{row.comparison_eligibility}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </Paper>
                  </Grid>

                  <Grid size={{ xs: 12, xl: 4.8 }}>
                    <Paper sx={{ p: 2.25 }}>
                      <Stack spacing={2}>
                        <Box>
                          <Stack direction="row" justifyContent="space-between" alignItems="center" spacing={1}>
                            <Typography variant="h6">Asset Review Queue</Typography>
                            {assetReviewsLoading ? <CircularProgress size={18} /> : <Chip label={`${assetReviews.length} pending`} size="small" variant="outlined" />}
                          </Stack>
                          <Typography variant="body2" color="text.secondary">
                            Analyst merge and split actions for ambiguous asset matches.
                          </Typography>
                        </Box>
                        {assetReviews.length === 0 ? (
                          <Alert severity="info">No pending ambiguous asset reviews.</Alert>
                        ) : (
                          <>
                            <Stack spacing={1} sx={{ maxHeight: 220, overflowY: "auto", pr: 0.5 }}>
                              {assetReviews.map((review) => (
                                <Box
                                  key={review.id}
                                  onClick={() => setSelectedAssetReviewId(review.id)}
                                  sx={{
                                    border: 1,
                                    borderColor: selectedAssetReviewId === review.id ? "primary.main" : "divider",
                                    borderRadius: 1.5,
                                    p: 1.25,
                                    cursor: "pointer"
                                  }}
                                >
                                  <Stack direction="row" justifyContent="space-between" spacing={1}>
                                    <Typography variant="body2">{review.left_asset.stable_asset_key}</Typography>
                                    <Chip label={review.status} size="small" variant="outlined" />
                                  </Stack>
                                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                                    {review.right_asset.stable_asset_key}
                                  </Typography>
                                  <Stack direction="row" spacing={0.75} useFlexGap flexWrap="wrap" sx={{ mt: 1 }}>
                                    {review.match_basis.map((basis) => (
                                      <Chip key={`${review.id}-${basis}`} label={basis} size="small" />
                                    ))}
                                  </Stack>
                                </Box>
                              ))}
                            </Stack>
                            {selectedAssetReview ? (
                              <>
                                <Grid container spacing={1.25}>
                                  <Grid size={{ xs: 12, sm: 6 }}>
                                    <Box sx={{ border: 1, borderColor: "divider", borderRadius: 1.5, p: 1.25, height: "100%" }}>
                                      <Typography variant="subtitle2">Left candidate</Typography>
                                      <Typography variant="body2" sx={{ mt: 0.75 }}>{selectedAssetReview.left_asset.stable_asset_key}</Typography>
                                      <Typography variant="caption" color="text.secondary">
                                        {selectedAssetReview.left_asset.hostname || selectedAssetReview.left_asset.fqdn || selectedAssetReview.left_asset.ipv4_address || "No hostname or IP"}
                                      </Typography>
                                    </Box>
                                  </Grid>
                                  <Grid size={{ xs: 12, sm: 6 }}>
                                    <Box sx={{ border: 1, borderColor: "divider", borderRadius: 1.5, p: 1.25, height: "100%" }}>
                                      <Typography variant="subtitle2">Right candidate</Typography>
                                      <Typography variant="body2" sx={{ mt: 0.75 }}>{selectedAssetReview.right_asset.stable_asset_key}</Typography>
                                      <Typography variant="caption" color="text.secondary">
                                        {selectedAssetReview.right_asset.hostname || selectedAssetReview.right_asset.fqdn || selectedAssetReview.right_asset.ipv4_address || "No hostname or IP"}
                                      </Typography>
                                    </Box>
                                  </Grid>
                                </Grid>
                                <TextField
                                  fullWidth
                                  label="Canonical asset key"
                                  value={assetReviewDraft.canonical_asset_key}
                                  onChange={(event) => setAssetReviewDraft((current) => ({ ...current, canonical_asset_key: event.target.value }))}
                                />
                                <TextField
                                  fullWidth
                                  multiline
                                  minRows={2}
                                  label="Review notes"
                                  value={assetReviewDraft.notes}
                                  onChange={(event) => setAssetReviewDraft((current) => ({ ...current, notes: event.target.value }))}
                                />
                                <Stack direction={{ xs: "column", sm: "row" }} spacing={1}>
                                  <Button
                                    variant="outlined"
                                    onClick={() => void handleAssetReviewMerge(selectedAssetReview.left_asset.stable_asset_key)}
                                    disabled={!hasPermission("findings.override") || assetReviewBusy !== "" || selectedAssetReview.status !== "pending"}
                                  >
                                    Merge to left
                                  </Button>
                                  <Button
                                    variant="outlined"
                                    onClick={() => void handleAssetReviewMerge(selectedAssetReview.right_asset.stable_asset_key)}
                                    disabled={!hasPermission("findings.override") || assetReviewBusy !== "" || selectedAssetReview.status !== "pending"}
                                  >
                                    Merge to right
                                  </Button>
                                  <Button
                                    variant="contained"
                                    onClick={() => void handleAssetReviewMerge(assetReviewDraft.canonical_asset_key.trim())}
                                    disabled={!hasPermission("findings.override") || assetReviewBusy !== "" || !assetReviewDraft.canonical_asset_key.trim() || selectedAssetReview.status !== "pending"}
                                  >
                                    Manual merge
                                  </Button>
                                  <Button
                                    color="warning"
                                    variant="outlined"
                                    onClick={() => void handleAssetReviewSplit()}
                                    disabled={!hasPermission("findings.override") || assetReviewBusy !== "" || selectedAssetReview.status !== "pending"}
                                  >
                                    Keep split
                                  </Button>
                                </Stack>
                              </>
                            ) : null}
                          </>
                        )}
                        <Divider />
                        {selectedFinding ? (
                        <Stack spacing={2}>
                          <Box>
                            <Typography variant="h6">Workflow</Typography>
                            <Typography variant="body2" color="text.secondary">
                              {selectedFinding.finding_key}
                            </Typography>
                          </Box>
                          {workflowLoading ? (
                            <Stack alignItems="center" py={4}>
                              <CircularProgress size={24} />
                            </Stack>
                          ) : workflow ? (
                            <>
                              <Grid container spacing={1.25}>
                                <Grid size={{ xs: 12, sm: 6 }}>
                                  <TextField fullWidth label="Owner" value={workflowDraft.owner} onChange={(event) => setWorkflowDraft((current) => ({ ...current, owner: event.target.value }))} />
                                </Grid>
                                <Grid size={{ xs: 12, sm: 6 }}>
                                  <TextField
                                    fullWidth
                                    label="Remediation team"
                                    value={workflowDraft.remediation_team}
                                    onChange={(event) => setWorkflowDraft((current) => ({ ...current, remediation_team: event.target.value }))}
                                  />
                                </Grid>
                                <Grid size={{ xs: 12 }}>
                                  <FormControl fullWidth>
                                    <InputLabel id="workflow-status-label">Workflow status</InputLabel>
                                    <Select
                                      labelId="workflow-status-label"
                                      label="Workflow status"
                                      value={workflowDraft.workflow_status}
                                      onChange={(event) => setWorkflowDraft((current) => ({ ...current, workflow_status: event.target.value }))}
                                    >
                                      {workflowStatuses.map((item) => (
                                        <MenuItem key={item} value={item}>
                                          {item}
                                        </MenuItem>
                                      ))}
                                    </Select>
                                  </FormControl>
                                </Grid>
                                <Grid size={{ xs: 12, sm: 6 }}>
                                  <TextField fullWidth type="date" label="SLA start" value={workflowDraft.sla_start_date} onChange={(event) => setWorkflowDraft((current) => ({ ...current, sla_start_date: event.target.value }))} InputLabelProps={{ shrink: true }} />
                                </Grid>
                                <Grid size={{ xs: 12, sm: 6 }}>
                                  <TextField fullWidth type="date" label="Target date" value={workflowDraft.target_date} onChange={(event) => setWorkflowDraft((current) => ({ ...current, target_date: event.target.value }))} InputLabelProps={{ shrink: true }} />
                                </Grid>
                                <Grid size={{ xs: 12, sm: 6 }}>
                                  <TextField fullWidth label="Due date" value={workflow.due_date ?? ""} InputProps={{ readOnly: true }} />
                                </Grid>
                                <Grid size={{ xs: 12, sm: 6 }}>
                                  <TextField fullWidth label="Days overdue" value={workflow.days_overdue} InputProps={{ readOnly: true }} />
                                </Grid>
                                <Grid size={{ xs: 12, sm: 6 }}>
                                  <TextField fullWidth label="Ticket number" value={workflowDraft.ticket_number} onChange={(event) => setWorkflowDraft((current) => ({ ...current, ticket_number: event.target.value }))} />
                                </Grid>
                                <Grid size={{ xs: 12, sm: 6 }}>
                                  <TextField fullWidth label="Ticket URL" value={workflowDraft.ticket_url} onChange={(event) => setWorkflowDraft((current) => ({ ...current, ticket_url: event.target.value }))} />
                                </Grid>
                                <Grid size={{ xs: 12 }}>
                                  <TextField fullWidth multiline minRows={3} label="Comments" value={workflowDraft.comments} onChange={(event) => setWorkflowDraft((current) => ({ ...current, comments: event.target.value }))} />
                                </Grid>
                                <Grid size={{ xs: 12 }}>
                                  <TextField fullWidth multiline minRows={2} label="Evidence" value={workflowDraft.evidence} onChange={(event) => setWorkflowDraft((current) => ({ ...current, evidence: event.target.value }))} />
                                </Grid>
                                <Grid size={{ xs: 12 }}>
                                  <TextField fullWidth label="Validation status" value={workflowDraft.validation_status} onChange={(event) => setWorkflowDraft((current) => ({ ...current, validation_status: event.target.value }))} />
                                </Grid>
                                <Grid size={{ xs: 12 }}>
                                  <FormControlLabel
                                    control={<Switch checked={workflowDraft.rescan_requested} onChange={(event) => setWorkflowDraft((current) => ({ ...current, rescan_requested: event.target.checked }))} />}
                                    label="Rescan requested"
                                  />
                                </Grid>
                              </Grid>
                              <Stack direction="row" justifyContent="space-between" alignItems="center">
                                <Chip label={workflow.is_technically_open ? "Technically Open" : "Closed"} color={workflow.is_technically_open ? "warning" : "success"} variant="outlined" />
                                <Button startIcon={<SaveOutlinedIcon />} variant="contained" onClick={() => void handleWorkflowSave()} disabled={!hasPermission("findings.update") || workflowSaving}>
                                  Save
                                </Button>
                              </Stack>
                              <Divider />
                              <Stack spacing={1.25}>
                                <Typography variant="subtitle1">Decisions</Typography>
                                <Grid container spacing={1.25}>
                                  <Grid size={{ xs: 12 }}>
                                    <FormControl fullWidth>
                                      <InputLabel id="decision-type-label">Decision type</InputLabel>
                                      <Select
                                        labelId="decision-type-label"
                                        label="Decision type"
                                        value={decisionDraft.decision_type}
                                        onChange={(event) => setDecisionDraft((current) => ({ ...current, decision_type: event.target.value }))}
                                      >
                                        {Object.entries(decisionTypeLabels).map(([value, label]) => (
                                          <MenuItem key={value} value={value}>
                                            {label}
                                          </MenuItem>
                                        ))}
                                      </Select>
                                    </FormControl>
                                  </Grid>
                                  <Grid size={{ xs: 12 }}>
                                    <TextField fullWidth label="Reason" value={decisionDraft.reason} onChange={(event) => setDecisionDraft((current) => ({ ...current, reason: event.target.value }))} />
                                  </Grid>
                                  <Grid size={{ xs: 12 }}>
                                    <TextField fullWidth multiline minRows={2} label="Business justification" value={decisionDraft.business_justification} onChange={(event) => setDecisionDraft((current) => ({ ...current, business_justification: event.target.value }))} />
                                  </Grid>
                                  <Grid size={{ xs: 12 }}>
                                    <TextField fullWidth multiline minRows={2} label="Compensating controls" value={decisionDraft.compensating_controls} onChange={(event) => setDecisionDraft((current) => ({ ...current, compensating_controls: event.target.value }))} />
                                  </Grid>
                                  <Grid size={{ xs: 12, sm: 4 }}>
                                    <TextField fullWidth type="date" label="Start date" value={decisionDraft.start_date} onChange={(event) => setDecisionDraft((current) => ({ ...current, start_date: event.target.value }))} InputLabelProps={{ shrink: true }} />
                                  </Grid>
                                  <Grid size={{ xs: 12, sm: 4 }}>
                                    <TextField fullWidth type="date" label="Expiry date" value={decisionDraft.expiry_date} onChange={(event) => setDecisionDraft((current) => ({ ...current, expiry_date: event.target.value }))} InputLabelProps={{ shrink: true }} />
                                  </Grid>
                                  <Grid size={{ xs: 12, sm: 4 }}>
                                    <TextField fullWidth type="date" label="Review date" value={decisionDraft.review_date} onChange={(event) => setDecisionDraft((current) => ({ ...current, review_date: event.target.value }))} InputLabelProps={{ shrink: true }} />
                                  </Grid>
                                </Grid>
                                <Button variant="outlined" onClick={() => void handleDecisionRequest()} disabled={decisionBusy || !decisionDraft.reason.trim()}>
                                  Request decision
                                </Button>
                              </Stack>
                              <Divider />
                              <Stack spacing={1}>
                                <Stack direction="row" justifyContent="space-between" alignItems="center">
                                  <Typography variant="subtitle1">History</Typography>
                                  {decisionsLoading ? <CircularProgress size={16} /> : null}
                                </Stack>
                                {decisions.map((decision) => (
                                  <Box key={decision.id} sx={{ border: 1, borderColor: "divider", borderRadius: 1.5, p: 1.5 }}>
                                    <Stack direction="row" justifyContent="space-between" alignItems="center" spacing={1}>
                                      <Chip label={decisionTypeLabels[decision.decision_type] || decision.decision_type} size="small" variant="outlined" />
                                      <Chip label={decision.status} size="small" color={decision.status === "approved" ? "success" : decision.status === "expired" ? "warning" : "default"} />
                                    </Stack>
                                    <Typography variant="body2" sx={{ mt: 1 }}>
                                      {decision.reason}
                                    </Typography>
                                    {decision.status === "requested" &&
                                    ((decision.decision_type === "exception" && hasPermission("exceptions.approve")) ||
                                      (decision.decision_type === "risk_acceptance" && hasPermission("risk_acceptance.approve")) ||
                                      (decision.decision_type === "false_positive" && hasPermission("false_positive.approve"))) ? (
                                      <Button sx={{ mt: 1 }} size="small" variant="text" onClick={() => void handleDecisionApprove(decision.id)} disabled={decisionApproval}>
                                        Approve
                                      </Button>
                                    ) : null}
                                  </Box>
                                ))}
                              </Stack>
                            </>
                          ) : (
                            <Alert severity="info">Select a finding to load workflow details.</Alert>
                          )}
                        </Stack>
                      ) : (
                        <Alert severity="info">Select a finding to load workflow details.</Alert>
                      )}
                      </Stack>
                    </Paper>
                  </Grid>
                </Grid>
              ) : null}

              {activeSection === "folders" ? (
                hasPermission("folders.view") ? (
                  <Grid container spacing={2}>
                    <Grid size={{ xs: 12, xl: 7 }}>
                      <Paper sx={{ p: 2.25 }}>
                        <Stack spacing={2}>
                          <Stack direction={{ xs: "column", lg: "row" }} spacing={1.25} justifyContent="space-between">
                            <TextField
                              label="Search folders"
                              value={folderSearch}
                              onChange={(event) => setFolderSearch(event.target.value)}
                              sx={{ minWidth: { xs: "100%", lg: 300 } }}
                              InputProps={{
                                startAdornment: (
                                  <InputAdornment position="start">
                                    <SearchOutlinedIcon fontSize="small" />
                                  </InputAdornment>
                                )
                              }}
                            />
                            <Stack direction="row" spacing={1}>
                              <Button variant="outlined" startIcon={<SearchOutlinedIcon />} onClick={() => void refreshFolders()} disabled={foldersLoading}>
                                Load
                              </Button>
                              <Button variant="outlined" startIcon={<RefreshOutlinedIcon />} onClick={() => void refreshFolders(true)} disabled={foldersLoading}>
                                Sync
                              </Button>
                            </Stack>
                          </Stack>
                          <Stack direction="row" justifyContent="space-between" alignItems="center">
                            <Typography variant="body2" color="text.secondary">
                              {folders.length} folders
                            </Typography>
                            {foldersLoading ? <CircularProgress size={18} /> : null}
                          </Stack>
                          <TableContainer sx={{ maxHeight: 620 }}>
                            <Table stickyHeader size="small">
                              <TableHead>
                                <TableRow>
                                  <TableCell>Name</TableCell>
                                  <TableCell>Folder ID</TableCell>
                                  <TableCell>Type</TableCell>
                                  <TableCell>Owner</TableCell>
                                  <TableCell>Scans</TableCell>
                                  <TableCell>Status</TableCell>
                                </TableRow>
                              </TableHead>
                              <TableBody>
                                {folders.map((row) => (
                                  <TableRow
                                    key={row.id}
                                    hover
                                    selected={selectedFolderId === row.id}
                                    onClick={() => setSelectedFolderId(row.id)}
                                    sx={{ cursor: "pointer" }}
                                  >
                                    <TableCell>
                                      <Stack spacing={0.3}>
                                        <Typography variant="body2">{row.name}</Typography>
                                        <Typography variant="caption" color="text.secondary">
                                          {row.is_custom ? "Custom" : "System"}
                                        </Typography>
                                      </Stack>
                                    </TableCell>
                                    <TableCell>{row.nessus_folder_id}</TableCell>
                                    <TableCell>{row.folder_type || "-"}</TableCell>
                                    <TableCell>{row.owner || "-"}</TableCell>
                                    <TableCell>{row.scan_count}</TableCell>
                                    <TableCell>
                                      <Chip label={row.permission_status} size="small" variant="outlined" color={row.deleted_at ? "default" : "success"} />
                                    </TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </TableContainer>
                        </Stack>
                      </Paper>
                    </Grid>

                    <Grid size={{ xs: 12, xl: 5 }}>
                      <Stack spacing={2}>
                        <Paper sx={{ p: 2.25 }}>
                          <Stack spacing={1.5}>
                            <Typography variant="h6">Create Folder</Typography>
                            <TextField
                              fullWidth
                              label="Folder name"
                              value={folderCreateName}
                              onChange={(event) => setFolderCreateName(event.target.value)}
                            />
                            <Button
                              variant="contained"
                              startIcon={<AddOutlinedIcon />}
                              onClick={() => void handleFolderCreate()}
                              disabled={!hasPermission("folders.create") || folderCreateBusy || !folderCreateName.trim()}
                            >
                              {folderCreateBusy ? "Creating..." : "Create Folder"}
                            </Button>
                          </Stack>
                        </Paper>

                        <Paper sx={{ p: 2.25 }}>
                          <Stack spacing={1.5}>
                            <Stack direction="row" justifyContent="space-between" alignItems="center">
                              <Box>
                                <Typography variant="h6">Folder Details</Typography>
                                <Typography variant="body2" color="text.secondary">
                                  {selectedFolder ? selectedFolder.nessus_folder_id : "No folder selected"}
                                </Typography>
                              </Box>
                              {selectedFolder ? (
                                <Chip label={selectedFolder.is_custom ? "Custom" : "System"} size="small" variant="outlined" />
                              ) : null}
                            </Stack>
                            {selectedFolder ? (
                              <>
                                <Grid container spacing={1.25}>
                                  <Grid size={{ xs: 6 }}>
                                    <Typography variant="caption" color="text.secondary">Owner</Typography>
                                    <Typography variant="body2">{selectedFolder.owner || "-"}</Typography>
                                  </Grid>
                                  <Grid size={{ xs: 6 }}>
                                    <Typography variant="caption" color="text.secondary">Scan count</Typography>
                                    <Typography variant="body2">{selectedFolder.scan_count}</Typography>
                                  </Grid>
                                  <Grid size={{ xs: 12 }}>
                                    <Typography variant="caption" color="text.secondary">Last sync</Typography>
                                    <Typography variant="body2">{formatTimestamp(selectedFolder.last_synchronized_at)}</Typography>
                                  </Grid>
                                </Grid>
                                <Divider />
                                <TextField
                                  fullWidth
                                  label="Rename folder"
                                  value={folderRenameName}
                                  onChange={(event) => setFolderRenameName(event.target.value)}
                                />
                                <Button
                                  variant="outlined"
                                  startIcon={<SaveOutlinedIcon />}
                                  onClick={() => void handleFolderRename()}
                                  disabled={!hasPermission("folders.rename") || folderRenameBusy || !selectedFolder.is_custom || !folderRenameName.trim()}
                                >
                                  {folderRenameBusy ? "Saving..." : "Rename Folder"}
                                </Button>
                              </>
                            ) : (
                              <Alert severity="info">Select a folder to manage it.</Alert>
                            )}
                          </Stack>
                        </Paper>

                        {selectedFolder ? (
                          <Paper sx={{ p: 2.25 }}>
                            <Stack spacing={1.5}>
                              <Typography variant="h6">Delete Preview</Typography>
                              <Button
                                variant="outlined"
                                startIcon={<DeleteOutlineOutlinedIcon />}
                                onClick={() => void loadFolderDeletePreview(selectedFolder.id)}
                                disabled={!hasPermission("folders.delete") || folderPreviewBusy || !selectedFolder.is_custom}
                              >
                                {folderPreviewBusy ? "Loading..." : "Prepare Delete"}
                              </Button>
                              {folderDeletePreview && folderDeletePreview.folder.id === selectedFolder.id ? (
                                <>
                                  <Alert severity="warning">{folderDeletePreview.deletion_behavior}</Alert>
                                  <Stack spacing={0.75}>
                                    <Typography variant="subtitle2">Affected scans</Typography>
                                    {folderDeletePreview.affected_scans.length === 0 ? (
                                      <Typography variant="body2" color="text.secondary">No remote scans reported in this folder.</Typography>
                                    ) : (
                                      folderDeletePreview.affected_scans.map((scan) => (
                                        <Box key={`${scan.id || scan.uuid || scan.name}`} sx={{ border: 1, borderColor: "divider", borderRadius: 1.5, px: 1.25, py: 1 }}>
                                          <Typography variant="body2">{String(scan.name || scan.id || "Unnamed scan")}</Typography>
                                          <Typography variant="caption" color="text.secondary">
                                            {String(scan.status || "unknown")} {scan.uuid ? `| ${scan.uuid}` : ""}
                                          </Typography>
                                        </Box>
                                      ))
                                    )}
                                  </Stack>
                                  <TextField
                                    fullWidth
                                    label="Type folder name"
                                    value={folderDeleteDraft.confirmation_name}
                                    onChange={(event) => setFolderDeleteDraft((current) => ({ ...current, confirmation_name: event.target.value }))}
                                  />
                                  <TextField
                                    fullWidth
                                    label="Current password"
                                    type="password"
                                    value={folderDeleteDraft.current_password}
                                    onChange={(event) => setFolderDeleteDraft((current) => ({ ...current, current_password: event.target.value }))}
                                  />
                                  <Button
                                    color="error"
                                    variant="contained"
                                    startIcon={<DeleteOutlineOutlinedIcon />}
                                    onClick={() => void handleFolderDelete()}
                                    disabled={
                                      folderDeleteBusy ||
                                      folderDeleteDraft.confirmation_name !== selectedFolder.name ||
                                      !folderDeleteDraft.current_password
                                    }
                                  >
                                    {folderDeleteBusy ? "Deleting..." : "Delete Folder"}
                                  </Button>
                                </>
                              ) : null}
                              {!selectedFolder.is_custom ? <Alert severity="info">System folders are protected.</Alert> : null}
                            </Stack>
                          </Paper>
                        ) : null}
                      </Stack>
                    </Grid>
                  </Grid>
                ) : (
                  <Alert severity="info">Folder access is not available for this account.</Alert>
                )
              ) : null}

              {activeSection === "scans" ? (
                hasPermission("scans.view") ? (
                  <Grid container spacing={2}>
                    <Grid size={{ xs: 12, xl: 7 }}>
                      <Paper sx={{ p: 2.25 }}>
                        <Stack spacing={2}>
                          <Stack direction={{ xs: "column", lg: "row" }} spacing={1.25} justifyContent="space-between">
                            <TextField
                              label="Search scans"
                              value={scanSearch}
                              onChange={(event) => setScanSearch(event.target.value)}
                              sx={{ minWidth: { xs: "100%", lg: 300 } }}
                              InputProps={{
                                startAdornment: (
                                  <InputAdornment position="start">
                                    <SearchOutlinedIcon fontSize="small" />
                                  </InputAdornment>
                                )
                              }}
                            />
                            <Stack direction="row" spacing={1}>
                              <Button variant="outlined" startIcon={<SearchOutlinedIcon />} onClick={() => void refreshScans()} disabled={scansLoading}>
                                Load
                              </Button>
                              <Button variant="outlined" startIcon={<RefreshOutlinedIcon />} onClick={() => void refreshScans(true)} disabled={scansLoading}>
                                Sync
                              </Button>
                            </Stack>
                          </Stack>
                          <Stack direction="row" justifyContent="space-between" alignItems="center">
                            <Typography variant="body2" color="text.secondary">
                              {scans.length} scans
                            </Typography>
                            {scansLoading ? <CircularProgress size={18} /> : null}
                          </Stack>
                          <TableContainer sx={{ maxHeight: 620 }}>
                            <Table stickyHeader size="small">
                              <TableHead>
                                <TableRow>
                                  <TableCell>Name</TableCell>
                                  <TableCell>Folder</TableCell>
                                  <TableCell>Status</TableCell>
                                  <TableCell>Targets</TableCell>
                                  <TableCell>History</TableCell>
                                </TableRow>
                              </TableHead>
                              <TableBody>
                                {scans.map((row) => (
                                  <TableRow
                                    key={row.id}
                                    hover
                                    selected={selectedScanId === row.id}
                                    onClick={() => setSelectedScanId(row.id)}
                                    sx={{ cursor: "pointer" }}
                                  >
                                    <TableCell>
                                      <Stack spacing={0.3}>
                                        <Stack direction="row" spacing={0.75} alignItems="center" useFlexGap flexWrap="wrap">
                                          <Typography variant="body2">{row.name}</Typography>
                                          {row.deleted_at ? <Chip label="Trash" size="small" color="warning" variant="outlined" /> : null}
                                          {row.is_permanently_deleted ? <Chip label="Permanent" size="small" color="error" variant="outlined" /> : null}
                                        </Stack>
                                        <Typography variant="caption" color="text.secondary">
                                          {row.nessus_scan_id} | {row.nessus_uuid}
                                        </Typography>
                                      </Stack>
                                    </TableCell>
                                    <TableCell>{row.folder_name}</TableCell>
                                    <TableCell>
                                      <Chip
                                        label={row.status}
                                        size="small"
                                        variant="outlined"
                                        color={row.status === "running" ? "warning" : row.status === "completed" ? "success" : "default"}
                                      />
                                    </TableCell>
                                    <TableCell>{row.target_count}</TableCell>
                                    <TableCell>{row.history_count}</TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </TableContainer>
                        </Stack>
                      </Paper>
                    </Grid>

                    <Grid size={{ xs: 12, xl: 5 }}>
                      <Stack spacing={2}>
                        <ScanCreateWizard
                          key={scanCreateWizardVersion}
                          draft={scanCreateDraft}
                          setDraft={setScanCreateDraft}
                          folders={folders.map((folder) => ({ id: folder.id, name: folder.name }))}
                          templates={scanTemplates}
                          policies={scanPolicies.map((policy) => ({
                            id: policy.id,
                            name: policy.name,
                            has_credentials: policy.has_credentials
                          }))}
                          scanners={scanners.map((scanner) => ({
                            id: scanner.id,
                            name: scanner.name,
                            status: scanner.status
                          }))}
                          masterTemplates={availableMasterTemplates.map((scan) => ({
                            id: scan.id,
                            name: scan.name,
                            folder_name: scan.folder_name,
                            target_count: scan.target_count
                          }))}
                          scheduleOptions={scanScheduleOptions}
                          dependenciesLoading={scanDependenciesLoading}
                          createBusy={scanCreateBusy}
                          scanApiUnavailable={scanApiUnavailable}
                          canCreate={hasPermission("scans.create")}
                          onSubmit={() => void handleScanCreate()}
                        />

                        <Paper sx={{ p: 2.25 }}>
                          <Stack spacing={1.5}>
                            <Stack direction="row" justifyContent="space-between" alignItems="center">
                              <Box>
                                <Typography variant="h6">Selected Scan</Typography>
                                <Typography variant="body2" color="text.secondary">
                                  {selectedScan ? selectedScan.nessus_scan_id : "No scan selected"}
                                </Typography>
                              </Box>
                              {selectedScan ? <Chip label={selectedScan.status} size="small" variant="outlined" /> : null}
                            </Stack>
                            {selectedScan ? (
                              <>
                                <Grid container spacing={1.25}>
                                  <Grid size={{ xs: 6 }}>
                                    <Typography variant="caption" color="text.secondary">Folder</Typography>
                                    <Typography variant="body2">{selectedScan.folder_name}</Typography>
                                  </Grid>
                                  <Grid size={{ xs: 6 }}>
                                    <Typography variant="caption" color="text.secondary">Owner</Typography>
                                    <Typography variant="body2">{selectedScan.owner || "-"}</Typography>
                                  </Grid>
                                  <Grid size={{ xs: 6 }}>
                                    <Typography variant="caption" color="text.secondary">Last launch</Typography>
                                    <Typography variant="body2">{formatTimestamp(selectedScan.last_launch_at)}</Typography>
                                  </Grid>
                                  <Grid size={{ xs: 6 }}>
                                    <Typography variant="caption" color="text.secondary">Last completion</Typography>
                                    <Typography variant="body2">{formatTimestamp(selectedScan.last_completion_at)}</Typography>
                                  </Grid>
                                  <Grid size={{ xs: 6 }}>
                                    <Typography variant="caption" color="text.secondary">Trash state</Typography>
                                    <Typography variant="body2">
                                      {selectedScan.deleted_at ? `In Trash since ${formatTimestamp(selectedScan.deleted_at)}` : "Active"}
                                    </Typography>
                                  </Grid>
                                  <Grid size={{ xs: 6 }}>
                                    <Typography variant="caption" color="text.secondary">Permanent delete</Typography>
                                    <Typography variant="body2">
                                      {selectedScan.permanently_deleted_at ? formatTimestamp(selectedScan.permanently_deleted_at) : "Not deleted"}
                                    </Typography>
                                  </Grid>
                                </Grid>
                                <TextField
                                  fullWidth
                                  label="Scan name"
                                  value={scanUpdateDraft.name}
                                  onChange={(event) => setScanUpdateDraft((current) => ({ ...current, name: event.target.value }))}
                                  disabled={Boolean(selectedScan.deleted_at || selectedScan.is_permanently_deleted)}
                                />
                                <FormControl fullWidth>
                                  <InputLabel id="edit-folder-label">Folder</InputLabel>
                                  <Select
                                    labelId="edit-folder-label"
                                    label="Folder"
                                    value={scanUpdateDraft.folder_record_id}
                                    onChange={(event) => setScanUpdateDraft((current) => ({ ...current, folder_record_id: event.target.value }))}
                                    disabled={Boolean(selectedScan.deleted_at || selectedScan.is_permanently_deleted)}
                                  >
                                    {folders.map((folder) => (
                                      <MenuItem key={folder.id} value={folder.id}>
                                        {folder.name}
                                      </MenuItem>
                                    ))}
                                  </Select>
                                </FormControl>
                                <FormControl fullWidth>
                                  <InputLabel id="edit-scanner-label">Scanner</InputLabel>
                                  <Select
                                    labelId="edit-scanner-label"
                                    label="Scanner"
                                    value={scanUpdateDraft.scanner_id}
                                    onChange={(event) => setScanUpdateDraft((current) => ({ ...current, scanner_id: event.target.value }))}
                                    disabled={Boolean(selectedScan.deleted_at || selectedScan.is_permanently_deleted)}
                                  >
                                    <MenuItem value="">Default</MenuItem>
                                    {scanners.map((item) => (
                                      <MenuItem key={item.id} value={item.id}>
                                        {item.name} ({item.status})
                                      </MenuItem>
                                    ))}
                                  </Select>
                                </FormControl>
                                <FormControl fullWidth>
                                  <InputLabel id="edit-schedule-label">Schedule</InputLabel>
                                  <Select
                                    labelId="edit-schedule-label"
                                    label="Schedule"
                                    value={scanUpdateDraft.schedule_type}
                                    onChange={(event) => setScanUpdateDraft((current) => ({ ...current, schedule_type: event.target.value }))}
                                    disabled={Boolean(selectedScan.deleted_at || selectedScan.is_permanently_deleted)}
                                  >
                                    {scanScheduleOptions.map((item) => (
                                      <MenuItem key={item.value} value={item.value}>
                                        {item.label}
                                      </MenuItem>
                                    ))}
                                  </Select>
                                </FormControl>
                                <TextField
                                  fullWidth
                                  multiline
                                  minRows={4}
                                  label="Targets"
                                  value={scanUpdateDraft.targets}
                                  onChange={(event) => setScanUpdateDraft((current) => ({ ...current, targets: event.target.value }))}
                                  disabled={Boolean(selectedScan.deleted_at || selectedScan.is_permanently_deleted)}
                                />
                                <Stack direction={{ xs: "column", sm: "row" }} spacing={1}>
                                  <Button
                                    variant="contained"
                                    startIcon={<SaveOutlinedIcon />}
                                    onClick={() => void handleScanUpdate()}
                                    disabled={
                                      scanApiUnavailable ||
                                      !hasPermission("scans.edit") ||
                                      scanUpdateBusy ||
                                      !scanUpdateDraft.name.trim() ||
                                      !scanUpdateDraft.targets.trim() ||
                                      Boolean(selectedScan.deleted_at || selectedScan.is_permanently_deleted)
                                    }
                                  >
                                    {scanUpdateBusy ? "Saving..." : "Save"}
                                  </Button>
                                  <Button
                                    variant="outlined"
                                    startIcon={<DriveFileMoveOutlinedIcon />}
                                    onClick={() => void handleScanMove()}
                                    disabled={
                                      scanApiUnavailable ||
                                      !hasPermission("scans.move") ||
                                      scanActionBusy === "move" ||
                                      !scanUpdateDraft.folder_record_id ||
                                      Boolean(selectedScan.deleted_at || selectedScan.is_permanently_deleted)
                                    }
                                  >
                                    {scanActionBusy === "move" ? "Moving..." : "Move"}
                                  </Button>
                                  <Button
                                    variant="outlined"
                                    startIcon={<PlayArrowOutlinedIcon />}
                                    onClick={() => void handleScanLaunch()}
                                    disabled={
                                      scanApiUnavailable ||
                                      !hasPermission("scans.launch") ||
                                      scanActionBusy === "launch" ||
                                      Boolean(selectedScan.deleted_at || selectedScan.is_permanently_deleted)
                                    }
                                  >
                                    {scanActionBusy === "launch" ? "Launching..." : "Launch"}
                                  </Button>
                                  <Button
                                    variant="outlined"
                                    startIcon={<StopOutlinedIcon />}
                                    onClick={() => void handleScanPause()}
                                    disabled={
                                      scanApiUnavailable ||
                                      !hasPermission("scans.pause") ||
                                      scanActionBusy === "pause" ||
                                      Boolean(selectedScan.deleted_at || selectedScan.is_permanently_deleted) ||
                                      selectedScan.status !== "running"
                                    }
                                  >
                                    {scanActionBusy === "pause" ? "Pausing..." : "Pause"}
                                  </Button>
                                  <Button
                                    variant="outlined"
                                    startIcon={<PlayArrowOutlinedIcon />}
                                    onClick={() => void handleScanResume()}
                                    disabled={
                                      scanApiUnavailable ||
                                      !hasPermission("scans.resume") ||
                                      scanActionBusy === "resume" ||
                                      Boolean(selectedScan.deleted_at || selectedScan.is_permanently_deleted) ||
                                      selectedScan.status !== "paused"
                                    }
                                  >
                                    {scanActionBusy === "resume" ? "Resuming..." : "Resume"}
                                  </Button>
                                  <Button
                                    variant="outlined"
                                    startIcon={<StopOutlinedIcon />}
                                    onClick={() => void handleScanStop()}
                                    disabled={
                                      scanApiUnavailable ||
                                      !hasPermission("scans.stop") ||
                                      scanActionBusy === "stop" ||
                                      Boolean(selectedScan.deleted_at || selectedScan.is_permanently_deleted)
                                    }
                                  >
                                    {scanActionBusy === "stop" ? "Stopping..." : "Stop"}
                                  </Button>
                                  <Button
                                    color="error"
                                    variant="outlined"
                                    startIcon={<DeleteOutlineOutlinedIcon />}
                                    onClick={() => void handleScanTrash()}
                                    disabled={
                                      scanApiUnavailable ||
                                      !hasPermission("scans.delete") ||
                                      scanActionBusy === "trash" ||
                                      Boolean(selectedScan.deleted_at || selectedScan.is_permanently_deleted)
                                    }
                                  >
                                    {scanActionBusy === "trash" ? "Removing..." : "Trash"}
                                  </Button>
                                  <Button
                                    color="warning"
                                    variant="outlined"
                                    startIcon={<RefreshOutlinedIcon />}
                                    onClick={() => void handleScanRestore()}
                                    disabled={!hasPermission("scans.restore") || scanActionBusy === "restore" || !selectedScan.is_restorable}
                                  >
                                    {scanActionBusy === "restore" ? "Restoring..." : "Restore"}
                                  </Button>
                                  <Button
                                    color="error"
                                    variant="contained"
                                    startIcon={<DeleteOutlineOutlinedIcon />}
                                    onClick={() => void handleScanPermanentDelete()}
                                    disabled={
                                      !hasPermission("scans.permanent_delete") ||
                                      scanActionBusy === "permanent-delete" ||
                                      !selectedScan.deleted_at ||
                                      selectedScan.is_restorable ||
                                      selectedScan.is_permanently_deleted
                                    }
                                  >
                                    {scanActionBusy === "permanent-delete" ? "Deleting..." : "Permanent Delete"}
                                  </Button>
                                </Stack>
                                <Alert severity={scanApiUnavailable ? "warning" : "info"}>
                                  {scanApiUnavailable
                                    ? "The connected Nessus license disables live scan-control API actions such as launch, pause, resume, stop, move, edit, and trash."
                                    : selectedScan.is_permanently_deleted
                                      ? "This scan is permanently deleted in the local inventory and cannot be restored."
                                      : selectedScan.deleted_at
                                        ? selectedScan.is_restorable
                                          ? "This scan is in Trash and can be restored because it still exists in Nessus."
                                          : "This scan is in Trash. Permanent delete becomes available once the remote scan no longer exists in Nessus."
                                        : "Active scans support launch, pause, resume, stop, trash, and the normal edit workflow."}
                                </Alert>
                              </>
                            ) : (
                              <Alert severity="info">Select a scan to manage it.</Alert>
                            )}
                          </Stack>
                        </Paper>

                        {selectedScan ? (
                          <>
                            <Paper sx={{ p: 2.25 }}>
                              <Stack spacing={1.5}>
                                <Typography variant="h6">Clone Scan</Typography>
                                <TextField
                                  fullWidth
                                  label="Clone name"
                                  value={scanCloneDraft.name}
                                  onChange={(event) => setScanCloneDraft((current) => ({ ...current, name: event.target.value }))}
                                />
                                <FormControl fullWidth>
                                  <InputLabel id="clone-folder-label">Folder</InputLabel>
                                  <Select
                                    labelId="clone-folder-label"
                                    label="Folder"
                                    value={scanCloneDraft.folder_record_id}
                                    onChange={(event) => setScanCloneDraft((current) => ({ ...current, folder_record_id: event.target.value }))}
                                  >
                                    <MenuItem value="">Keep source folder</MenuItem>
                                    {folders.map((folder) => (
                                      <MenuItem key={folder.id} value={folder.id}>
                                        {folder.name}
                                      </MenuItem>
                                    ))}
                                  </Select>
                                </FormControl>
                                <FormControl fullWidth>
                                  <InputLabel id="clone-scanner-label">Scanner</InputLabel>
                                  <Select
                                    labelId="clone-scanner-label"
                                    label="Scanner"
                                    value={scanCloneDraft.scanner_id}
                                    onChange={(event) => setScanCloneDraft((current) => ({ ...current, scanner_id: event.target.value }))}
                                  >
                                    <MenuItem value="">Keep source scanner</MenuItem>
                                    {scanners.map((item) => (
                                      <MenuItem key={item.id} value={item.id}>
                                        {item.name} ({item.status})
                                      </MenuItem>
                                    ))}
                                  </Select>
                                </FormControl>
                                <FormControlLabel
                                  control={
                                    <Switch
                                      checked={scanCloneDraft.launch_now}
                                      onChange={(event) => setScanCloneDraft((current) => ({ ...current, launch_now: event.target.checked }))}
                                    />
                                  }
                                  label="Launch cloned scan"
                                />
                                <Button
                                  variant="outlined"
                                  startIcon={<ContentCopyOutlinedIcon />}
                                  onClick={() => void handleScanClone()}
                                  disabled={scanApiUnavailable || !hasPermission("scans.clone") || scanCloneBusy || !scanCloneDraft.name.trim()}
                                >
                                  {scanCloneBusy ? "Cloning..." : "Clone Scan"}
                                </Button>
                              </Stack>
                            </Paper>

                            <Paper sx={{ p: 2.25 }}>
                              <Stack spacing={1.5}>
                                <Stack direction="row" justifyContent="space-between" alignItems="center">
                                  <Typography variant="h6">Scan History</Typography>
                                  {scanHistoryLoading ? <CircularProgress size={18} /> : null}
                                </Stack>
                                <TextField
                                  fullWidth
                                  label="Delete justification"
                                  value={scanHistoryDeleteJustification}
                                  onChange={(event) => setScanHistoryDeleteJustification(event.target.value)}
                                />
                                <Stack spacing={1}>
                                  {scanHistories.length === 0 ? (
                                    <Typography variant="body2" color="text.secondary">No histories available.</Typography>
                                  ) : (
                                    scanHistories.map((history) => (
                                      <Box key={history.id} sx={{ border: 1, borderColor: "divider", borderRadius: 1.5, px: 1.25, py: 1.25 }}>
                                        <Stack direction="row" justifyContent="space-between" alignItems="flex-start" spacing={1}>
                                          <Box>
                                            <Typography variant="body2">History {history.nessus_history_id}</Typography>
                                            <Typography variant="caption" color="text.secondary">
                                              {history.status} | {formatTimestamp(history.started_at)} to {formatTimestamp(history.completed_at)}
                                            </Typography>
                                          </Box>
                                          <Chip
                                            label={history.is_baseline_locked || history.is_evidence_locked ? "Protected" : "Deletable"}
                                            size="small"
                                            color={history.is_baseline_locked || history.is_evidence_locked ? "warning" : "default"}
                                            variant="outlined"
                                          />
                                        </Stack>
                                        <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 0.75 }}>
                                          Findings: {history.finding_count}
                                        </Typography>
                                        <Button
                                          sx={{ mt: 1 }}
                                          size="small"
                                          color="error"
                                          variant="text"
                                          onClick={() => void handleScanHistoryDelete(history.id)}
                                          disabled={
                                            !hasPermission("scan_history.delete") ||
                                            Boolean(history.is_baseline_locked || history.is_evidence_locked) ||
                                            scanHistoryDeleteBusy === history.id ||
                                            !scanHistoryDeleteJustification.trim()
                                          }
                                        >
                                          {scanHistoryDeleteBusy === history.id ? "Deleting..." : "Delete History"}
                                        </Button>
                                      </Box>
                                    ))
                                  )}
                                </Stack>
                              </Stack>
                            </Paper>
                          </>
                        ) : null}
                      </Stack>
                    </Grid>
                  </Grid>
                ) : (
                  <Alert severity="info">Scan access is not available for this account.</Alert>
                )
              ) : null}

              {activeSection === "ip-search" ? (
                hasPermission("scans.view") ? (
                  <Grid container spacing={2}>
                    <Grid size={{ xs: 12, xl: 4.5 }}>
                      <Stack spacing={2}>
                        <Paper sx={{ p: 2.25 }}>
                          <Stack spacing={1.5}>
                            <Typography variant="h6">Bulk IP Search</Typography>
                            <TextField
                              fullWidth
                              multiline
                              minRows={12}
                              label="Targets"
                              placeholder="10.0.0.1&#10;192.168.1.10&#10;10.0.0.0/24"
                              value={ipSearchEntries}
                              onChange={(event) => setIpSearchEntries(event.target.value)}
                            />
                            <FormControlLabel
                              control={<Switch checked={ipSearchExpandCidr} onChange={(event) => setIpSearchExpandCidr(event.target.checked)} />}
                              label="Expand CIDR ranges"
                            />
                            <Button
                              variant="contained"
                              startIcon={<SearchOutlinedIcon />}
                              onClick={() => void handleIpSearch()}
                              disabled={ipSearchBusy || !ipSearchEntries.trim()}
                            >
                              {ipSearchBusy ? "Searching..." : "Search Entries"}
                            </Button>
                          </Stack>
                        </Paper>

                        <Paper sx={{ p: 2.25 }}>
                          <Stack spacing={1.5}>
                            <Typography variant="h6">File Upload</Typography>
                            <Button component="label" variant="outlined" startIcon={<CloudUploadOutlinedIcon />}>
                              Select File
                              <input
                                hidden
                                type="file"
                                accept=".txt,.csv,.xlsx"
                                onChange={(event) => setIpSearchFile(event.target.files?.[0] || null)}
                              />
                            </Button>
                            <Typography variant="body2" color="text.secondary">
                              {ipSearchFile ? ipSearchFile.name : "No file selected"}
                            </Typography>
                            <Button
                              variant="contained"
                              onClick={() => void handleIpUploadSearch()}
                              disabled={!ipSearchFile || ipSearchUploadBusy}
                            >
                              {ipSearchUploadBusy ? "Processing..." : "Process File"}
                            </Button>
                          </Stack>
                        </Paper>
                      </Stack>
                    </Grid>

                    <Grid size={{ xs: 12, xl: 7.5 }}>
                      <Paper sx={{ p: 2.25 }}>
                        <Stack spacing={2}>
                          <Typography variant="h6">Search Results</Typography>
                          {ipSearchResponse ? (
                            <>
                              <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap">
                                <Chip label={`Inputs ${ipSearchResponse.total_inputs}`} size="small" variant="outlined" />
                                <Chip label={`Unique ${ipSearchResponse.unique_inputs}`} size="small" variant="outlined" />
                                <Chip label={`Invalid ${ipSearchResponse.invalid_inputs.length}`} size="small" variant="outlined" color={ipSearchResponse.invalid_inputs.length > 0 ? "warning" : "default"} />
                              </Stack>
                              {ipSearchResponse.invalid_inputs.length > 0 ? (
                                <Alert severity="warning">{ipSearchResponse.invalid_inputs.join(", ")}</Alert>
                              ) : null}
                              <TableContainer sx={{ maxHeight: 700 }}>
                                <Table stickyHeader size="small">
                                  <TableHead>
                                    <TableRow>
                                      <TableCell>Query</TableCell>
                                      <TableCell>Folder</TableCell>
                                      <TableCell>Scan</TableCell>
                                      <TableCell>Status</TableCell>
                                      <TableCell>Reachability</TableCell>
                                      <TableCell>Authentication</TableCell>
                                      <TableCell>Credentialed</TableCell>
                                      <TableCell>Last scan</TableCell>
                                    </TableRow>
                                  </TableHead>
                                  <TableBody>
                                    {ipSearchResponse.results.flatMap((result) => {
                                      if (result.matches.length === 0) {
                                        return [
                                          <TableRow key={`${result.query}-empty`}>
                                            <TableCell>{result.query}</TableCell>
                                            <TableCell colSpan={7}>
                                              <Typography variant="body2" color="text.secondary">
                                                No matching scan targets found.
                                              </Typography>
                                            </TableCell>
                                          </TableRow>
                                        ];
                                      }
                                      return result.matches.map((match, index) => (
                                        <TableRow key={`${result.query}-${match.scan_name}-${index}`}>
                                          <TableCell>{result.query}</TableCell>
                                          <TableCell>{match.folder_name}</TableCell>
                                          <TableCell>{match.scan_name}</TableCell>
                                          <TableCell>{match.scan_status}</TableCell>
                                          <TableCell>{match.reachability}</TableCell>
                                          <TableCell>{match.authentication_status}</TableCell>
                                          <TableCell>{match.credentialed_checks_status}</TableCell>
                                          <TableCell>{formatTimestamp(match.last_scan_date)}</TableCell>
                                        </TableRow>
                                      ));
                                    })}
                                  </TableBody>
                                </Table>
                              </TableContainer>
                            </>
                          ) : (
                            <Alert severity="info">Run a manual search or upload a file to see matches across synchronized scans.</Alert>
                          )}
                        </Stack>
                      </Paper>
                    </Grid>
                  </Grid>
                ) : (
                  <Alert severity="info">IP search is not available for this account.</Alert>
                )
              ) : null}

              {activeSection === "reports" ? (
                <Paper sx={{ p: 2.25 }}>
                  <Grid container spacing={2}>
                    <Grid size={{ xs: 12, xl: 5 }}>
                      <Stack spacing={1.25}>
                        <FormControl fullWidth>
                          <InputLabel id="report-type-label">Report</InputLabel>
                          <Select labelId="report-type-label" label="Report" value={reportType} onChange={(event) => setReportType(event.target.value)}>
                            {reportTypes.map((item) => (
                              <MenuItem key={item.value} value={item.value}>
                                {item.label}
                              </MenuItem>
                            ))}
                          </Select>
                        </FormControl>
                        <FormControl fullWidth>
                          <InputLabel id="report-format-label">Format</InputLabel>
                          <Select labelId="report-format-label" label="Format" value={reportFormat} onChange={(event) => setReportFormat(event.target.value)}>
                            <MenuItem value="csv">CSV</MenuItem>
                            <MenuItem value="xlsx">Excel</MenuItem>
                          </Select>
                        </FormControl>
                        {selectedReport.requiresEntries ? (
                          <>
                            <TextField
                              fullWidth
                              multiline
                              minRows={4}
                              label="Entries"
                              value={reportEntries}
                              onChange={(event) => setReportEntries(event.target.value)}
                              placeholder="10.10.10.5&#10;10.10.10.0/24&#10;192.168.1.15"
                            />
                            <FormControlLabel
                              control={<Switch checked={reportExpandCidr} onChange={(event) => setReportExpandCidr(event.target.checked)} />}
                              label="Expand CIDR ranges before export"
                            />
                          </>
                        ) : null}
                        {selectedReport.supportsDaysUntilExpiry ? (
                          <TextField
                            fullWidth
                            type="number"
                            label="Days until expiry"
                            value={reportDaysUntilExpiry}
                            onChange={(event) => setReportDaysUntilExpiry(event.target.value)}
                            inputProps={{ min: 0, max: 365 }}
                          />
                        ) : null}
                        <Alert severity="info">{selectedReport.description}</Alert>
                        <Button startIcon={<DownloadOutlinedIcon />} variant="contained" onClick={() => void handleExport()} disabled={!hasPermission("reports.export") || exportBusy}>
                          Export
                        </Button>
                      </Stack>
                    </Grid>
                    <Grid size={{ xs: 12, xl: 7 }}>
                      <Grid container spacing={1.25}>
                        {reportTypes.map((item) => (
                          <Grid key={item.value} size={{ xs: 12, sm: 6 }}>
                            <Paper
                              sx={{
                                p: 1.75,
                                border: 1,
                                borderColor: reportType === item.value ? "primary.main" : "divider",
                                cursor: "pointer"
                              }}
                              onClick={() => setReportType(item.value)}
                            >
                              <Typography variant="subtitle2">{item.label}</Typography>
                              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.75 }}>
                                {item.description}
                              </Typography>
                            </Paper>
                          </Grid>
                        ))}
                      </Grid>
                    </Grid>
                  </Grid>
                </Paper>
              ) : null}

              {activeSection === "audit" ? (
                hasPermission("audit.view") ? (
                  <Paper sx={{ p: 2.25 }}>
                    <Stack spacing={2}>
                      <Stack direction={{ xs: "column", lg: "row" }} spacing={1.25} justifyContent="space-between">
                        <Stack direction={{ xs: "column", sm: "row" }} spacing={1}>
                          <TextField
                            label="Action"
                            value={auditActionFilter}
                            onChange={(event) => setAuditActionFilter(event.target.value)}
                            sx={{ minWidth: 220 }}
                          />
                          <TextField
                            label="Object type"
                            value={auditObjectTypeFilter}
                            onChange={(event) => setAuditObjectTypeFilter(event.target.value)}
                            sx={{ minWidth: 180 }}
                          />
                          <FormControl sx={{ minWidth: 160 }}>
                            <InputLabel id="audit-result-label">Result</InputLabel>
                            <Select
                              labelId="audit-result-label"
                              label="Result"
                              value={auditResultFilter}
                              onChange={(event) => setAuditResultFilter(event.target.value)}
                            >
                              <MenuItem value="">All</MenuItem>
                              <MenuItem value="success">Success</MenuItem>
                              <MenuItem value="failure">Failure</MenuItem>
                            </Select>
                          </FormControl>
                        </Stack>
                        <TextField
                          value={auditSearch}
                          onChange={(event) => setAuditSearch(event.target.value)}
                          label="Search"
                          sx={{ minWidth: { xs: "100%", lg: 260 } }}
                          InputProps={{
                            startAdornment: (
                              <InputAdornment position="start">
                                <SearchOutlinedIcon fontSize="small" />
                              </InputAdornment>
                            )
                          }}
                        />
                      </Stack>
                      <Stack direction="row" justifyContent="space-between" alignItems="center">
                        <Typography variant="body2" color="text.secondary">
                          {auditEvents.length} events
                        </Typography>
                        {auditLoading ? <CircularProgress size={18} /> : null}
                      </Stack>
                      <TableContainer sx={{ maxHeight: 680 }}>
                        <Table stickyHeader size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell>Timestamp</TableCell>
                              <TableCell>Actor</TableCell>
                              <TableCell>Action</TableCell>
                              <TableCell>Object</TableCell>
                              <TableCell>Result</TableCell>
                              <TableCell>Context</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {auditEvents.map((row) => (
                              <TableRow key={row.id} hover>
                                <TableCell>{row.timestamp.replace("T", " ").replace("+00:00", " UTC")}</TableCell>
                                <TableCell>{row.actor_username || "-"}</TableCell>
                                <TableCell>{row.action}</TableCell>
                                <TableCell>
                                  <Stack spacing={0.3}>
                                    <Typography variant="body2">{row.object_type}</Typography>
                                    <Typography variant="caption" color="text.secondary">
                                      {row.object_name || row.object_id || "-"}
                                    </Typography>
                                  </Stack>
                                </TableCell>
                                <TableCell>
                                  <Chip
                                    label={row.result}
                                    size="small"
                                    color={row.result === "success" ? "success" : row.result === "failure" ? "error" : "default"}
                                    variant="outlined"
                                  />
                                </TableCell>
                                <TableCell>
                                  <Stack spacing={0.3}>
                                    <Typography variant="body2">{row.source_ip || "-"}</Typography>
                                    <Typography variant="caption" color="text.secondary">
                                      {row.justification || row.new_state || row.previous_state || "-"}
                                    </Typography>
                                  </Stack>
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </Stack>
                  </Paper>
                ) : (
                  <Alert severity="info">Audit access is not available for this account.</Alert>
                )
              ) : null}

              {activeSection === "settings" ? (
                isAdministrator ? (
                  <Grid container spacing={2}>
                    <Grid size={{ xs: 12, xl: 7 }}>
                      <Paper sx={{ p: 2.25 }}>
                        <Stack spacing={2}>
                          <Stack direction="row" justifyContent="space-between" alignItems="center">
                            <Box>
                              <Typography variant="h6">Nessus Connection</Typography>
                              <Typography variant="body2" color="text.secondary">
                                Administrator configuration
                              </Typography>
                            </Box>
                            {nessusLoading ? <CircularProgress size={20} /> : null}
                          </Stack>
                          <Grid container spacing={1.25}>
                            <Grid size={{ xs: 12 }}>
                              <TextField
                                fullWidth
                                label="Nessus URL"
                                value={nessusForm.base_url}
                                onChange={(event) => setNessusForm((current) => ({ ...current, base_url: event.target.value }))}
                              />
                            </Grid>
                            <Grid size={{ xs: 12, sm: 6 }}>
                              <TextField
                                fullWidth
                                label="Access key"
                                value={nessusForm.access_key}
                                onChange={(event) => setNessusForm((current) => ({ ...current, access_key: event.target.value }))}
                                helperText={nessusConfig?.masked_access_key ? `Saved: ${nessusConfig.masked_access_key}` : "Enter access key"}
                              />
                            </Grid>
                            <Grid size={{ xs: 12, sm: 6 }}>
                              <TextField
                                fullWidth
                                label="Secret key"
                                type="password"
                                value={nessusForm.secret_key}
                                onChange={(event) => setNessusForm((current) => ({ ...current, secret_key: event.target.value }))}
                                helperText={nessusConfig?.masked_secret_key ? `Saved: ${nessusConfig.masked_secret_key}` : "Enter secret key"}
                              />
                            </Grid>
                            <Grid size={{ xs: 12, sm: 4 }}>
                              <TextField
                                fullWidth
                                label="Timeout seconds"
                                type="number"
                                value={nessusForm.timeout_seconds}
                                onChange={(event) => setNessusForm((current) => ({ ...current, timeout_seconds: event.target.value }))}
                                inputProps={{ min: 1, max: 120 }}
                              />
                            </Grid>
                            <Grid size={{ xs: 12, sm: 8 }}>
                              <TextField
                                fullWidth
                                label="Approved hosts"
                                value={nessusForm.approved_hosts}
                                onChange={(event) => setNessusForm((current) => ({ ...current, approved_hosts: event.target.value }))}
                                placeholder="scanner.example.com, 10.1.2.3"
                              />
                            </Grid>
                            <Grid size={{ xs: 12 }}>
                              <FormControlLabel
                                control={<Switch checked={nessusForm.verify_tls} onChange={(event) => setNessusForm((current) => ({ ...current, verify_tls: event.target.checked }))} />}
                                label="Verify TLS"
                              />
                            </Grid>
                          </Grid>
                          <Stack direction={{ xs: "column", sm: "row" }} spacing={1}>
                            <Button
                              variant="outlined"
                              onClick={() => void handleNessusTest()}
                              disabled={
                                nessusTesting ||
                                !nessusForm.base_url.trim() ||
                                nessusForm.access_key.trim().length < 8 ||
                                nessusForm.secret_key.trim().length < 8
                              }
                            >
                              {nessusTesting ? "Testing..." : "Test Connection"}
                            </Button>
                            <Button
                              variant="contained"
                              startIcon={<SaveOutlinedIcon />}
                              onClick={() => void handleNessusSave()}
                              disabled={
                                nessusSaving ||
                                !nessusForm.base_url.trim() ||
                                nessusForm.access_key.trim().length < 8 ||
                                nessusForm.secret_key.trim().length < 8
                              }
                            >
                              {nessusSaving ? "Saving..." : "Save Configuration"}
                            </Button>
                          </Stack>
                        </Stack>
                      </Paper>
                    </Grid>

                    <Grid size={{ xs: 12, xl: 5 }}>
                      <Stack spacing={2}>
                        <Paper sx={{ p: 2.25 }}>
                          <Stack spacing={1.5}>
                            <Typography variant="h6">Current State</Typography>
                            <Chip
                              label={nessusConfig?.configured ? "Configured" : "Not configured"}
                              size="small"
                              color={nessusConfig?.configured ? "success" : "default"}
                              variant="outlined"
                              sx={{ alignSelf: "flex-start" }}
                            />
                            <Typography variant="body2" color="text.secondary">
                              {nessusConfig?.base_url || nessusValidation?.base_url || "No saved connection"}
                            </Typography>
                            {nessusConfig?.validated_at ? (
                              <Typography variant="caption" color="text.secondary">
                                Validated {nessusConfig.validated_at.replace("T", " ").replace("+00:00", " UTC")}
                              </Typography>
                            ) : null}
                            <Divider />
                            <Typography variant="subtitle2">API permissions</Typography>
                            <Stack direction="row" spacing={0.75} useFlexGap flexWrap="wrap">
                              {(nessusValidation?.api_permissions || nessusConfig?.api_permissions || []).map((item) => (
                                <Chip key={item} label={item} size="small" variant="outlined" />
                              ))}
                              {(nessusValidation?.api_permissions || nessusConfig?.api_permissions || []).length === 0 ? <Typography variant="body2" color="text.secondary">No permissions reported.</Typography> : null}
                            </Stack>
                            <Divider />
                            <Typography variant="subtitle2">Capabilities</Typography>
                            <Stack direction="row" spacing={0.75} useFlexGap flexWrap="wrap">
                              {Object.entries(nessusValidation?.capabilities || nessusConfig?.capabilities || {}).map(([key, value]) => (
                                <Chip key={key} label={key} size="small" color={value ? "success" : "default"} variant="outlined" />
                              ))}
                              {Object.keys(nessusValidation?.capabilities || nessusConfig?.capabilities || {}).length === 0 ? <Typography variant="body2" color="text.secondary">No capability probe data yet.</Typography> : null}
                            </Stack>
                            <Divider />
                            <Typography variant="subtitle2">Server info</Typography>
                            <Stack spacing={0.75}>
                              {Object.entries(nessusValidation?.server_info || nessusConfig?.server_info || {}).map(([key, value]) => (
                                <Stack key={key} direction="row" justifyContent="space-between" spacing={1}>
                                  <Typography variant="body2" color="text.secondary" sx={{ textTransform: "capitalize" }}>
                                    {key.replaceAll("_", " ")}
                                  </Typography>
                                  <Typography variant="body2">{value}</Typography>
                                </Stack>
                              ))}
                              {Object.keys(nessusValidation?.server_info || nessusConfig?.server_info || {}).length === 0 ? <Typography variant="body2" color="text.secondary">No server details loaded.</Typography> : null}
                            </Stack>
                          </Stack>
                        </Paper>

                        <Paper sx={{ p: 2.25 }}>
                          <Stack spacing={1.5}>
                            <Typography variant="h6">Reset Nessus Credentials</Typography>
                            <TextField
                              fullWidth
                              type="password"
                              label="Current password"
                              value={nessusReset.current_password}
                              onChange={(event) => setNessusReset((current) => ({ ...current, current_password: event.target.value }))}
                            />
                            <TextField
                              fullWidth
                              label="Confirmation text"
                              value={nessusReset.confirmation_text}
                              onChange={(event) => setNessusReset((current) => ({ ...current, confirmation_text: event.target.value }))}
                              helperText="RESET NESSUS CREDENTIALS"
                            />
                            <Button
                              color="error"
                              variant="outlined"
                              onClick={() => void handleNessusReset()}
                              disabled={
                                nessusResetting ||
                                !nessusReset.current_password ||
                                nessusReset.confirmation_text !== "RESET NESSUS CREDENTIALS"
                              }
                            >
                              {nessusResetting ? "Resetting..." : "Reset Credentials"}
                            </Button>
                          </Stack>
                        </Paper>
                      </Stack>
                    </Grid>
                  </Grid>
                ) : (
                  <Alert severity="info">Administrator access is required for Nessus configuration.</Alert>
                )
              ) : null}
            </Stack>
          </Grid>
        </Grid>
      </Box>

      <Snackbar open={Boolean(banner)} autoHideDuration={4500} onClose={() => setBanner(null)}>
        <Alert severity={banner?.tone || "success"} variant="filled">
          {banner?.message}
        </Alert>
      </Snackbar>
    </Box>
  );
}
