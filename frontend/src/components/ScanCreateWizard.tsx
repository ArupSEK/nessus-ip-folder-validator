import React from "react";
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  FormControl,
  FormControlLabel,
  Grid,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Stack,
  Step,
  StepLabel,
  Stepper,
  Switch,
  TextField,
  Typography
} from "@mui/material";
import AddOutlinedIcon from "@mui/icons-material/AddOutlined";
import ArrowBackOutlinedIcon from "@mui/icons-material/ArrowBackOutlined";
import ArrowForwardOutlinedIcon from "@mui/icons-material/ArrowForwardOutlined";

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

type FolderOption = {
  id: string;
  name: string;
};

type TemplateOption = {
  uuid: string;
  title: string;
};

type PolicyOption = {
  id: string;
  name: string;
  has_credentials: boolean;
};

type ScannerOption = {
  id: string;
  name: string;
  status: string;
};

type MasterTemplateOption = {
  id: string;
  name: string;
  folder_name: string;
  target_count: number;
};

type ScanCreateWizardProps = {
  draft: ScanCreateDraft;
  setDraft: React.Dispatch<React.SetStateAction<ScanCreateDraft>>;
  folders: FolderOption[];
  templates: TemplateOption[];
  policies: PolicyOption[];
  scanners: ScannerOption[];
  masterTemplates: MasterTemplateOption[];
  scheduleOptions: Array<{ value: string; label: string }>;
  dependenciesLoading: boolean;
  createBusy: boolean;
  scanApiUnavailable: boolean;
  canCreate: boolean;
  onSubmit: () => void;
};

const wizardSteps = ["Basic Details", "Target Scope", "Execution", "Review"];

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

function rawTargetEntries(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function sourceSelectionValid(draft: ScanCreateDraft): boolean {
  if (draft.creation_mode === "template") {
    return Boolean(draft.template_uuid);
  }
  if (draft.creation_mode === "policy") {
    return Boolean(draft.policy_id);
  }
  return Boolean(draft.clone_from_scan_record_id);
}

function basicDetailsValid(draft: ScanCreateDraft): boolean {
  return Boolean(draft.name.trim() && draft.folder_record_id && sourceSelectionValid(draft));
}

function targetScopeValid(draft: ScanCreateDraft): boolean {
  if (draft.creation_mode === "master_template") {
    return Boolean(draft.clone_from_scan_record_id);
  }
  return parseTargetsInput(draft.targets).length > 0;
}

function executionValid(_draft: ScanCreateDraft): boolean {
  return true;
}

export default function ScanCreateWizard({
  draft,
  setDraft,
  folders,
  templates,
  policies,
  scanners,
  masterTemplates,
  scheduleOptions,
  dependenciesLoading,
  createBusy,
  scanApiUnavailable,
  canCreate,
  onSubmit
}: ScanCreateWizardProps): React.JSX.Element {
  const [activeStep, setActiveStep] = React.useState(0);

  const normalizedTargets = React.useMemo(() => parseTargetsInput(draft.targets), [draft.targets]);
  const enteredTargets = React.useMemo(() => rawTargetEntries(draft.targets), [draft.targets]);
  const duplicateTargetCount = Math.max(enteredTargets.length - normalizedTargets.length, 0);

  const selectedFolder = React.useMemo(
    () => folders.find((item) => item.id === draft.folder_record_id) ?? null,
    [draft.folder_record_id, folders]
  );
  const selectedTemplate = React.useMemo(
    () => templates.find((item) => item.uuid === draft.template_uuid) ?? null,
    [draft.template_uuid, templates]
  );
  const selectedPolicy = React.useMemo(
    () => policies.find((item) => item.id === draft.policy_id) ?? null,
    [draft.policy_id, policies]
  );
  const selectedMasterTemplate = React.useMemo(
    () => masterTemplates.find((item) => item.id === draft.clone_from_scan_record_id) ?? null,
    [draft.clone_from_scan_record_id, masterTemplates]
  );
  const selectedScanner = React.useMemo(
    () => scanners.find((item) => item.id === draft.scanner_id) ?? null,
    [draft.scanner_id, scanners]
  );
  const selectedSchedule = React.useMemo(
    () => scheduleOptions.find((item) => item.value === draft.schedule_type) ?? null,
    [draft.schedule_type, scheduleOptions]
  );

  const stepValidations = React.useMemo(
    () => [
      basicDetailsValid(draft),
      targetScopeValid(draft),
      executionValid(draft),
      basicDetailsValid(draft) && targetScopeValid(draft) && executionValid(draft)
    ],
    [draft]
  );

  const currentStepValid = stepValidations[activeStep];
  const finalStep = wizardSteps.length - 1;
  const canSubmit = canCreate && !scanApiUnavailable && stepValidations.every(Boolean);

  const sourceLabel =
    draft.creation_mode === "template" ? "Template" : draft.creation_mode === "policy" ? "Policy" : "Master Template";
  const sourceValue =
    draft.creation_mode === "template"
      ? selectedTemplate?.title || "Not selected"
      : draft.creation_mode === "policy"
        ? selectedPolicy?.name || "Not selected"
        : selectedMasterTemplate?.name || "Not selected";

  function updateDraft<K extends keyof ScanCreateDraft>(field: K, value: ScanCreateDraft[K]): void {
    setDraft((current) => ({ ...current, [field]: value }));
  }

  function handleModeChange(mode: ScanCreateDraft["creation_mode"]): void {
    setDraft((current) => ({
      ...current,
      creation_mode: mode,
      template_uuid: "",
      policy_id: "",
      clone_from_scan_record_id: "",
      targets: mode === "master_template" ? "" : current.targets
    }));
  }

  function handleNext(): void {
    if (activeStep === finalStep) {
      if (canSubmit) {
        onSubmit();
      }
      return;
    }
    if (currentStepValid) {
      setActiveStep((current) => current + 1);
    }
  }

  function handleBack(): void {
    setActiveStep((current) => Math.max(current - 1, 0));
  }

  function stepMessage(): string | null {
    if (activeStep === 0 && !basicDetailsValid(draft)) {
      return "Provide a scan name, target folder and source selection before continuing.";
    }
    if (activeStep === 1 && !targetScopeValid(draft)) {
      return draft.creation_mode === "master_template"
        ? "Select the master scan that should be cloned."
        : "Add at least one target to continue.";
    }
    return null;
  }

  return (
    <Paper sx={{ p: 2.25 }}>
      <Stack spacing={2}>
        <Stack direction="row" justifyContent="space-between" alignItems="center">
          <Box>
            <Typography variant="h6">Create Scan Wizard</Typography>
            <Typography variant="body2" color="text.secondary">
              Build a new scan from a template, policy or master scan with a guided review step.
            </Typography>
          </Box>
          {dependenciesLoading ? <CircularProgress size={18} /> : null}
        </Stack>

        {scanApiUnavailable ? (
          <Alert severity="warning">
            This Nessus scanner reports `scan_api=false`. Scan create, clone, launch, stop and delete actions are unavailable on this scanner.
          </Alert>
        ) : null}

        <Stack direction={{ xs: "column", md: "row" }} spacing={1} useFlexGap flexWrap="wrap">
          <Chip label={`Step ${activeStep + 1} of ${wizardSteps.length}`} color="primary" variant="outlined" />
          <Chip label={sourceLabel} variant="outlined" />
          {selectedFolder ? <Chip label={selectedFolder.name} variant="outlined" /> : null}
          <Chip label={draft.launch_now ? "Create and launch" : "Create only"} color={draft.launch_now ? "warning" : "default"} variant="outlined" />
        </Stack>

        <Stepper activeStep={activeStep} alternativeLabel sx={{ px: { xs: 0, md: 1 } }}>
          {wizardSteps.map((label) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>

        {stepMessage() ? <Alert severity="info">{stepMessage()}</Alert> : null}

        <Box sx={{ border: 1, borderColor: "divider", borderRadius: 2, p: 2 }}>
          {activeStep === 0 ? (
            <Stack spacing={1.5}>
              <Grid container spacing={1.5}>
                <Grid size={{ xs: 12 }}>
                  <TextField
                    fullWidth
                    label="Scan name"
                    value={draft.name}
                    onChange={(event) => updateDraft("name", event.target.value)}
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <FormControl fullWidth>
                    <InputLabel id="create-folder-label">Folder</InputLabel>
                    <Select
                      labelId="create-folder-label"
                      label="Folder"
                      value={draft.folder_record_id}
                      onChange={(event) => updateDraft("folder_record_id", event.target.value)}
                    >
                      {folders.map((folder) => (
                        <MenuItem key={folder.id} value={folder.id}>
                          {folder.name}
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <FormControl fullWidth>
                    <InputLabel id="create-mode-label">Source</InputLabel>
                    <Select
                      labelId="create-mode-label"
                      label="Source"
                      value={draft.creation_mode}
                      onChange={(event) => handleModeChange(event.target.value as ScanCreateDraft["creation_mode"])}
                    >
                      <MenuItem value="template">Template</MenuItem>
                      <MenuItem value="policy">Policy</MenuItem>
                      <MenuItem value="master_template">Master Template</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
              </Grid>

              {draft.creation_mode === "template" ? (
                <FormControl fullWidth>
                  <InputLabel id="create-template-label">Template</InputLabel>
                  <Select
                    labelId="create-template-label"
                    label="Template"
                    value={draft.template_uuid}
                    onChange={(event) => updateDraft("template_uuid", event.target.value)}
                  >
                    {templates.map((item) => (
                      <MenuItem key={item.uuid} value={item.uuid}>
                        {item.title}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              ) : null}

              {draft.creation_mode === "policy" ? (
                <FormControl fullWidth>
                  <InputLabel id="create-policy-label">Policy</InputLabel>
                  <Select
                    labelId="create-policy-label"
                    label="Policy"
                    value={draft.policy_id}
                    onChange={(event) => updateDraft("policy_id", event.target.value)}
                  >
                    {policies.map((item) => (
                      <MenuItem key={item.id} value={item.id}>
                        {item.name}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              ) : null}

              {draft.creation_mode === "master_template" ? (
                <FormControl fullWidth>
                  <InputLabel id="create-master-template-label">Master Template</InputLabel>
                  <Select
                    labelId="create-master-template-label"
                    label="Master Template"
                    value={draft.clone_from_scan_record_id}
                    onChange={(event) => updateDraft("clone_from_scan_record_id", event.target.value)}
                  >
                    {masterTemplates.map((item) => (
                      <MenuItem key={item.id} value={item.id}>
                        {item.name} ({item.folder_name || "No folder"})
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              ) : null}
            </Stack>
          ) : null}

          {activeStep === 1 ? (
            <Stack spacing={1.5}>
              {draft.creation_mode === "master_template" ? (
                <>
                  <Alert severity="info">
                    The cloned scan inherits targets and core settings from the selected master scan. Use this when you want near-identical copies.
                  </Alert>
                  <Grid container spacing={1.5}>
                    <Grid size={{ xs: 12, md: 6 }}>
                      <TextField
                        fullWidth
                        label="Selected master scan"
                        value={selectedMasterTemplate?.name || ""}
                        InputProps={{ readOnly: true }}
                      />
                    </Grid>
                    <Grid size={{ xs: 12, md: 6 }}>
                      <TextField
                        fullWidth
                        label="Existing target count"
                        value={selectedMasterTemplate ? String(selectedMasterTemplate.target_count) : ""}
                        InputProps={{ readOnly: true }}
                      />
                    </Grid>
                  </Grid>
                </>
              ) : (
                <>
                  <TextField
                    fullWidth
                    multiline
                    minRows={8}
                    label="Targets"
                    placeholder="10.0.0.1&#10;server.example.com&#10;10.0.0.0/24"
                    value={draft.targets}
                    onChange={(event) => updateDraft("targets", event.target.value)}
                  />
                  <Stack direction={{ xs: "column", md: "row" }} spacing={1} useFlexGap flexWrap="wrap">
                    <Chip label={`${normalizedTargets.length} unique targets`} color={normalizedTargets.length > 0 ? "success" : "default"} variant="outlined" />
                    <Chip label={`${enteredTargets.length} entered rows`} variant="outlined" />
                    {duplicateTargetCount > 0 ? <Chip label={`${duplicateTargetCount} duplicates removed`} color="warning" variant="outlined" /> : null}
                  </Stack>
                  <Typography variant="body2" color="text.secondary">
                    Enter one target per line or comma. Duplicate targets are collapsed before create.
                  </Typography>
                </>
              )}
            </Stack>
          ) : null}

          {activeStep === 2 ? (
            <Stack spacing={1.5}>
              <Grid container spacing={1.5}>
                <Grid size={{ xs: 12, md: 6 }}>
                  <FormControl fullWidth>
                    <InputLabel id="create-scanner-label">Scanner</InputLabel>
                    <Select
                      labelId="create-scanner-label"
                      label="Scanner"
                      value={draft.scanner_id}
                      onChange={(event) => updateDraft("scanner_id", event.target.value)}
                    >
                      <MenuItem value="">Default</MenuItem>
                      {scanners.map((item) => (
                        <MenuItem key={item.id} value={item.id}>
                          {item.name} ({item.status})
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <FormControl fullWidth disabled={draft.creation_mode === "master_template"}>
                    <InputLabel id="create-schedule-label">Schedule</InputLabel>
                    <Select
                      labelId="create-schedule-label"
                      label="Schedule"
                      value={draft.schedule_type}
                      onChange={(event) => updateDraft("schedule_type", event.target.value)}
                    >
                      {scheduleOptions.map((item) => (
                        <MenuItem key={item.value} value={item.value}>
                          {item.label}
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </Grid>
              </Grid>

              {draft.creation_mode === "policy" && selectedPolicy?.has_credentials ? (
                <Alert severity="info">The selected policy already indicates stored credentials on the Nessus side.</Alert>
              ) : null}
              {draft.creation_mode === "master_template" ? (
                <Alert severity="info">
                  Schedule and advanced scan settings stay aligned to the master scan until the cloned scan is edited later.
                </Alert>
              ) : null}

              <FormControlLabel
                control={<Switch checked={draft.launch_now} onChange={(event) => updateDraft("launch_now", event.target.checked)} />}
                label="Launch after create"
              />
            </Stack>
          ) : null}

          {activeStep === 3 ? (
            <Stack spacing={1.5}>
              <Typography variant="subtitle2">Review</Typography>
              <Grid container spacing={1.5}>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField fullWidth label="Scan name" value={draft.name} InputProps={{ readOnly: true }} />
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField fullWidth label="Folder" value={selectedFolder?.name || ""} InputProps={{ readOnly: true }} />
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField fullWidth label="Source" value={`${sourceLabel}: ${sourceValue}`} InputProps={{ readOnly: true }} />
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField fullWidth label="Scanner" value={selectedScanner?.name || "Default"} InputProps={{ readOnly: true }} />
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    label="Schedule"
                    value={draft.creation_mode === "master_template" ? "Inherited from master scan" : selectedSchedule?.label || "On demand"}
                    InputProps={{ readOnly: true }}
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    label="Launch mode"
                    value={draft.launch_now ? "Create and launch" : "Create only"}
                    InputProps={{ readOnly: true }}
                  />
                </Grid>
              </Grid>

              <Box sx={{ border: 1, borderColor: "divider", borderRadius: 2, p: 1.5 }}>
                <Typography variant="subtitle2" sx={{ mb: 1 }}>
                  Target summary
                </Typography>
                {draft.creation_mode === "master_template" ? (
                  <Typography variant="body2" color="text.secondary">
                    Targets are inherited from the selected master scan.
                  </Typography>
                ) : normalizedTargets.length === 0 ? (
                  <Typography variant="body2" color="text.secondary">
                    No targets entered.
                  </Typography>
                ) : (
                  <Stack direction={{ xs: "column", md: "row" }} spacing={1} useFlexGap flexWrap="wrap">
                    <Chip label={`${normalizedTargets.length} unique targets`} color="success" variant="outlined" />
                    {normalizedTargets.slice(0, 4).map((target) => (
                      <Chip key={target} label={target} variant="outlined" />
                    ))}
                    {normalizedTargets.length > 4 ? <Chip label={`+${normalizedTargets.length - 4} more`} variant="outlined" /> : null}
                  </Stack>
                )}
              </Box>
            </Stack>
          ) : null}
        </Box>

        <Stack direction={{ xs: "column-reverse", md: "row" }} spacing={1} justifyContent="space-between">
          <Button
            variant="text"
            startIcon={<ArrowBackOutlinedIcon />}
            onClick={handleBack}
            disabled={activeStep === 0 || createBusy}
          >
            Back
          </Button>
          <Stack direction={{ xs: "column", sm: "row" }} spacing={1}>
            {activeStep < finalStep ? (
              <Button
                variant="contained"
                endIcon={<ArrowForwardOutlinedIcon />}
                onClick={handleNext}
                disabled={!currentStepValid}
              >
                Next
              </Button>
            ) : (
              <Button
                variant="contained"
                startIcon={<AddOutlinedIcon />}
                onClick={handleNext}
                disabled={!canSubmit || createBusy}
              >
                {createBusy ? "Creating..." : draft.launch_now ? "Create and Launch" : "Create Scan"}
              </Button>
            )}
          </Stack>
        </Stack>
      </Stack>
    </Paper>
  );
}
