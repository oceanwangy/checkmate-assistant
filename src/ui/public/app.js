const ui = { state: null, cards: new Map() };

const byId = (id) => document.getElementById(id);
const node = (tag, className, text) => {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "content-type": "application/json", ...(options.headers || {}) },
  });
  const body = await response.json();
  if (!response.ok) {
    const error = new Error(body.error || "The request failed.");
    error.responseBody = body;
    throw error;
  }
  return body;
}

let toastTimer;
function toast(message, error = false) {
  const target = byId("toast");
  target.textContent = message;
  target.className = `toast show${error ? " error" : ""}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    target.className = "toast";
  }, 3500);
}

function renderProgress() {
  const { completed, total } = ui.state.progress;
  byId("progress-label").textContent = ui.state.scanning
    ? "CheckMate scan in progress"
    : !ui.state.hasReport
      ? "Ready to scan"
      : ui.state.triaged
        ? `${completed} of ${total} reviewed`
        : `AI interpreting ${ui.state.reportFindingCount} findings`;
  byId("progress-bar").style.width =
    `${total ? (completed / total) * 100 : 0}%`;
}

function renderScanLoading(profile) {
  ui.state.scanning = true;
  renderProgress();
  const page = node("section", "triage-page");
  page.append(
    node("div", "spinner", ""),
    node("h1", "", "CheckMate is scanning the tenant"),
    node(
      "p",
      "",
      `Running the read-only assessment against the ${profile} profile. This can take a few minutes.`,
    ),
  );
  byId("workspace").replaceChildren(page);
}

function renderStartPage() {
  renderProgress();
  const page = node("section", "scan-start-page");
  const content = node("div", "scan-start-content");
  content.append(
    node("div", "eyebrow", "Start a new assessment"),
    node("h1", "", "Run CheckMate"),
    node(
      "p",
      "scan-intro",
      "CheckMate reads the Auth0 tenant configuration and creates a JSON security report. AI guidance starts after the report is ready.",
    ),
  );
  const form = node("div", "scan-form");
  const label = node("label", "scan-profile-label", "Tenant profile");
  const select = document.createElement("select");
  select.className = "scan-profile";
  select.setAttribute("aria-label", "Tenant profile");
  const available = ui.state.availableProfiles || [];
  for (const profile of available) {
    const option = document.createElement("option");
    option.value = profile;
    option.textContent =
      profile === "dev" ? "Development" : "Production (scan only)";
    option.selected =
      profile ===
      (ui.state.selectedProfile ||
        (available.includes("dev") ? "dev" : available[0]));
    select.append(option);
  }
  label.append(select);
  const run = node("button", "scan-button", "Run CheckMate scan");
  run.type = "button";
  run.disabled = available.length === 0;
  run.addEventListener("click", async () => {
    const profile = select.value;
    renderScanLoading(profile);
    try {
      const result = await api("/api/scan", {
        method: "POST",
        body: JSON.stringify({ profile }),
      });
      ui.state = result.state;
      toast("CheckMate report created. Starting AI guidance.");
      await runTriage();
    } catch (error) {
      ui.state.scanning = false;
      renderStartPage();
      toast(error.message, true);
    }
  });
  form.append(label, run);
  content.append(form);
  if (!available.length) {
    content.append(
      node(
        "p",
        "scan-config-error",
        "No Auth0 profile is configured. Add the dev or production CheckMate credentials to .env, then restart the UI.",
      ),
    );
  } else {
    content.append(
      node(
        "p",
        "scan-note",
        "The scan is read-only. It does not change Auth0 settings.",
      ),
    );
  }
  if (ui.state.hasReport) {
    const cancel = node("button", "return-review-button", "Return to review");
    cancel.type = "button";
    cancel.addEventListener("click", renderPage);
    content.append(cancel);
  }
  page.append(content);
  byId("workspace").replaceChildren(page);
}

function addBulletList(parent, items) {
  const list = node("ul");
  for (const item of items) list.append(node("li", "", item));
  parent.append(list);
}

function findingForKey(key) {
  return ui.state.findings.find((finding) => finding.key === key);
}

function valueAt(source, dottedPath) {
  let current = source;
  for (const segment of dottedPath.split(".")) {
    if (!current || typeof current !== "object") return undefined;
    current = current[segment];
  }
  return current;
}

function displayValue(value) {
  if (value === null) return "Not set";
  if (Array.isArray(value)) return value.length ? value.join(", ") : "None";
  return String(value);
}

function closePlanReview() {
  byId("plan-modal-overlay")?.remove();
}

function executionSummary(parent) {
  if (!ui.state.execution) return;
  const result = node(
    "section",
    `execution-result ${ui.state.execution.status}`,
  );
  result.append(
    node(
      "h3",
      "",
      ui.state.execution.status === "succeeded"
        ? "Execution completed"
        : "Execution stopped",
    ),
  );
  if (ui.state.execution.error) {
    result.append(node("p", "", ui.state.execution.error));
  }
  for (const call of ui.state.execution.calls) {
    const row = node("div", "execution-call");
    row.append(
      node("code", "", call.endpoint),
      node(
        "span",
        `execution-status ${call.status}`,
        call.status.replaceAll("_", " "),
      ),
    );
    if (call.error) row.append(node("p", "", call.error));
    result.append(row);
  }
  parent.append(result);
}

function openPlanReview() {
  closePlanReview();
  const plan = ui.state.plan;
  if (!plan) return;
  const overlay = node("div", "modal-overlay");
  overlay.id = "plan-modal-overlay";
  const modal = node("section", "plan-modal");
  modal.setAttribute("role", "dialog");
  modal.setAttribute("aria-modal", "true");
  modal.setAttribute("aria-labelledby", "plan-modal-title");
  const header = node("header", "plan-modal-header");
  const heading = node("div");
  heading.append(
    node("div", "eyebrow", "YAML API plan"),
    node("h2", "", "Review changes before execution"),
    node(
      "p",
      "",
      `${plan.calls.length} PATCH ${plan.calls.length === 1 ? "call" : "calls"} for the ${plan.profile} profile.`,
    ),
  );
  heading.querySelector("h2").id = "plan-modal-title";
  const close = node("button", "modal-close", "×");
  close.type = "button";
  close.setAttribute("aria-label", "Close plan review");
  close.addEventListener("click", closePlanReview);
  header.append(heading, close);
  modal.append(header);

  const calls = node("div", "plan-calls");
  if (!plan.calls.length) {
    calls.append(
      node(
        "p",
        "empty-plan",
        "There are no accepted changes. No API calls will be made.",
      ),
    );
  }
  for (const call of plan.calls) {
    const card = node("article", "plan-call");
    const callTop = node("div", "plan-call-top");
    callTop.append(
      node("span", "method", call.method),
      node("code", "endpoint", call.endpoint),
    );
    card.append(callTop, node("h3", "", call.resourceName));
    const changes = node("div", "plan-changes");
    for (const precondition of call.preconditions) {
      const change = node("div", "plan-change");
      change.append(
        node("code", "", precondition.path),
        node(
          "span",
          "",
          `${displayValue(precondition.expectedValue)} → ${displayValue(valueAt(call.body, precondition.path))}`,
        ),
      );
      changes.append(change);
    }
    card.append(changes);
    if (call.bodyStrategy === "merge_live_connection_options") {
      card.append(
        node(
          "p",
          "merge-note",
          "At execution, these changes are merged into the latest full connection options so existing settings are preserved.",
        ),
      );
    } else if (call.bodyStrategy === "merge_live_nested_objects") {
      card.append(
        node(
          "p",
          "merge-note",
          "Nested settings are merged with the latest live values so unselected settings are preserved.",
        ),
      );
    }
    calls.append(card);
  }
  modal.append(calls);
  if (plan.unchangedActionIds.length) {
    modal.append(
      node(
        "p",
        "unchanged-count",
        `${plan.unchangedActionIds.length} unchanged ${plan.unchangedActionIds.length === 1 ? "item is" : "items are"} excluded from the API calls.`,
      ),
    );
  }
  executionSummary(modal);

  const footer = node("footer", "plan-modal-footer");
  const cancel = node("button", "modal-cancel", "Close");
  cancel.type = "button";
  cancel.addEventListener("click", closePlanReview);
  footer.append(cancel);
  if (ui.state.canExecute) {
    const confirmation = node("label", "execute-confirmation");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    confirmation.append(
      checkbox,
      node("span", "", "I understand this will change the dev tenant."),
    );
    const execute = node("button", "execute-button", "Execute changes");
    execute.type = "button";
    execute.disabled = true;
    checkbox.addEventListener("change", () => {
      execute.disabled = !checkbox.checked;
    });
    execute.addEventListener("click", async () => {
      checkbox.disabled = true;
      execute.disabled = true;
      execute.textContent = "Executing…";
      try {
        const result = await api("/api/execute", {
          method: "POST",
          body: JSON.stringify({ confirmed: true }),
        });
        ui.state = result.state;
        renderSubmission();
        openPlanReview();
        toast(
          result.executed
            ? "Auth0 changes executed and verified."
            : "Execution stopped. Review the result.",
          !result.executed,
        );
      } catch (error) {
        if (error.responseBody?.state) ui.state = error.responseBody.state;
        checkbox.disabled = false;
        execute.disabled = !checkbox.checked;
        execute.textContent = "Execute changes";
        toast(error.message, true);
      }
    });
    footer.append(confirmation, execute);
  } else if (plan.calls.length && ui.state.execution?.status !== "succeeded") {
    footer.append(
      node(
        "p",
        "execution-unavailable",
        "Execution is available only when the UI is started with the dev profile.",
      ),
    );
  }
  modal.append(footer);
  overlay.append(modal);
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) closePlanReview();
  });
  document.body.append(overlay);
  close.focus();
}

function renderDecisionOptions(finding) {
  const options = node("div", "decision-options");
  const accepted = finding.decision === "approved";
  const unchangedSelected = finding.decision === "accepted_risk";
  const accept = node(
    "button",
    `decision accept${accepted ? " selected" : ""}`,
    accepted ? "✓ AI suggestion accepted" : "Accept AI suggestion",
  );
  const unchanged = node(
    "button",
    `decision unchanged${unchangedSelected ? " selected" : ""}`,
    unchangedSelected ? "✓ Remains unchanged" : "Remain unchanged",
  );
  accept.type = "button";
  unchanged.type = "button";
  accept.addEventListener("click", () =>
    saveDecision(
      finding,
      "approved",
      `Accepted AI suggestion: ${finding.analysis.remediationConsiderations.join(" ")}`,
      [accept, unchanged],
    ),
  );
  unchanged.addEventListener("click", () =>
    saveDecision(
      finding,
      "accepted_risk",
      "Reviewer selected remain unchanged.",
      [accept, unchanged],
    ),
  );
  options.append(accept, unchanged);
  return options;
}

function createFindingCard(finding, index) {
  const card = node(
    "article",
    `finding-card${finding.decision ? " reviewed" : ""}`,
  );
  card.dataset.findingKey = finding.key;
  const top = node("div", "finding-top");
  top.append(node("span", "finding-number", String(index + 1)));
  if (finding.severity) {
    top.append(
      node(
        "span",
        `severity ${finding.severity.toLowerCase()}`,
        finding.severity,
      ),
    );
  }
  if (finding.decision) top.append(node("span", "saved", "Decision saved"));
  card.append(top, node("h2", "validator-title", finding.title));
  if (finding.validatorTitle && finding.validatorTitle !== finding.title) {
    card.append(node("p", "validator-context", finding.validatorTitle));
  }

  const suggestion = node("section", "suggestion");
  suggestion.append(node("h3", "", "AI-suggested changes"));
  addBulletList(suggestion, finding.analysis.remediationConsiderations);
  const reason = node("div", "reason");
  reason.append(node("strong", "", "Why this matters"));
  addBulletList(reason, finding.analysis.whyItMatters);
  suggestion.append(reason);
  const exact = node("div", "exact-changes");
  exact.append(node("strong", "", "Exact configuration changes"));
  for (const change of finding.actionableChanges) {
    const item = node("div", "exact-change");
    item.append(
      node("span", "change-resource", change.resourceName),
      node("code", "change-path", change.configPath),
      node(
        "span",
        "change-values",
        `${JSON.stringify(change.currentValue)} → ${JSON.stringify(change.targetValue)}`,
      ),
    );
    exact.append(item);
  }
  suggestion.append(exact);
  card.append(suggestion, renderDecisionOptions(finding));
  return card;
}

function replaceCard(key) {
  const finding = findingForKey(key);
  if (!finding) return;
  const index = ui.state.findings.findIndex((item) => item.key === key);
  const next = createFindingCard(finding, index);
  const current = ui.cards.get(key);
  if (current) current.replaceWith(next);
  ui.cards.set(key, next);
}

function renderSubmission() {
  const current = byId("submission");
  if (!current) return;
  const panel = node("section", "submission-panel");
  panel.id = "submission";
  if (!ui.state.submissionReady) {
    panel.hidden = true;
    current.replaceWith(panel);
    return;
  }
  if (ui.state.submitted) {
    panel.classList.add("submitted");
    panel.append(
      node("div", "submit-check", "✓"),
      node(
        "h2",
        "",
        ui.state.execution?.status === "succeeded"
          ? "Changes executed"
          : "YAML API plan created",
      ),
      node(
        "p",
        "",
        ui.state.execution?.status === "succeeded"
          ? "The accepted Auth0 changes were applied and verified against the dev tenant."
          : "Only accepted suggestions are included. Review the plan before executing any Auth0 changes.",
      ),
      node("code", "yaml-file", ui.state.yamlFile),
    );
    const review = node("button", "review-plan-button", "Review API plan");
    review.type = "button";
    review.addEventListener("click", openPlanReview);
    panel.append(review);
    current.replaceWith(panel);
    return;
  }
  panel.append(
    node("div", "eyebrow", "All decisions saved"),
    node("h2", "", "Create the API plan"),
    node(
      "p",
      "",
      "Submit your decisions to create a YAML file containing the accepted Auth0 API changes.",
    ),
  );
  const submit = node("button", "submit-button", "Submit");
  submit.type = "button";
  submit.addEventListener("click", async () => {
    submit.disabled = true;
    submit.textContent = "Creating YAML…";
    try {
      ui.state = await api("/api/submit", {
        method: "POST",
        body: "{}",
      }).then((result) => result.state);
      renderSubmission();
      openPlanReview();
      toast("YAML API plan created.");
    } catch (error) {
      submit.disabled = false;
      submit.textContent = "Submit";
      toast(error.message, true);
    }
  });
  panel.append(submit);
  current.replaceWith(panel);
}

function renderTriageLoading() {
  renderProgress();
  const page = node("section", "triage-page");
  page.append(
    node("div", "spinner", ""),
    node("h1", "", "AI is interpreting your CheckMate report"),
    node(
      "p",
      "",
      `Checking ${ui.state.reportFindingCount} findings against live tenant settings and preparing specific recommendations.`,
    ),
  );
  byId("workspace").replaceChildren(page);
}

function renderPage() {
  renderProgress();
  const workspace = byId("workspace");
  workspace.replaceChildren();
  ui.cards.clear();
  const intro = node("section", "page-intro");
  intro.append(
    node("div", "eyebrow", "AI remediation guidance"),
    node("h1", "", `${ui.state.findings.length} recommended changes`),
    node(
      "p",
      "",
      `AI interpreted ${ui.state.reportFindingCount} CheckMate findings and verified each recommendation against your tenant's current configuration.`,
    ),
  );
  const scanAgain = node("button", "scan-again-button", "Run new scan");
  scanAgain.type = "button";
  scanAgain.addEventListener("click", renderStartPage);
  intro.append(scanAgain);
  const list = node("section", "findings");
  if (!ui.state.findings.length) {
    const empty = node("article", "finding-card empty-card");
    empty.append(
      node("h2", "validator-title", "No actionable recommendations are ready"),
      node(
        "p",
        "",
        "The report needs more tenant or business context before AI can recommend a specific configuration change.",
      ),
    );
    list.append(empty);
  }
  for (const [index, finding] of ui.state.findings.entries()) {
    const card = createFindingCard(finding, index);
    ui.cards.set(finding.key, card);
    list.append(card);
  }
  const submission = node("section", "submission-panel");
  submission.id = "submission";
  workspace.append(intro, list, submission);
  renderSubmission();
}

async function runTriage() {
  renderTriageLoading();
  try {
    ui.state = await api("/api/triage", {
      method: "POST",
      body: "{}",
    });
    renderPage();
  } catch (error) {
    const page = node("section", "error-page");
    page.append(
      node("h1", "", "AI triage could not be completed"),
      node("p", "", error.message),
    );
    const retry = node("button", "decision unchanged", "Try again");
    retry.type = "button";
    retry.addEventListener("click", runTriage);
    page.append(retry);
    byId("workspace").replaceChildren(page);
  }
}

async function saveDecision(finding, status, rationale, buttons) {
  for (const button of buttons) button.disabled = true;
  try {
    ui.state = await api("/api/decision", {
      method: "POST",
      body: JSON.stringify({ findingKey: finding.key, status, rationale }),
    }).then((result) => result.state);
    renderProgress();
    replaceCard(finding.key);
    renderSubmission();
    toast("Decision saved.");
  } catch (error) {
    toast(error.message, true);
    for (const button of buttons) button.disabled = false;
  }
}

async function initialise() {
  try {
    ui.state = await api("/api/state");
    if (!ui.state.hasReport) renderStartPage();
    else if (ui.state.triaged) renderPage();
    else await runTriage();
  } catch (error) {
    const page = node("section", "error-page");
    page.append(
      node("h1", "", "Unable to load review"),
      node("p", "", error.message),
    );
    byId("workspace").replaceChildren(page);
  }
}

initialise();
