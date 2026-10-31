const walletStatus = document.querySelector("#wallet-status");
const refreshButton = document.querySelector("#refresh-wallet");
const scanForm = document.querySelector("#scan-form");
const scanButton = document.querySelector("#scan-button");
const scanError = document.querySelector("#scan-error");
const reportSection = document.querySelector("#report-section");
const reportSummary = document.querySelector("#report-summary");
const reportDigest = document.querySelector("#report-digest");
const receiptButton = document.querySelector("#receipt-button");
const receiptResult = document.querySelector("#receipt-result");
const findingsContainer = document.querySelector("#findings");
const lockfileInput = document.querySelector("#lockfile");
let activeReportDigest = "";
let walletReady = false;

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function showWalletMessage(message, className = "") {
  walletStatus.replaceChildren(element("span", className, message));
}

async function loadWalletStatus() {
  refreshButton.disabled = true;
  showWalletMessage("Checking local wallet and Devnet balance…");
  walletStatus.prepend(element("span", "spinner"));
  try {
    const response = await fetch("/api/solana/status");
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
    if (!payload.configured) {
      walletReady = false;
      showWalletMessage("Wallet not configured. Set SOLANA_KEYPAIR_PATH in your local environment.", "wallet-warning");
      receiptButton.disabled = true;
      return;
    }
    if (payload.error) {
      walletReady = false;
      showWalletMessage(`Wallet configured, but Devnet status failed: ${payload.error}`, "wallet-error");
      receiptButton.disabled = true;
      return;
    }
    walletReady = payload.balanceSol > 0;
    receiptButton.disabled = !activeReportDigest || !walletReady;
    const details = element("div", "wallet-details");
    const wallet = element("div");
    wallet.append(element("div", "wallet-label", "PUBLIC ADDRESS"));
    wallet.append(element("div", "wallet-value", payload.wallet));
    const balance = element("div");
    balance.append(element("div", "wallet-label", "DEVNET BALANCE"));
    balance.append(element("div", "balance", `${payload.balanceSol} SOL`));
    details.append(wallet, balance);
    walletStatus.replaceChildren(details);
  } catch (error) {
    showWalletMessage(error.message || "Unable to load wallet status.", "wallet-error");
  } finally {
    refreshButton.disabled = false;
  }
}

async function loadDefaultLockfile() {
  try {
    const response = await fetch("/api/config");
    const payload = await response.json();
    if (response.ok && typeof payload.defaultLockfile === "string") {
      lockfileInput.value = payload.defaultLockfile;
    }
  } catch {
    lockfileInput.value = "";
  }
}

function renderFinding(finding) {
  const card = element("article", "finding-card");
  const top = element("div", "finding-top");
  const severity = element("span", `severity severity-${finding.severity.toLowerCase()}`, finding.severity);
  top.append(severity);
  top.append(element("span", "package-name", `${finding.packageName}@${finding.packageVersion}`));
  top.append(element("span", "finding-id", finding.id));
  card.append(top);
  card.append(element("p", "finding-summary", finding.summary));
  card.append(element("div", "finding-path", `Path: ${finding.dependencyPath.join(" > ")}`));
  if (finding.explanation) {
    const explanation = element("div", "finding-explanation");
    explanation.append(element("span", "finding-explanation-label", "GEMMA 4 EXPLANATION · VERIFY AGAINST ADVISORY"));
    explanation.append(document.createTextNode(finding.explanation));
    card.append(explanation);
  }
  return card;
}

scanForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  scanError.hidden = true;
  scanError.textContent = "";
  receiptResult.textContent = "";
  scanButton.disabled = true;
  scanButton.textContent = "Scanning…";
  reportSection.hidden = true;

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        lockfile: lockfileInput.value.trim(),
        explain: document.querySelector("#explain").checked,
      }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `Scan failed (${response.status})`);
    activeReportDigest = payload.reportSha256;
    reportDigest.textContent = activeReportDigest;
    reportSummary.replaceChildren(
      element("span", "", `${payload.report.dependencyCount} dependencies checked · ${payload.report.sources.join(", ")}`),
      element("span", "report-count", `${payload.report.findings.length} findings`),
    );
    findingsContainer.replaceChildren(...payload.report.findings.map(renderFinding));
    if (payload.report.findings.length === 0) {
      findingsContainer.append(element("div", "finding-card finding-summary", "No known vulnerabilities were returned by OSV for the scanned dependency versions."));
    }
    reportSection.hidden = false;
    receiptButton.disabled = !walletReady;
  } catch (error) {
    scanError.textContent = error.message || "Scan failed.";
    scanError.hidden = false;
  } finally {
    scanButton.disabled = false;
    scanButton.textContent = "Scan lockfile ↗";
  }
});

receiptButton.addEventListener("click", async () => {
  if (!activeReportDigest) return;
  receiptButton.disabled = true;
  receiptButton.textContent = "Submitting to Devnet…";
  receiptResult.textContent = "";
  try {
    const response = await fetch("/api/solana/receipt", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ reportSha256: activeReportDigest }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `Receipt failed (${response.status})`);
    receiptResult.replaceChildren(
      document.createTextNode("Confirmed on Solana Devnet · "),
      Object.assign(element("a", "", payload.signature), {
        href: payload.explorerUrl,
        target: "_blank",
        rel: "noopener noreferrer",
      }),
    );
    receiptButton.textContent = "Receipt confirmed";
  } catch (error) {
    receiptResult.textContent = error.message || "Receipt submission failed.";
    receiptButton.disabled = false;
    receiptButton.textContent = "Submit Devnet receipt ↗";
  }
});

refreshButton.addEventListener("click", loadWalletStatus);
loadDefaultLockfile();
loadWalletStatus();
