"use strict";
const rawBase = "https://raw.githubusercontent.com/manishwvn/rewardseal/main/";
const elements = Object.fromEntries(["verify", "tamper", "status", "totals", "files"].map(id => [id, document.getElementById(id)]));
let manifest = null;
let fetched = [];
const covered = /^(?:results\/(?:certificates|exposure|exposure-sample|replications|ultra|control|web-exposure|web-exposure-sample)\/[^/\\]+\.json|results\/evidence\/[^/\\]+\.(?:md|json)|results\/(?:confirmations|batch)\.json|docs\/claims\.md)$/;

function validateManifest(value) {
  if (!value || value.schema !== "rewardseal.evidence-manifest" || value.schema_version !== 1 ||
      !Array.isArray(value.files) || !value.totals || typeof value.totals !== "object") {
    throw new Error("Invalid evidence manifest");
  }
  const seen = new Set();
  for (const entry of value.files) {
    if (!entry || typeof entry.path !== "string" || !covered.test(entry.path) ||
        entry.path.split("/").some(part => part === "." || part === "..") ||
        seen.has(entry.path) || !/^[0-9a-f]{64}$/.test(entry.sha256) ||
        !Number.isSafeInteger(entry.bytes) || entry.bytes < 0) {
      throw new Error("Invalid or duplicate manifest file");
    }
    seen.add(entry.path);
  }
  return value;
}

async function readBytes(url) {
  const response = await fetch(url, {cache: "no-store", credentials: "omit", redirect: "error"});
  if (!response.ok) throw new Error("HTTP " + response.status);
  return new Uint8Array(await response.arrayBuffer());
}

async function sha256(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

function jsonOf(file) {
  if (!file.bytes) throw new Error("Missing artifact: " + file.entry.path);
  return JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(file.bytes));
}

function recomputeTotals() {
  const certs = fetched.filter(file => /^results\/certificates\/[^/]+\.json$/.test(file.entry.path)).map(jsonOf);
  let certified = 0;
  for (const cert of certs) {
    const before = cert.harden?.before, after = cert.harden?.after;
    if (!before || typeof cert.certified !== "boolean" ||
        ![before, after].every(round => round === null ||
          (round && ["error", "inconclusive", "no_attempt"].every(key => Object.hasOwn(round, key))))) {
      throw new Error("Invalid certificate counting fields");
    }
    // Match certify.score's outcome precedence: gate failure, inconclusive, no attempt, certified.
    const rounds = [before, after].filter(round => round !== null);
    if (before.gates?.ok === true && before.error === null &&
        rounds.every(round => round.error === null && round.inconclusive === null && round.no_attempt === null) &&
        cert.certified) certified += 1;
  }
  const totals = {M: 0, N_future: 0, N_fix: 0, N_full_overlap: 0, N_closed: 0, N_fix_closed: 0,
    exposure_source: "none", n: certs.length, certified};
  const primary = fetched.filter(file => /^results\/exposure\/[^/]+\.json$/.test(file.entry.path) &&
    !file.entry.path.split("/").pop().startsWith("_"));
  if (primary.length) {
    totals.exposure_source = "audit";
    const ids = new Set();
    for (const file of primary) {
      const record = jsonOf(file), scan = record.future_scan, patch = record.patch;
      if (record.schema !== "rewardseal.exposure-audit" || record.schema_version !== 1 ||
          typeof record.instance_id !== "string" || ids.has(record.instance_id) || !scan || !patch ||
          ![patch.applied, patch.gold_gate_ok, patch.empty_gate_ok, record.closed].every(v => typeof v === "boolean") ||
          !(record.future_commits_after === null ||
            (Number.isSafeInteger(record.future_commits_after) && record.future_commits_after >= 0)) ||
          ![record.future_commits_before, scan.commits_scanned, scan.gold_added_lines, scan.gold_lines_in_future]
            .every(n => Number.isSafeInteger(n) && n >= 0) ||
          scan.gold_lines_in_future > scan.gold_added_lines || scan.commits_scanned > record.future_commits_before) {
        throw new Error("Invalid exposure counting fields: " + file.entry.path);
      }
      ids.add(record.instance_id);
      const future = record.future_commits_before > 0;
      const fix = future && scan.commits_scanned > 0 &&
        scan.gold_lines_in_future >= Math.max(1, Math.ceil(0.5 * scan.gold_added_lines));
      const closed = patch.applied && patch.gold_gate_ok && patch.empty_gate_ok && record.future_commits_after === 0;
      if (fix !== record.fix_reachable || closed !== record.closed) {
        throw new Error("Inconsistent exposure flags: " + file.entry.path);
      }
      totals.M += 1;
      if (future) {
        totals.N_future += 1;
        if (closed) totals.N_closed += 1;
      }
      if (fix) {
        totals.N_fix += 1;
        if (scan.gold_lines_in_future === scan.gold_added_lines) totals.N_full_overlap += 1;
        if (closed) totals.N_fix_closed += 1;
      }
    }
  } else {
    // The report uses certificate exposure scans when no primary audit records exist.
    for (const cert of certs) {
      const before = cert.exposure_before;
      if (before && typeof before.future_git === "boolean") {
        totals.M += 1;
        if (before.future_git) totals.N_future += 1;
      }
    }
    if (totals.M) {
      totals.exposure_source = "certificates";
      // These measures are absent in certificate scans. Recompute the report's nulls, not measurements.
      for (const key of ["N_fix", "N_full_overlap", "N_closed", "N_fix_closed"]) totals[key] = null;
    }
  }
  return totals;
}

async function render(tampered = false) {
  elements.files.replaceChildren();
  let failures = 0;
  let totalsClaim = "Totals not checked.";
  for (const file of fetched) {
    const actual = file.bytes ? await sha256(file.bytes) : file.error;
    const ok = Boolean(file.bytes) && actual === file.entry.sha256 && file.bytes.length === file.entry.bytes;
    if (!ok) failures += 1;
    const row = document.createElement("tr");
    for (const value of [file.entry.path, file.entry.sha256, actual, ok ? "OK" : "FAIL"]) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.appendChild(cell);
    }
    row.lastChild.className = ok ? "ok" : "fail";
    elements.files.appendChild(row);
  }
  try {
    const totals = recomputeTotals();
    const keys = [...new Set([...Object.keys(totals), ...Object.keys(manifest.totals)])];
    const checked = keys.filter(key => Object.hasOwn(totals, key));
    const unchecked = keys.filter(key => !Object.hasOwn(totals, key));
    const lines = keys.map(key => {
      if (!Object.hasOwn(totals, key)) {
        return key + ": stored " + manifest.totals[key] + " — not recomputed in the browser";
      }
      return key + ": expected " + manifest.totals[key] + ", actual " + totals[key] +
        (totals[key] === manifest.totals[key] ? " OK" : " FAIL") +
        (totals[key] === null ? " (not measured in certificate scans)" : "");
    });
    const match = checked.every(key => Object.hasOwn(manifest.totals, key) && totals[key] === manifest.totals[key]);
    const trusted = match && failures === 0 && !tampered;
    totalsClaim = "Recomputed totals/source checked: " + checked.join(", ") + "." +
      (unchecked.length ? " Not recomputed in the browser: " + unchecked.join(", ") + "." : "");
    elements.totals.textContent = (trusted ? "Totals OK" : "Totals FAIL / untrusted") + "\n" + lines.join("\n") +
      (tampered ? "\nTamper detected: artifact integrity failed; totals cannot be trusted even if counts match." : "");
    elements.totals.className = trusted ? "ok" : "fail";
    if (!match) failures += 1;
  } catch (error) {
    elements.totals.textContent = "Totals FAIL: " + error.message;
    elements.totals.className = "fail";
    failures += 1;
  }
  elements.status.textContent = (failures ? "FAIL: " : "OK: ") + fetched.length + " artifacts checked; " +
    failures + " failed checks. " + totalsClaim + (tampered ? " Tamper demo: one byte flipped in memory only." : "");
  elements.status.className = failures ? "fail" : "ok";
}

async function verifyEvidence() {
  elements.verify.disabled = true;
  elements.tamper.disabled = true;
  manifest = null;
  fetched = [];
  elements.files.replaceChildren();
  elements.status.textContent = "Fetching manifest and evidence…";
  elements.totals.textContent = "Totals pending.";
  try {
    if (!crypto.subtle) throw new Error("Web Crypto requires HTTPS or localhost");
    manifest = validateManifest(JSON.parse(new TextDecoder().decode(
      await readBytes(new URL("manifest.json", window.location.href).href))));
    if (!manifest.files.length) throw new Error("Manifest lists no evidence files");
    fetched = await Promise.all(manifest.files.map(async entry => {
      try {
        const url = rawBase + entry.path.split("/").map(encodeURIComponent).join("/");
        return {entry, bytes: await readBytes(url)};
      } catch (error) {
        return {entry, bytes: null, error: error.message};
      }
    }));
    await render();
    elements.tamper.disabled = !fetched.some(file => file.bytes && file.bytes.length);
  } catch (error) {
    elements.status.textContent = "FAIL: " + error.message;
    elements.status.className = "fail";
    elements.totals.textContent = "Totals FAIL: verification incomplete.";
    elements.totals.className = "fail";
  } finally {
    elements.verify.disabled = false;
  }
}

async function tamperDemo() {
  // Prefer an audit record; a whitespace change still invalidates integrity and trust in totals.
  const file = fetched.find(file => /^results\/exposure\/[^_][^/]*\.json$/.test(file.entry.path) && file.bytes?.length) ||
    fetched.find(file => file.bytes?.length);
  if (!file) return;
  elements.verify.disabled = true;
  elements.tamper.disabled = true;
  try {
    file.bytes = file.bytes.slice();
    file.bytes[file.bytes.length - 1] ^= 1;
    await render(true);
  } finally {
    elements.verify.disabled = false;
  }
}

elements.verify.addEventListener("click", verifyEvidence);
elements.tamper.addEventListener("click", tamperDemo);
