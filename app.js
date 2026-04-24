const STORAGE_KEY = "attackSurfaceMapper.v1";

const ASSET_TYPES = [
  "Aplicación web",
  "API",
  "Base de datos",
  "Servidor",
  "Estación de trabajo",
  "Identidad / IAM",
  "Correo corporativo",
  "Red / segmento",
  "Cloud workload",
  "SaaS",
  "Dispositivo móvil",
  "OT / IoT",
  "Tercero / proveedor",
  "Repositorio de código",
  "Backup / DRP"
];

const SAMPLE_ATTACKS = [
  { mitreId: "T1566", name: "Phishing", tactic: "Initial Access", description: "Mensajes maliciosos para obtener acceso inicial." },
  { mitreId: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access", description: "Explotación de aplicaciones expuestas públicamente." },
  { mitreId: "T1078", name: "Valid Accounts", tactic: "Defense Evasion / Persistence", description: "Uso de cuentas válidas para acceder o persistir." },
  { mitreId: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution", description: "Ejecución de comandos o scripts." },
  { mitreId: "T1087", name: "Account Discovery", tactic: "Discovery", description: "Enumeración de cuentas del entorno." },
  { mitreId: "T1021", name: "Remote Services", tactic: "Lateral Movement", description: "Movimiento lateral mediante servicios remotos." },
  { mitreId: "T1041", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration", description: "Exfiltración a través de canal de comando y control." },
  { mitreId: "T1486", name: "Data Encrypted for Impact", tactic: "Impact", description: "Cifrado de datos para afectar disponibilidad." }
];

const SAMPLE_ASSETS = [
  { name: "Portal clientes", type: "Aplicación web", criticality: 5, owner: "Canales digitales", notes: "Front público con autenticación de clientes." },
  { name: "API pagos", type: "API", criticality: 5, owner: "Plataforma", notes: "Servicios de integración para pagos." },
  { name: "Active Directory", type: "Identidad / IAM", criticality: 5, owner: "Infraestructura", notes: "Directorio e identidades corporativas." },
  { name: "Correo Microsoft 365", type: "Correo corporativo", criticality: 4, owner: "Soporte TI", notes: "Correo y colaboración." },
  { name: "Red OT planta", type: "OT / IoT", criticality: 5, owner: "Operaciones", notes: "Segmento industrial crítico." }
];

let state = loadState();

const els = {};

document.addEventListener("DOMContentLoaded", () => {
  bindElements();
  bindEvents();
  hydrateAssetTypes();
  render();
});

function defaultState() {
  const assets = SAMPLE_ASSETS.map(asset => ({ ...asset, id: uid("asset") }));
  const attacks = SAMPLE_ATTACKS.map(attack => ({ ...attack, id: uid("attack") }));

  return {
    assets,
    attacks,
    risks: {},
    thresholds: { green: 35, yellow: 70 },
    updatedAt: new Date().toISOString()
  };
}

function blankState() {
  return {
    assets: [],
    attacks: [],
    risks: {},
    thresholds: { green: 35, yellow: 70 },
    updatedAt: new Date().toISOString()
  };
}

function loadState() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) return defaultState();
    const parsed = JSON.parse(stored);
    return {
      assets: Array.isArray(parsed.assets) ? parsed.assets : [],
      attacks: Array.isArray(parsed.attacks) ? parsed.attacks : [],
      risks: parsed.risks && typeof parsed.risks === "object" ? parsed.risks : {},
      thresholds: normalizeThresholds(parsed.thresholds),
      updatedAt: parsed.updatedAt || new Date().toISOString()
    };
  } catch {
    return defaultState();
  }
}

function saveState() {
  state.updatedAt = new Date().toISOString();
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

function normalizeThresholds(thresholds = {}) {
  const green = clamp(Number(thresholds.green ?? 35), 0, 100);
  const yellow = clamp(Number(thresholds.yellow ?? 70), green, 100);
  return { green, yellow };
}

function bindElements() {
  [
    "assetForm", "assetId", "assetName", "assetType", "assetCriticality", "assetOwner", "assetNotes",
    "attackForm", "attackId", "attackName", "attackMitreId", "attackTactic", "attackDescription",
    "assetList", "attackList", "matrixWrap", "greenThreshold", "yellowThreshold", "mitreInput",
    "assetCount", "attackCount", "highRiskCount", "coverageCount", "riskDialog", "riskForm",
    "riskAssetId", "riskAttackId", "riskTitle", "riskNotApplicable", "vulnerabilityScore",
    "exposureScore", "threatScore", "impactScore", "controlScore", "vulnerabilityOut", "exposureOut",
    "threatOut", "impactOut", "controlOut", "riskPreview", "riskPreviewLabel", "vulnerabilityText",
    "exposureText", "threatText", "controlText", "impactText"
  ].forEach(id => {
    els[id] = document.getElementById(id);
  });
}

function bindEvents() {
  document.getElementById("addAssetBtn").addEventListener("click", () => showAssetForm());
  document.getElementById("cancelAssetBtn").addEventListener("click", hideAssetForm);
  document.getElementById("addAttackBtn").addEventListener("click", () => showAttackForm());
  document.getElementById("cancelAttackBtn").addEventListener("click", hideAttackForm);
  document.getElementById("saveThresholdsBtn").addEventListener("click", saveThresholds);
  document.getElementById("importMitreBtn").addEventListener("click", importMitre);
  document.getElementById("loadSampleBtn").addEventListener("click", loadSample);
  document.getElementById("loadCompletedDemoBtn").addEventListener("click", loadCompletedDemo);
  document.getElementById("resetProjectBtn").addEventListener("click", resetProject);
  document.getElementById("exportProjectBtn").addEventListener("click", exportProject);
  document.getElementById("importProjectInput").addEventListener("change", importProject);
  document.getElementById("deleteRiskBtn").addEventListener("click", deleteRisk);
  document.getElementById("closeRiskBtn").addEventListener("click", () => els.riskDialog.close());

  els.assetForm.addEventListener("submit", saveAsset);
  els.attackForm.addEventListener("submit", saveAttack);
  els.riskForm.addEventListener("submit", saveRisk);
  els.riskNotApplicable.addEventListener("change", updateRiskPreview);

  ["vulnerabilityScore", "exposureScore", "threatScore", "impactScore", "controlScore"].forEach(id => {
    els[id].addEventListener("input", updateRiskPreview);
  });
}

function hydrateAssetTypes() {
  els.assetType.innerHTML = ASSET_TYPES.map(type => `<option value="${escapeHtml(type)}">${escapeHtml(type)}</option>`).join("");
}

function render() {
  saveState();
  renderThresholds();
  renderAssets();
  renderAttacks();
  renderMetrics();
  renderMatrix();
}

function renderThresholds() {
  els.greenThreshold.value = state.thresholds.green;
  els.yellowThreshold.value = state.thresholds.yellow;
}

function renderAssets() {
  if (!state.assets.length) {
    els.assetList.innerHTML = `<p class="hint">Agrega activos para construir la matriz.</p>`;
    return;
  }

  els.assetList.innerHTML = state.assets.map(asset => `
    <article class="list-item">
      <strong>${escapeHtml(asset.name)}</strong>
      <small>${escapeHtml(asset.type)} · Criticidad ${asset.criticality}/5</small>
      <small>${escapeHtml(asset.owner || "Sin responsable")}</small>
      <div class="list-actions">
        <button type="button" data-action="edit-asset" data-id="${asset.id}">Editar</button>
        <button type="button" data-action="delete-asset" data-id="${asset.id}">Eliminar</button>
      </div>
    </article>
  `).join("");

  els.assetList.querySelectorAll("button").forEach(button => {
    button.addEventListener("click", event => {
      const { action, id } = event.currentTarget.dataset;
      if (action === "edit-asset") showAssetForm(id);
      if (action === "delete-asset") deleteAsset(id);
    });
  });
}

function renderAttacks() {
  if (!state.attacks.length) {
    els.attackList.innerHTML = `<p class="hint">Carga ataques manualmente o desde una matriz MITRE.</p>`;
    return;
  }

  els.attackList.innerHTML = state.attacks.map(attack => `
    <article class="list-item">
      <strong>${escapeHtml(attack.name)}</strong>
      <small>${escapeHtml(attack.mitreId || "Sin MITRE")} · ${escapeHtml(attack.tactic || "Sin táctica")}</small>
      <div class="list-actions">
        <button type="button" data-action="edit-attack" data-id="${attack.id}">Editar</button>
        <button type="button" data-action="delete-attack" data-id="${attack.id}">Eliminar</button>
      </div>
    </article>
  `).join("");

  els.attackList.querySelectorAll("button").forEach(button => {
    button.addEventListener("click", event => {
      const { action, id } = event.currentTarget.dataset;
      if (action === "edit-attack") showAttackForm(id);
      if (action === "delete-attack") deleteAttack(id);
    });
  });
}

function renderMetrics() {
  const totalCells = state.assets.length * state.attacks.length;
  const evaluated = Object.values(state.risks).filter(risk => risk && (risk.notApplicable || hasScore(risk))).length;
  const high = Object.values(state.risks).filter(risk => risk && !risk.notApplicable && riskCategory(risk).key === "high").length;

  els.assetCount.textContent = state.assets.length;
  els.attackCount.textContent = state.attacks.length;
  els.highRiskCount.textContent = high;
  els.coverageCount.textContent = totalCells ? `${Math.round((evaluated / totalCells) * 100)}%` : "0%";
}

function renderMatrix() {
  if (!state.assets.length || !state.attacks.length) {
    els.matrixWrap.innerHTML = `<div class="empty-state">Agrega al menos un activo y un ataque para visualizar la matriz.</div>`;
    return;
  }

  const header = `
    <thead>
      <tr>
        <th>Ataque / activo</th>
        ${state.assets.map(asset => `<th title="${escapeHtml(asset.type)}">${escapeHtml(asset.name)}</th>`).join("")}
      </tr>
    </thead>
  `;

  const body = state.attacks.map(attack => `
    <tr>
      <td class="attack-cell">
        <strong>${escapeHtml(attack.name)}</strong>
        <small>${escapeHtml([attack.mitreId, attack.tactic].filter(Boolean).join(" · "))}</small>
      </td>
      ${state.assets.map(asset => renderRiskCell(asset, attack)).join("")}
    </tr>
  `).join("");

  els.matrixWrap.innerHTML = `<table class="risk-table">${header}<tbody>${body}</tbody></table>`;
  els.matrixWrap.querySelectorAll("[data-action='open-risk']").forEach(button => {
    button.addEventListener("click", event => openRiskDialog(event.currentTarget.dataset.assetId, event.currentTarget.dataset.attackId));
  });
}

function renderRiskCell(asset, attack) {
  const risk = state.risks[riskKey(asset.id, attack.id)];
  const category = riskCategory(risk);
  const label = risk?.notApplicable ? "N/A" : hasScore(risk) ? `${calculateRisk(risk)}%` : "+";

  return `
    <td>
      <button class="risk-cell ${category.key}" data-action="open-risk" data-asset-id="${asset.id}" data-attack-id="${attack.id}" title="${escapeHtml(category.label)}">
        ${label}
      </button>
    </td>
  `;
}

function showAssetForm(id = "") {
  const asset = state.assets.find(item => item.id === id);
  els.assetId.value = asset?.id || "";
  els.assetName.value = asset?.name || "";
  els.assetType.value = asset?.type || ASSET_TYPES[0];
  els.assetCriticality.value = asset?.criticality || "3";
  els.assetOwner.value = asset?.owner || "";
  els.assetNotes.value = asset?.notes || "";
  els.assetForm.classList.remove("hidden");
  els.assetName.focus();
}

function hideAssetForm() {
  els.assetForm.reset();
  els.assetId.value = "";
  els.assetForm.classList.add("hidden");
}

function saveAsset(event) {
  event.preventDefault();
  const asset = {
    id: els.assetId.value || uid("asset"),
    name: els.assetName.value.trim(),
    type: els.assetType.value,
    criticality: Number(els.assetCriticality.value),
    owner: els.assetOwner.value.trim(),
    notes: els.assetNotes.value.trim()
  };

  if (!asset.name) return;
  state.assets = upsertById(state.assets, asset);
  hideAssetForm();
  render();
}

function deleteAsset(id) {
  if (!confirm("¿Eliminar este activo y sus evaluaciones asociadas?")) return;
  state.assets = state.assets.filter(asset => asset.id !== id);
  Object.keys(state.risks).forEach(key => {
    if (key.startsWith(`${id}::`)) delete state.risks[key];
  });
  render();
}

function showAttackForm(id = "") {
  const attack = state.attacks.find(item => item.id === id);
  els.attackId.value = attack?.id || "";
  els.attackName.value = attack?.name || "";
  els.attackMitreId.value = attack?.mitreId || "";
  els.attackTactic.value = attack?.tactic || "";
  els.attackDescription.value = attack?.description || "";
  els.attackForm.classList.remove("hidden");
  els.attackName.focus();
}

function hideAttackForm() {
  els.attackForm.reset();
  els.attackId.value = "";
  els.attackForm.classList.add("hidden");
}

function saveAttack(event) {
  event.preventDefault();
  const attack = {
    id: els.attackId.value || uid("attack"),
    name: els.attackName.value.trim(),
    mitreId: els.attackMitreId.value.trim(),
    tactic: els.attackTactic.value.trim(),
    description: els.attackDescription.value.trim()
  };

  if (!attack.name) return;
  state.attacks = upsertById(state.attacks, attack);
  hideAttackForm();
  render();
}

function deleteAttack(id) {
  if (!confirm("¿Eliminar este ataque y sus evaluaciones asociadas?")) return;
  state.attacks = state.attacks.filter(attack => attack.id !== id);
  Object.keys(state.risks).forEach(key => {
    if (key.endsWith(`::${id}`)) delete state.risks[key];
  });
  render();
}

function openRiskDialog(assetId, attackId) {
  const asset = state.assets.find(item => item.id === assetId);
  const attack = state.attacks.find(item => item.id === attackId);
  const risk = state.risks[riskKey(assetId, attackId)] || {};

  els.riskAssetId.value = assetId;
  els.riskAttackId.value = attackId;
  els.riskTitle.textContent = `${attack.name} → ${asset.name}`;
  els.riskNotApplicable.checked = Boolean(risk.notApplicable);
  els.vulnerabilityScore.value = risk.vulnerabilityScore ?? 0;
  els.exposureScore.value = risk.exposureScore ?? 0;
  els.threatScore.value = risk.threatScore ?? 0;
  els.impactScore.value = risk.impactScore ?? asset.criticality ?? 0;
  els.controlScore.value = risk.controlScore ?? 0;
  els.vulnerabilityText.value = risk.vulnerabilityText || "";
  els.exposureText.value = risk.exposureText || "";
  els.threatText.value = risk.threatText || "";
  els.controlText.value = risk.controlText || "";
  els.impactText.value = risk.impactText || "";

  updateRiskPreview();
  els.riskDialog.showModal();
}

function saveRisk(event) {
  event.preventDefault();
  const key = riskKey(els.riskAssetId.value, els.riskAttackId.value);

  state.risks[key] = {
    notApplicable: els.riskNotApplicable.checked,
    vulnerabilityScore: Number(els.vulnerabilityScore.value),
    exposureScore: Number(els.exposureScore.value),
    threatScore: Number(els.threatScore.value),
    impactScore: Number(els.impactScore.value),
    controlScore: Number(els.controlScore.value),
    vulnerabilityText: els.vulnerabilityText.value.trim(),
    exposureText: els.exposureText.value.trim(),
    threatText: els.threatText.value.trim(),
    controlText: els.controlText.value.trim(),
    impactText: els.impactText.value.trim(),
    updatedAt: new Date().toISOString()
  };

  els.riskDialog.close();
  render();
}

function deleteRisk() {
  delete state.risks[riskKey(els.riskAssetId.value, els.riskAttackId.value)];
  els.riskDialog.close();
  render();
}

function updateRiskPreview() {
  const risk = readRiskForm();
  const score = calculateRisk(risk);
  const category = riskCategory(risk);

  els.vulnerabilityOut.textContent = risk.vulnerabilityScore;
  els.exposureOut.textContent = risk.exposureScore;
  els.threatOut.textContent = risk.threatScore;
  els.impactOut.textContent = risk.impactScore;
  els.controlOut.textContent = risk.controlScore;
  els.riskPreview.textContent = risk.notApplicable ? "N/A" : `${score}%`;
  els.riskPreviewLabel.textContent = category.label;
}

function readRiskForm() {
  return {
    notApplicable: els.riskNotApplicable.checked,
    vulnerabilityScore: Number(els.vulnerabilityScore.value),
    exposureScore: Number(els.exposureScore.value),
    threatScore: Number(els.threatScore.value),
    impactScore: Number(els.impactScore.value),
    controlScore: Number(els.controlScore.value)
  };
}

function calculateRisk(risk = {}) {
  if (!risk || risk.notApplicable) return 0;
  const vulnerability = Number(risk.vulnerabilityScore || 0);
  const exposure = Number(risk.exposureScore || 0);
  const threat = Number(risk.threatScore || 0);
  const impact = Number(risk.impactScore || 0);
  const controls = Number(risk.controlScore || 0);
  const inherent = (vulnerability * 0.28) + (exposure * 0.22) + (threat * 0.22) + (impact * 0.28);
  const mitigationFactor = 1 - (controls * 0.12);
  return clamp(Math.round(inherent * 20 * mitigationFactor), 0, 100);
}

function riskCategory(risk) {
  if (!risk) return { key: "empty", label: "Sin evaluar" };
  if (risk.notApplicable) return { key: "na", label: "No aplica" };
  if (!hasScore(risk)) return { key: "empty", label: "Sin evaluar" };

  const score = calculateRisk(risk);
  if (score <= state.thresholds.green) return { key: "low", label: "Riesgo bajo" };
  if (score <= state.thresholds.yellow) return { key: "medium", label: "Riesgo medio" };
  return { key: "high", label: "Riesgo alto" };
}

function hasScore(risk = {}) {
  return ["vulnerabilityScore", "exposureScore", "threatScore", "impactScore", "controlScore"]
    .some(field => Number(risk[field] || 0) > 0);
}

function saveThresholds() {
  state.thresholds = normalizeThresholds({
    green: els.greenThreshold.value,
    yellow: els.yellowThreshold.value
  });
  render();
}

function importMitre() {
  const raw = els.mitreInput.value.trim();
  if (!raw) return;

  const imported = parseAttackInput(raw);
  if (!imported.length) {
    alert("No se detectaron ataques. Prueba con STIX, Navigator layer, CSV o una lista de técnicas.");
    return;
  }

  state.attacks = mergeAttacks(state.attacks, imported);
  els.mitreInput.value = "";
  render();
  alert(`Se importaron ${imported.length} ataques/técnicas.`);
}

function parseAttackInput(raw) {
  try {
    const parsed = JSON.parse(raw);
    const fromStix = parseStix(parsed);
    if (fromStix.length) return fromStix;
    const fromNavigator = parseNavigator(parsed);
    if (fromNavigator.length) return fromNavigator;
  } catch {
    return parseTextAttacks(raw);
  }

  return parseTextAttacks(raw);
}

function parseStix(bundle) {
  if (!Array.isArray(bundle.objects)) return [];
  return bundle.objects
    .filter(object => object.type === "attack-pattern" && !object.revoked && !object.x_mitre_deprecated)
    .map(object => {
      const mitreRef = (object.external_references || []).find(ref => ref.source_name === "mitre-attack" || ref.external_id);
      const tactics = (object.kill_chain_phases || [])
        .map(phase => titleCase(String(phase.phase_name || "").replace(/-/g, " ")))
        .filter(Boolean)
        .join(", ");

      return {
        id: uid("attack"),
        name: object.name || mitreRef?.external_id || "Técnica MITRE",
        mitreId: mitreRef?.external_id || "",
        tactic: tactics,
        description: object.description || ""
      };
    });
}

function parseNavigator(layer) {
  if (!Array.isArray(layer.techniques)) return [];
  return layer.techniques.map(item => ({
    id: uid("attack"),
    name: item.name || item.techniqueID || "Técnica MITRE",
    mitreId: item.techniqueID || "",
    tactic: item.tactic || "",
    description: item.comment || ""
  }));
}

function parseTextAttacks(raw) {
  return raw
    .split(/\n+/)
    .map(line => line.trim())
    .filter(Boolean)
    .map(line => {
      const columns = line.split(/\t|,|;/).map(part => part.trim()).filter(Boolean);
      const mitreId = columns.find(part => /^T\d{4}(?:\.\d{3})?$/i.test(part)) || "";
      const name = columns.find(part => part !== mitreId) || mitreId || line;
      const tactic = columns.find(part => part !== mitreId && part !== name) || "";

      return {
        id: uid("attack"),
        name,
        mitreId,
        tactic,
        description: ""
      };
    });
}

function mergeAttacks(existing, imported) {
  const byKey = new Map();

  existing.forEach(attack => {
    byKey.set(attackIdentity(attack), attack);
  });

  imported.forEach(attack => {
    const key = attackIdentity(attack);
    if (!byKey.has(key)) byKey.set(key, { ...attack, id: attack.id || uid("attack") });
  });

  return [...byKey.values()].sort((a, b) => String(a.mitreId || a.name).localeCompare(String(b.mitreId || b.name)));
}

function mergeAssets(existing, imported) {
  const byKey = new Map();

  existing.forEach(asset => {
    byKey.set(String(asset.name).trim().toLowerCase(), asset);
  });

  imported.forEach(asset => {
    const key = String(asset.name).trim().toLowerCase();
    if (!byKey.has(key)) byKey.set(key, asset);
  });

  return [...byKey.values()].sort((a, b) => String(a.name).localeCompare(String(b.name)));
}

function loadSample() {
  state.assets = mergeAssets(state.assets, SAMPLE_ASSETS.map(asset => ({ ...asset, id: uid("asset") })));
  state.attacks = mergeAttacks(state.attacks, SAMPLE_ATTACKS.map(attack => ({ ...attack, id: uid("attack") })));
  render();
}

function resetProject() {
  if (!confirm("¿Reiniciar todo y dejar el proyecto local en blanco? Esta acción borra los datos guardados en este navegador.")) return;
  state = blankState();
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  hideAssetForm();
  hideAttackForm();
  render();
}

function loadCompletedDemo() {
  if (!confirm("¿Cargar el demo completo? Reemplazará los datos actuales por una matriz ya evaluada.")) return;

  const assets = SAMPLE_ASSETS.map(asset => ({ ...asset, id: uid("asset") }));
  const attacks = SAMPLE_ATTACKS.map(attack => ({ ...attack, id: uid("attack") }));
  const assetByName = Object.fromEntries(assets.map(asset => [asset.name, asset]));
  const attackByMitre = Object.fromEntries(attacks.map(attack => [attack.mitreId, attack]));
  const risks = {};

  const addRisk = (assetName, mitreId, risk) => {
    const asset = assetByName[assetName];
    const attack = attackByMitre[mitreId];
    if (!asset || !attack) return;
    risks[riskKey(asset.id, attack.id)] = {
      vulnerabilityScore: risk.vulnerability ?? 0,
      exposureScore: risk.exposure ?? 0,
      threatScore: risk.threat ?? 0,
      impactScore: risk.impact ?? asset.criticality,
      controlScore: risk.controls ?? 0,
      notApplicable: Boolean(risk.notApplicable),
      vulnerabilityText: risk.notApplicable ? "" : risk.vulnerabilityText,
      exposureText: risk.notApplicable ? "" : risk.exposureText,
      threatText: risk.notApplicable ? "" : risk.threatText,
      controlText: risk.notApplicable ? "" : risk.controlText,
      impactText: risk.notApplicable ? "" : risk.impactText,
      updatedAt: new Date().toISOString()
    };
  };

  const red = {
    vulnerability: 5,
    exposure: 5,
    threat: 4,
    impact: 5,
    controls: 1,
    vulnerabilityText: "Debilidades críticas pendientes de remediación.",
    exposureText: "Activo expuesto a Internet o a múltiples redes.",
    threatText: "Técnica observada activamente en campañas recientes.",
    controlText: "Controles parciales, sin cobertura preventiva completa.",
    impactText: "Interrupción o compromiso tendría impacto operacional alto."
  };
  const yellow = {
    vulnerability: 3,
    exposure: 3,
    threat: 3,
    impact: 4,
    controls: 2,
    vulnerabilityText: "Existen brechas conocidas, pero acotadas.",
    exposureText: "Exposición limitada a usuarios, VPN o integraciones.",
    threatText: "Amenaza plausible para el tipo de activo.",
    controlText: "Controles implementados con brechas de monitoreo o hardening.",
    impactText: "Impacto relevante pero recuperable con procedimientos existentes."
  };
  const green = {
    vulnerability: 1,
    exposure: 1,
    threat: 1,
    impact: 2,
    controls: 4,
    vulnerabilityText: "Sin vulnerabilidades relevantes identificadas.",
    exposureText: "Exposición baja o fuertemente segmentada.",
    threatText: "Baja probabilidad observada en el escenario actual.",
    controlText: "Controles preventivos y detectivos maduros.",
    impactText: "Impacto bajo o localizado."
  };
  const na = { notApplicable: true };

  const matrix = {
    "Portal clientes": {
      T1566: yellow, T1190: red, T1078: red, T1059: yellow,
      T1087: yellow, T1021: green, T1041: red, T1486: yellow
    },
    "API pagos": {
      T1566: green, T1190: red, T1078: red, T1059: yellow,
      T1087: yellow, T1021: yellow, T1041: red, T1486: yellow
    },
    "Active Directory": {
      T1566: yellow, T1190: green, T1078: red, T1059: red,
      T1087: red, T1021: red, T1041: yellow, T1486: red
    },
    "Correo Microsoft 365": {
      T1566: red, T1190: green, T1078: red, T1059: yellow,
      T1087: yellow, T1021: green, T1041: yellow, T1486: green
    },
    "Red OT planta": {
      T1566: green, T1190: na, T1078: yellow, T1059: red,
      T1087: yellow, T1021: red, T1041: green, T1486: red
    }
  };

  Object.entries(matrix).forEach(([assetName, attacksByMitre]) => {
    Object.entries(attacksByMitre).forEach(([mitreId, risk]) => {
      addRisk(assetName, mitreId, risk);
    });
  });

  state = {
    assets,
    attacks,
    risks,
    thresholds: { green: 35, yellow: 70 },
    updatedAt: new Date().toISOString()
  };

  hideAssetForm();
  hideAttackForm();
  render();
}

function exportProject() {
  const blob = new Blob([JSON.stringify(state, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `attack-surface-${new Date().toISOString().slice(0, 10)}.json`;
  link.click();
  URL.revokeObjectURL(url);
}

function importProject(event) {
  const file = event.target.files?.[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = () => {
    try {
      const imported = JSON.parse(String(reader.result));
      state = {
        assets: Array.isArray(imported.assets) ? imported.assets : [],
        attacks: Array.isArray(imported.attacks) ? imported.attacks : [],
        risks: imported.risks && typeof imported.risks === "object" ? imported.risks : {},
        thresholds: normalizeThresholds(imported.thresholds),
        updatedAt: imported.updatedAt || new Date().toISOString()
      };
      render();
    } catch {
      alert("El archivo no es un proyecto JSON válido.");
    } finally {
      event.target.value = "";
    }
  };
  reader.readAsText(file);
}

function upsertById(items, item) {
  const exists = items.some(current => current.id === item.id);
  if (exists) return items.map(current => current.id === item.id ? item : current);
  return [...items, item];
}

function riskKey(assetId, attackId) {
  return `${assetId}::${attackId}`;
}

function attackIdentity(attack) {
  return String(attack.mitreId || attack.name).trim().toLowerCase();
}

function uid(prefix) {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function titleCase(value) {
  return value.replace(/\w\S*/g, word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase());
}

function escapeHtml(value = "") {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
