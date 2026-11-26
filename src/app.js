import {
  DETECTOR_DEFINITIONS,
  DRILLS,
  analyzeMessage,
  drillById,
  gradeDrill,
} from './scamshield-core.js';

const LOOKALIKE_SAMPLE = {
  id: 'lookalike-payment',
  title: 'The lookalike payment request',
  input: {
    channel: 'email',
    displayName: 'PayPal Support',
    sender: 'security@paypa1.com',
    replyTo: 'security@paypa1.com',
    body: 'Urgent: verify your account within 2 hours and pay the $80 refund fee with a gift card. Do not delay.',
    attachments: [],
  },
};

const SAMPLES = [
  ...DRILLS.slice(0, 3).map((drill) => ({ id: drill.id, title: drill.title.replace(/^The /, ''), input: drill.input })),
  LOOKALIKE_SAMPLE,
  { id: 'school-pickup-change', title: 'School pickup change', input: drillById('school-pickup-change').input },
  { id: 'bank-statement-notice', title: 'Bank statement notice', input: drillById('bank-statement-notice').input },
];

const state = {
  analysis: null,
  input: null,
  mode: 'analyze',
  selectedDrillId: DRILLS[0].id,
  drillSelections: new Set(),
  drillCategory: '',
  drillGrade: null,
};

const $ = (selector) => document.querySelector(selector);

const els = {
  form: $('#analyzer-form'),
  sampleSelect: $('#sample-select'),
  channel: $('#channel'),
  displayName: $('#display-name'),
  sender: $('#sender'),
  replyTo: $('#reply-to'),
  attachments: $('#attachments'),
  body: $('#message-body'),
  clearButton: $('#clear-button'),
  verdictPanel: $('#verdict-panel'),
  scanState: $('#scan-state'),
  evidenceBook: $('#evidence-book'),
  tacticGrid: $('#tactic-grid'),
  tacticCount: $('#tactic-count'),
  modeAnalyze: $('#mode-analyze'),
  modeDrill: $('#mode-drill'),
  analyzerSection: $('#analyzer-section'),
  drillSection: $('#drill-section'),
  drillButtons: $('#drill-buttons'),
  drillCaseTitle: $('#drill-case-title'),
  drillMessage: $('#drill-message'),
  drillTactics: $('#drill-tactics'),
  categoryButtons: $('#category-buttons'),
  gradeDrillButton: $('#grade-drill'),
  resetDrillButton: $('#reset-drill'),
  gradePanel: $('#grade-panel'),
};

function el(tag, className = '', text = '') {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text) node.textContent = text;
  return node;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function truncate(value, length = 88) {
  const text = String(value).replace(/\s+/g, ' ').trim();
  return text.length > length ? `${text.slice(0, length - 1)}…` : text;
}

function populateSamples() {
  const custom = document.createElement('option');
  custom.value = 'custom';
  custom.textContent = 'Choose a sample';
  els.sampleSelect.append(custom);
  for (const sample of SAMPLES) {
    const option = document.createElement('option');
    option.value = sample.id;
    option.textContent = sample.title;
    els.sampleSelect.append(option);
  }
}

function fillForm(input) {
  els.channel.value = input.channel || 'email';
  els.displayName.value = input.displayName || '';
  els.sender.value = input.sender || '';
  els.replyTo.value = input.replyTo || '';
  els.attachments.value = (input.attachments || []).map((item) => item.name || String(item)).join(', ');
  els.body.value = input.body || '';
}

function readForm() {
  const attachments = els.attachments.value
    .split(',')
    .map((name) => name.trim())
    .filter(Boolean)
    .map((name) => ({ name, type: '' }));
  return {
    channel: els.channel.value,
    displayName: els.displayName.value,
    sender: els.sender.value,
    replyTo: els.replyTo.value,
    body: els.body.value,
    attachments,
  };
}

function loadSample(sampleId, analyze = true) {
  const sample = SAMPLES.find((item) => item.id === sampleId);
  if (!sample) return false;
  fillForm(sample.input);
  els.sampleSelect.value = sample.id;
  if (analyze) runAnalysis();
  return true;
}

function severityWord(severity) {
  return ['no match', 'weak signal', 'moderate signal', 'strong signal'][severity] || 'strong signal';
}

function renderVerdict() {
  els.verdictPanel.replaceChildren();
  if (!state.analysis) {
    const empty = el('div', 'verdict-empty');
    empty.append(el('h2', '', 'Analysis summary'));
    empty.append(el('p', '', 'Paste a synthetic message or choose a sample, then run the analyzer.'));
    els.verdictPanel.append(empty);
    return;
  }

  const { verdict, unevaluated, readAloudScript, inputQuality } = state.analysis;
  const wrap = el('div', 'verdict-content');
  wrap.append(el('h2', '', 'Analysis summary'));

  if (inputQuality.issues.length) {
    const issue = el('p', 'input-warning', `${inputQuality.issues.length} input issue${inputQuality.issues.length === 1 ? '' : 's'} normalized before scoring.`);
    wrap.append(issue);
  }

  const row = el('div', 'score-row');
  row.append(el('div', 'score-number', String(verdict.score)));
  const detail = el('div', 'score-detail');
  detail.append(el('strong', '', verdict.label));
  detail.append(el('span', '', `out of ${verdict.maxScore}`));
  row.append(detail);
  wrap.append(row);

  const meter = el('div', 'pressure-meter');
  meter.setAttribute('aria-hidden', 'true');
  const fill = el('div', 'pressure-fill');
  fill.style.setProperty('--score-width', `${verdict.score}%`);
  meter.append(fill);
  wrap.append(meter);

  wrap.append(el('p', 'verdict-summary', verdict.summary));

  const residual = el('div', 'residual-box');
  residual.append(el('h3', '', 'Still unchecked'));
  const residualList = el('ul');
  for (const item of unevaluated) {
    const li = el('li');
    li.append(el('strong', '', item.name));
    li.append(document.createTextNode(` ${item.explanation}`));
    residualList.append(li);
  }
  residual.append(residualList);
  residual.append(el('p', '', verdict.residualRisk));
  wrap.append(residual);

  const scriptBox = el('div', 'script-box');
  scriptBox.append(el('h3', '', 'Read this aloud'));
  const scriptList = el('ol');
  for (const line of readAloudScript) scriptList.append(el('li', '', line));
  scriptBox.append(scriptList);
  wrap.append(scriptBox);

  els.verdictPanel.append(wrap);
}

function annotationsByField(analysis) {
  const map = new Map();
  analysis.tactics.forEach((tactic, tacticIndex) => {
    if (tactic.status !== 'detected') return;
    for (const matched of tactic.matchedSpans) {
      if (!map.has(matched.field)) map.set(matched.field, []);
      map.get(matched.field).push({ ...matched, tacticIndex, severity: tactic.severity });
    }
  });
  return map;
}

function highlightedHtml(text, annotations) {
  if (!text) return '<span class="evidence-empty-inline">(empty)</span>';
  const valid = annotations
    .filter((item) => item.start < item.end && item.start < text.length)
    .map((item) => ({ ...item, end: Math.min(item.end, text.length) }));
  if (!valid.length) return escapeHtml(text);
  const boundaries = new Set([0, text.length]);
  for (const item of valid) {
    boundaries.add(item.start);
    boundaries.add(item.end);
  }
  const points = [...boundaries].sort((a, b) => a - b);
  let html = '';
  for (let index = 0; index < points.length - 1; index += 1) {
    const start = points[index];
    const end = points[index + 1];
    if (start === end) continue;
    const piece = text.slice(start, end);
    const active = valid.filter((item) => item.start <= start && item.end >= end);
    if (!active.length) {
      html += escapeHtml(piece);
      continue;
    }
    const severity = Math.max(...active.map((item) => item.severity));
    const starting = active.filter((item) => item.start === start);
    const keys = [...new Set(starting.map((item) => `E${item.tacticIndex + 1}`))];
    const keyHtml = keys.length ? `<sup class="evidence-key">${keys.join(' ')}</sup>` : '';
    html += `<mark class="severity-${severity}">${keyHtml}${escapeHtml(piece)}</mark>`;
  }
  return html;
}

function evidenceFields(input) {
  const fields = [
    { key: 'body', label: 'Message body', text: input.body || '' },
    { key: 'displayName', label: 'Display name', text: input.displayName || '' },
    { key: 'sender', label: 'Sender', text: input.sender || '' },
    { key: 'replyTo', label: 'Reply-to', text: input.replyTo || '' },
  ];
  for (const attachment of input.attachments || []) {
    fields.push({ key: `attachments[${attachment.index ?? 0}].name`, label: `Attachment ${Number(attachment.index ?? 0) + 1}`, text: attachment.name || '' });
  }
  return fields;
}

function renderEvidence() {
  els.evidenceBook.replaceChildren();
  els.evidenceBook.classList.remove('scanning');
  if (!state.analysis || !state.input) {
    els.evidenceBook.append(el('div', 'evidence-empty', 'Highlighted evidence will appear here after analysis.'));
    els.scanState.textContent = 'Waiting for a message';
    return;
  }
  const annotations = annotationsByField(state.analysis);
  for (const field of evidenceFields(state.input)) {
    const row = el('div', 'evidence-field');
    row.append(el('div', 'evidence-label', field.label));
    const text = el('div', 'evidence-text');
    text.innerHTML = highlightedHtml(field.text, annotations.get(field.key) || []);
    row.append(text);
    els.evidenceBook.append(row);
  }
  els.scanState.textContent = `${state.analysis.verdict.score} out of 100, still unverified`;
  requestAnimationFrame(() => els.evidenceBook.classList.add('scanning'));
}

function renderSpanList(tactic) {
  const list = el('ul', 'span-list');
  if (!tactic.matchedSpans.length) {
    const item = el('li');
    item.append(el('span', 'offset', 'no exact span '));
    item.append(document.createTextNode('This rule did not match the pasted evidence.'));
    list.append(item);
    return list;
  }
  tactic.matchedSpans.slice(0, 4).forEach((matched) => {
    const item = el('li');
    item.append(el('span', 'offset', `${matched.field} ${matched.start}-${matched.end} `));
    item.append(document.createTextNode(`"${truncate(matched.text, 74)}"`));
    list.append(item);
  });
  if (tactic.matchedSpans.length > 4) {
    const item = el('li');
    item.append(el('span', 'offset', `${tactic.matchedSpans.length - 4} more `));
    item.append(document.createTextNode('matched spans are included in the evidence notebook.'));
    list.append(item);
  }
  return list;
}

function renderTactics() {
  els.tacticGrid.replaceChildren();
  if (!state.analysis) {
    els.tacticCount.textContent = '8 detectors';
    for (const definition of DETECTOR_DEFINITIONS) {
      const card = el('article', 'tactic-card not-detected');
      const head = el('div', 'tactic-head');
      const titleWrap = el('div', 'tactic-title-wrap');
      titleWrap.append(el('span', 'tactic-index', `E${DETECTOR_DEFINITIONS.indexOf(definition) + 1}`));
      titleWrap.append(el('h3', '', definition.name));
      head.append(titleWrap);
      head.append(el('span', 'severity-pill', 'waiting'));
      card.append(head);
      card.append(el('p', '', definition.whyItWorks));
      els.tacticGrid.append(card);
    }
    return;
  }

  const detectedCount = state.analysis.tactics.filter((item) => item.status === 'detected').length;
  els.tacticCount.textContent = `${detectedCount} of 8 matched`;
  state.analysis.tactics.forEach((tactic, index) => {
    const detected = tactic.status === 'detected';
    const card = el('article', `tactic-card ${detected ? 'detected' : 'not-detected'} severity-${tactic.severity}`);
    const head = el('div', 'tactic-head');
    const titleWrap = el('div', 'tactic-title-wrap');
    titleWrap.append(el('span', 'tactic-index', `E${index + 1}`));
    titleWrap.append(el('h3', '', tactic.name));
    head.append(titleWrap);
    head.append(el('span', 'severity-pill', detected ? severityWord(tactic.severity) : 'no match'));
    card.append(head);
    card.append(renderSpanList(tactic));
    card.append(el('p', '', tactic.whyItWorks));
    card.append(el('p', 'next-step', tactic.nextStep));
    els.tacticGrid.append(card);
  });
}

function runAnalysis() {
  const input = readForm();
  state.input = input;
  state.analysis = analyzeMessage(input);
  renderVerdict();
  renderEvidence();
  renderTactics();
  return state.analysis;
}

function clearAnalysis() {
  fillForm({ channel: 'email', displayName: '', sender: '', replyTo: '', body: '', attachments: [] });
  els.sampleSelect.value = 'custom';
  state.input = null;
  state.analysis = null;
  renderVerdict();
  renderEvidence();
  renderTactics();
  els.body.focus();
}

function setMode(mode) {
  state.mode = mode;
  const drillMode = mode === 'drill';
  document.body.classList.toggle('drill-active', drillMode);
  els.modeAnalyze.setAttribute('aria-selected', String(!drillMode));
  els.modeDrill.setAttribute('aria-selected', String(drillMode));
  els.analyzerSection.hidden = drillMode;
  els.drillSection.hidden = !drillMode;
  els.form.hidden = drillMode;
  els.verdictPanel.hidden = drillMode;
  if (drillMode) renderDrill();
}

function renderDrillButtons() {
  els.drillButtons.replaceChildren();
  for (const drill of DRILLS) {
    const button = el('button', `drill-choice${drill.id === state.selectedDrillId ? ' selected' : ''}`, drill.title);
    button.type = 'button';
    button.dataset.drillId = drill.id;
    button.setAttribute('aria-pressed', String(drill.id === state.selectedDrillId));
    button.addEventListener('click', () => selectDrill(drill.id));
    els.drillButtons.append(button);
  }
}

function drillFieldRow(dl, label, value) {
  const dt = el('dt', '', label);
  const dd = el('dd', '', value || '(none)');
  dl.append(dt, dd);
}

function renderDrillMessage(drill) {
  els.drillMessage.replaceChildren();
  const dl = el('dl');
  drillFieldRow(dl, 'Channel', drill.input.channel);
  drillFieldRow(dl, 'Display name', drill.input.displayName);
  drillFieldRow(dl, 'Sender', drill.input.sender);
  drillFieldRow(dl, 'Reply-to', drill.input.replyTo);
  drillFieldRow(dl, 'Attachments', (drill.input.attachments || []).map((item) => item.name).join(', '));
  drillFieldRow(dl, 'Message', drill.input.body);
  els.drillMessage.append(dl);
}

function renderDrillTacticPicker() {
  els.drillTactics.replaceChildren();
  for (const tactic of DETECTOR_DEFINITIONS) {
    const label = el('label');
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.value = tactic.id;
    input.checked = state.drillSelections.has(tactic.id);
    input.addEventListener('change', () => {
      if (input.checked) state.drillSelections.add(tactic.id);
      else state.drillSelections.delete(tactic.id);
      state.drillGrade = null;
      renderGradePanel();
    });
    label.append(input, document.createTextNode(tactic.name));
    els.drillTactics.append(label);
  }
}

function renderCategoryButtons() {
  for (const button of els.categoryButtons.querySelectorAll('button')) {
    const selected = button.dataset.category === state.drillCategory;
    button.classList.toggle('selected', selected);
    button.setAttribute('aria-pressed', String(selected));
  }
}

function renderGradePanel() {
  els.gradePanel.replaceChildren();
  if (!state.drillGrade) {
    if (state.drillCategory) {
      els.gradePanel.append(el('p', '', 'Answers ready. Grade the read when you are finished.'));
    }
    return;
  }
  const grade = state.drillGrade;
  const drill = drillById(state.selectedDrillId);
  const result = el('div', 'grade-result');
  result.append(el('strong', 'score', `${grade.score}`));
  result.append(el('p', '', `${grade.verdict}. This drill was ${drill.category === 'scam' ? 'a scam pattern' : 'legitimate but suspicious'}.`));
  const list = el('ul');
  const correct = el('li', '', `Correct tactic marks: ${grade.correct.length ? grade.correct.join(', ') : 'none'}.`);
  const missed = el('li', '', `Missed tactics: ${grade.missed.length ? grade.missed.join(', ') : 'none'}.`);
  const falseAlarms = el('li', '', `False alarms: ${grade.falseAlarms.length ? grade.falseAlarms.join(', ') : 'none'}.`);
  list.append(correct, missed, falseAlarms);
  result.append(list);
  result.append(el('p', '', 'Even a legitimate-looking drill stays unverified until the family checks through a trusted route.'));
  els.gradePanel.append(result);
}

function renderDrill() {
  const drill = drillById(state.selectedDrillId) || DRILLS[0];
  state.selectedDrillId = drill.id;
  els.drillCaseTitle.textContent = drill.title;
  renderDrillButtons();
  renderDrillMessage(drill);
  renderDrillTacticPicker();
  renderCategoryButtons();
  renderGradePanel();
}

function selectDrill(id) {
  if (!drillById(id)) return false;
  state.selectedDrillId = id;
  state.drillSelections = new Set();
  state.drillCategory = '';
  state.drillGrade = null;
  renderDrill();
  return true;
}

function resetDrill() {
  state.drillSelections = new Set();
  state.drillCategory = '';
  state.drillGrade = null;
  renderDrill();
}

function gradeCurrentDrill() {
  if (!state.drillCategory) {
    els.gradePanel.replaceChildren(el('p', '', 'Choose scam pattern or legitimate but suspicious before grading.'));
    return null;
  }
  state.drillGrade = gradeDrill(state.selectedDrillId, [...state.drillSelections], state.drillCategory);
  renderGradePanel();
  return state.drillGrade;
}

function bindEvents() {
  els.form.addEventListener('submit', (event) => {
    event.preventDefault();
    runAnalysis();
  });
  els.sampleSelect.addEventListener('change', () => {
    if (els.sampleSelect.value !== 'custom') loadSample(els.sampleSelect.value);
  });
  els.clearButton.addEventListener('click', clearAnalysis);
  els.modeAnalyze.addEventListener('click', () => setMode('analyze'));
  els.modeDrill.addEventListener('click', () => setMode('drill'));
  for (const button of els.categoryButtons.querySelectorAll('button')) {
    button.setAttribute('aria-pressed', 'false');
    button.addEventListener('click', () => {
      state.drillCategory = button.dataset.category;
      state.drillGrade = null;
      renderCategoryButtons();
      renderGradePanel();
    });
  }
  els.gradeDrillButton.addEventListener('click', gradeCurrentDrill);
  els.resetDrillButton.addEventListener('click', resetDrill);
}

function init() {
  populateSamples();
  bindEvents();
  loadSample('bank-account-lock');
  renderDrill();
  window.__scamshield = {
    analyze: runAnalysis,
    clear: clearAnalysis,
    loadSample,
    selectDrill,
    setMode,
    gradeCurrentDrill,
    markDrillTactics(ids) {
      state.drillSelections = new Set(ids);
      renderDrillTacticPicker();
    },
    chooseDrillCategory(category) {
      state.drillCategory = category;
      state.drillGrade = null;
      renderCategoryButtons();
      renderGradePanel();
    },
    getState() {
      return {
        mode: state.mode,
        analysis: state.analysis,
        selectedDrillId: state.selectedDrillId,
        drillSelections: [...state.drillSelections],
        drillCategory: state.drillCategory,
        drillGrade: state.drillGrade,
      };
    },
  };
  window.__scamshieldReady = true;
}

init();
