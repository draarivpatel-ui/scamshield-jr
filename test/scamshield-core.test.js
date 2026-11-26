import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DETECTOR_DEFINITIONS,
  DRILLS,
  analyzeMessage,
  domainOrganizationPart,
  drillById,
  extractEmailDomain,
  gradeDrill,
  normalizeDomain,
  normalizeInput,
  normalizeLookalikeDomain,
  organizationHints,
  registrableDomain,
  sameDomainFamily,
} from '../src/scamshield-core.js';

function tactic(result, id) {
  const item = result.tactics.find((candidate) => candidate.id === id);
  assert.ok(item, `missing tactic ${id}`);
  return item;
}

function base(overrides = {}) {
  return {
    channel: 'email',
    displayName: '',
    sender: '',
    replyTo: '',
    body: '',
    attachments: [],
    ...overrides,
  };
}

test('urgency detector positive case records exact body offsets', () => {
  const result = analyzeMessage(base({ body: 'URGENT: send $850 in Apple gift cards right now.' }));
  const item = tactic(result, 'urgency-pressure');
  assert.equal(item.status, 'detected');
  assert.ok(item.severity >= 2);
  assert.deepEqual(item.matchedSpans[0], {
    field: 'body', start: 0, end: 6, text: 'URGENT', label: 'urgent warning',
  });
  const rightNow = item.matchedSpans.find((span) => span.label === 'immediate action demand');
  assert.equal(rightNow.start, 38);
  assert.equal(rightNow.end, 47);
  assert.equal(rightNow.text, 'right now');
});

test('urgency detector negative case ignores calm scheduling language', () => {
  const result = analyzeMessage(base({ body: 'No rush. Call the office when you have time this week.' }));
  const item = tactic(result, 'urgency-pressure');
  assert.equal(item.status, 'not-detected');
  assert.equal(item.severity, 0);
  assert.equal(item.matchedSpans.length, 0);
});

test('urgency detector border case gives one weak pattern severity one', () => {
  const result = analyzeMessage(base({ body: 'Please act soon when you can review the schedule.' }));
  const item = tactic(result, 'urgency-pressure');
  assert.equal(item.severity, 1);
  assert.equal(item.matchedSpans.length, 1);
  assert.equal(item.matchedSpans[0].label, 'act soon');
});

test('payment detector positive case finds gift card, wire and crypto rails', () => {
  const result = analyzeMessage(base({ body: 'Send $200 in gift cards, then wire transfer the rest or use bitcoin.' }));
  const item = tactic(result, 'payment-rail-switch');
  assert.equal(item.status, 'detected');
  assert.equal(item.severity, 3);
  const labels = new Set(item.matchedSpans.map((span) => span.label));
  assert.ok(labels.has('gift card rail'));
  assert.ok(labels.has('wire transfer rail'));
  assert.ok(labels.has('crypto rail'));
});

test('payment detector negative case ignores ordinary card acceptance', () => {
  const result = analyzeMessage(base({ body: 'The office accepts credit cards in person during normal hours.' }));
  const item = tactic(result, 'payment-rail-switch');
  assert.equal(item.status, 'not-detected');
  assert.equal(item.severity, 0);
});

test('payment detector border case treats a generic payment app mention as weak', () => {
  const result = analyzeMessage(base({ body: 'The club uses a payment app for pre-approved dues.' }));
  const item = tactic(result, 'payment-rail-switch');
  assert.equal(item.severity, 1);
  assert.equal(item.matchedSpans[0].label, 'generic payment app rail');
});

test('sender mismatch positive case compares display organization to real sender root', () => {
  const result = analyzeMessage(base({
    displayName: 'BlueCrest Bank Security',
    sender: 'security@bluecrest-verify.example.net',
    body: 'Please review this notice.',
  }));
  const item = tactic(result, 'sender-domain-mismatch');
  assert.equal(item.status, 'detected');
  assert.equal(item.severity, 3);
  assert.equal(item.matchedSpans[0].field, 'displayName');
  assert.equal(item.matchedSpans[0].start, 0);
  assert.equal(item.matchedSpans[0].text, 'BlueCrest');
  assert.equal(item.matchedSpans[1].field, 'sender');
  assert.equal(item.matchedSpans[1].text, 'bluecrest-verify.example.net');
});

test('sender mismatch negative case accepts a legitimate subdomain', () => {
  const result = analyzeMessage(base({
    displayName: 'BlueCrest Bank',
    sender: 'statements@mail.bluecrest.example',
    body: 'Your statement is ready.',
  }));
  const item = tactic(result, 'sender-domain-mismatch');
  assert.equal(item.status, 'not-detected');
  assert.equal(item.severity, 0);
});

test('sender mismatch border case ignores a personal display name without institutional words', () => {
  const result = analyzeMessage(base({
    displayName: 'Maya Patel',
    sender: 'maya@example.com',
    body: 'Dinner is at six.',
  }));
  const item = tactic(result, 'sender-domain-mismatch');
  assert.equal(item.status, 'not-detected');
  assert.equal(item.matchedSpans.length, 0);
});

test('sender mismatch catches subdomain trick domains', () => {
  const result = analyzeMessage(base({
    displayName: 'Chase Bank Security',
    sender: 'alerts@chase.com.evil.example',
    body: 'Review your account.',
  }));
  const item = tactic(result, 'sender-domain-mismatch');
  assert.equal(item.status, 'detected');
  assert.equal(item.severity, 3);
});

test('domain comparison helpers handle subdomains, suffixes and punycode-looking input', () => {
  assert.equal(extractEmailDomain('Security <alerts@mail.chase.com>'), 'mail.chase.com');
  assert.equal(registrableDomain('mail.chase.com'), 'chase.com');
  assert.equal(registrableDomain('login.example.co.uk'), 'example.co.uk');
  assert.equal(domainOrganizationPart('mail.bluecrest.example'), 'bluecrest');
  assert.equal(sameDomainFamily('mail.chase.com', 'chase.com'), true);
  assert.equal(sameDomainFamily('chase.com.evil.example', 'chase.com'), false);
  assert.equal(extractEmailDomain('xn--paypal-9we.com'), 'xn--paypal-9we.com');
  assert.equal(normalizeDomain('  MAIL.CHASE.COM. '), 'mail.chase.com');
});

test('lookalike normalization maps digits and Cyrillic letters deterministically', () => {
  const digit = normalizeLookalikeDomain('paypa1.com');
  assert.equal(digit.normalized, 'paypal.com');
  assert.deepEqual(digit.transformations[0], { index: 5, raw: '1', replacement: 'l' });
  const cyrillic = normalizeLookalikeDomain('p\u0430ypal.com');
  assert.equal(cyrillic.normalized, 'paypal.com');
  assert.equal(cyrillic.transformations[0].raw, '\u0430');
});

test('lookalike detector positive case flags digit camouflage with exact sender offsets', () => {
  const sender = 'security@paypa1.com';
  const result = analyzeMessage(base({ displayName: 'PayPal Support', sender, body: 'Review your account.' }));
  const item = tactic(result, 'lookalike-domain');
  assert.equal(item.status, 'detected');
  assert.equal(item.severity, 2);
  assert.equal(item.matchedSpans[0].start, 14);
  assert.equal(item.matchedSpans[0].end, 15);
  assert.equal(item.matchedSpans[0].text, '1');
});

test('lookalike detector positive case flags Cyrillic characters and punycode labels', () => {
  const cyrillic = analyzeMessage(base({ sender: 'security@p\u0430ypal.com', body: 'Review.' }));
  assert.equal(tactic(cyrillic, 'lookalike-domain').severity, 3);
  const punycode = analyzeMessage(base({ sender: 'security@xn--paypal-9we.com', body: 'Review.' }));
  const item = tactic(punycode, 'lookalike-domain');
  assert.equal(item.severity, 3);
  assert.ok(item.matchedSpans.some((span) => span.label === 'punycode-looking label'));
});

test('lookalike detector negative case leaves ordinary digits in non-brand domains alone', () => {
  const result = analyzeMessage(base({ sender: 'robotics@team2040.example', body: 'Meeting moved.' }));
  const item = tactic(result, 'lookalike-domain');
  assert.equal(item.status, 'not-detected');
  assert.equal(item.severity, 0);
});

test('reply-to detector positive case catches divergent roots', () => {
  const result = analyzeMessage(base({
    sender: 'statements@mail.bluecrest.example',
    replyTo: 'case-help@example.com',
    body: 'Statement ready.',
  }));
  const item = tactic(result, 'reply-to-divergence');
  assert.equal(item.status, 'detected');
  assert.equal(item.severity, 3);
  assert.equal(item.matchedSpans[1].field, 'replyTo');
  assert.equal(item.matchedSpans[1].text, 'example.com');
});

test('reply-to detector negative case accepts same-family subdomains', () => {
  const result = analyzeMessage(base({
    sender: 'statements@mail.bluecrest.example',
    replyTo: 'support@bluecrest.example',
    body: 'Statement ready.',
  }));
  const item = tactic(result, 'reply-to-divergence');
  assert.equal(item.status, 'not-detected');
});

test('reply-to detector border case ignores missing or malformed reply-to without throwing', () => {
  const missing = analyzeMessage(base({ sender: 'a@bluecrest.example', replyTo: '', body: 'Hi' }));
  assert.equal(tactic(missing, 'reply-to-divergence').status, 'not-detected');
  const malformed = analyzeMessage(base({ sender: 'a@bluecrest.example', replyTo: 'broken@', body: 'Hi' }));
  assert.equal(tactic(malformed, 'reply-to-divergence').status, 'not-detected');
  assert.ok(malformed.inputQuality.issues.some((issue) => issue.code === 'reply-to-malformed'));
});

test('attachment detector positive case catches double-extension executables', () => {
  const result = analyzeMessage(base({
    body: 'Open the attachment.',
    attachments: [{ name: 'shipping-label.pdf.exe', type: 'application/x-msdownload' }],
  }));
  const item = tactic(result, 'attachment-type');
  assert.equal(item.status, 'detected');
  assert.equal(item.severity, 3);
  assert.equal(item.matchedSpans[0].field, 'attachments[0].name');
  assert.equal(item.matchedSpans[0].text, 'exe');
  assert.equal(item.matchedSpans[0].label, 'double-extension executable');
});

test('attachment detector negative case accepts ordinary PDF and image names', () => {
  const result = analyzeMessage(base({
    body: 'Files attached.',
    attachments: [{ name: 'statement.pdf' }, { name: 'photo.png' }],
  }));
  const item = tactic(result, 'attachment-type');
  assert.equal(item.status, 'not-detected');
  assert.equal(item.severity, 0);
});

test('attachment detector border case treats archives as weak risk', () => {
  const result = analyzeMessage(base({ body: 'Archive attached.', attachments: ['records.zip'] }));
  const item = tactic(result, 'attachment-type');
  assert.equal(item.severity, 1);
  assert.equal(item.matchedSpans[0].label, 'risky .zip attachment');
});

test('credential detector positive case catches password and one-time code requests', () => {
  const body = 'Your account is locked. Verify your username and password and send the one-time code within 30 minutes or access will be suspended.';
  const result = analyzeMessage(base({ body }));
  const item = tactic(result, 'credential-request');
  assert.equal(item.status, 'detected');
  assert.equal(item.severity, 3);
  const passwordSpan = item.matchedSpans.find((span) => span.text.startsWith('Verify your username'));
  assert.equal(passwordSpan.start, 24);
  assert.equal(passwordSpan.end, 57);
  assert.ok(item.matchedSpans.some((span) => span.label === 'one-time code request'));
});

test('credential detector negative case respects a never-ask warning', () => {
  const result = analyzeMessage(base({ body: 'We will never ask for your password or one-time code. Sign in only through the app you already use.' }));
  const item = tactic(result, 'credential-request');
  assert.equal(item.status, 'not-detected');
  assert.equal(item.severity, 0);
});

test('credential detector border case treats verify-account phrasing as weak', () => {
  const result = analyzeMessage(base({ body: 'Please verify your account in the usual portal.' }));
  const item = tactic(result, 'credential-request');
  assert.equal(item.severity, 1);
  assert.equal(item.matchedSpans[0].label, 'verify account demand');
});

test('family emergency detector positive case combines relationship, secrecy and money', () => {
  const body = 'Grandma, it is Maya. I was in a car accident and I am in jail. Please do not tell Mom. Send $850 in Apple gift cards right now.';
  const result = analyzeMessage(base({ channel: 'sms', body }));
  const item = tactic(result, 'family-emergency-script');
  assert.equal(item.status, 'detected');
  assert.equal(item.severity, 3);
  assert.ok(item.matchedSpans.some((span) => span.start === 0 && span.end === 7 && span.text === 'Grandma'));
  assert.ok(item.matchedSpans.some((span) => span.start === 70 && span.end === 85));
  assert.ok(item.matchedSpans.some((span) => span.label === 'emergency money request'));
});

test('family emergency detector negative case ignores ordinary family logistics', () => {
  const result = analyzeMessage(base({ channel: 'sms', body: 'Grandma, can you call Mom when you get a chance? No rush. Dinner is Sunday.' }));
  const item = tactic(result, 'family-emergency-script');
  assert.equal(item.status, 'not-detected');
  assert.equal(item.severity, 0);
});

test('family emergency detector border case gives a single accident mention weak severity', () => {
  const result = analyzeMessage(base({ channel: 'sms', body: 'A neighbor had a small accident near the school and is fine.' }));
  const item = tactic(result, 'family-emergency-script');
  assert.equal(item.severity, 1);
});

test('scoring aggregation sums nonlinear severity contributions deterministically', () => {
  const result = analyzeMessage(base({
    displayName: 'BlueCrest Bank Security',
    sender: 'security@bluecrest-verify.example.net',
    replyTo: 'case-help@example.com',
    body: 'Your account is locked. Verify your username and password and send the one-time code within 30 minutes or access will be suspended.',
  }));
  assert.equal(tactic(result, 'urgency-pressure').contribution, 9);
  assert.equal(tactic(result, 'sender-domain-mismatch').contribution, 13);
  assert.equal(tactic(result, 'reply-to-divergence').contribution, 7);
  assert.equal(tactic(result, 'credential-request').contribution, 14);
  assert.equal(result.verdict.score, 43);
  assert.equal(result.verdict.band, 'high-pressure-pattern');
});

test('analysis never returns a binary safe verdict and always returns two unevaluated items', () => {
  const result = analyzeMessage(base({ body: 'Hello, this is a plain note with no known pattern.' }));
  assert.equal(result.unevaluated.length, 2);
  assert.equal(result.unevaluated[0].id, 'hidden-link-destination');
  assert.equal(result.unevaluated[1].id, 'live-sender-verification');
  assert.doesNotMatch(result.verdict.label.toLowerCase(), /\bsafe\b/);
  assert.doesNotMatch(result.verdict.summary.toLowerCase(), /\bsafe\b/);
  assert.match(result.verdict.residualRisk, /Residual risk remains/);
});

test('malformed input is normalized without throwing', () => {
  const result = analyzeMessage(null);
  assert.equal(result.inputQuality.status, 'malformed');
  assert.ok(result.inputQuality.issues.some((issue) => issue.code === 'input-not-object'));
  assert.ok(result.inputQuality.issues.some((issue) => issue.code === 'body-empty'));
  assert.equal(result.verdict.score, 0);
  const odd = analyzeMessage({ channel: 'carrier-pigeon', body: 'Hi', attachments: [null, { name: '' }] });
  assert.equal(odd.normalizedInput.channel, 'email');
  assert.ok(odd.inputQuality.issues.some((issue) => issue.code === 'channel-unknown'));
  assert.ok(odd.inputQuality.issues.some((issue) => issue.code === 'attachment-malformed'));
});

test('input normalization preserves string attachments and reports empty names', () => {
  const normalized = normalizeInput({ body: 'Hi', attachments: ['note.txt', { name: '' }] });
  assert.equal(normalized.attachments.length, 2);
  assert.equal(normalized.attachments[0].name, 'note.txt');
  assert.ok(normalized.issues.some((issue) => issue.code === 'attachment-name-empty'));
});

test('drill set contains six synthetic messages split into the required categories', () => {
  assert.equal(DRILLS.length, 6);
  assert.equal(DRILLS.filter((drill) => drill.category === 'scam').length, 3);
  assert.equal(DRILLS.filter((drill) => drill.category === 'legitimate-but-suspicious').length, 3);
  assert.ok(DRILLS.every((drill) => drill.input.body.length > 20));
  assert.equal(drillById('missing-id'), null);
});

test('drill grading gives a perfect score for exact selections and category', () => {
  const drill = DRILLS[0];
  const grade = gradeDrill(drill.id, drill.expectedTactics, drill.category);
  assert.equal(grade.ok, true);
  assert.equal(grade.score, 100);
  assert.equal(grade.verdict, 'excellent');
  assert.equal(grade.missed.length, 0);
  assert.equal(grade.falseAlarms.length, 0);
});

test('drill grading reports missed tactics, false alarms and wrong category', () => {
  const drill = DRILLS[0];
  const grade = gradeDrill(drill.id, ['urgency-pressure', 'attachment-type'], 'legitimate-but-suspicious');
  assert.equal(grade.ok, true);
  assert.equal(grade.categoryCorrect, false);
  assert.deepEqual(grade.missed, ['payment-rail-switch', 'family-emergency-script']);
  assert.deepEqual(grade.falseAlarms, ['attachment-type']);
  assert.ok(grade.score < 70);
});

test('drill grading handles unknown drills and unknown tactic selections', () => {
  const missing = gradeDrill('missing-id', [], 'scam');
  assert.equal(missing.ok, false);
  assert.equal(missing.score, 0);
  const drill = DRILLS[0];
  const grade = gradeDrill(drill.id, [...drill.expectedTactics, 'made-up-tactic'], drill.category);
  assert.deepEqual(grade.unknownSelections, ['made-up-tactic']);
  assert.equal(grade.score, 95);
});

test('every expected drill tactic is actually detected by the analyzer', () => {
  for (const drill of DRILLS) {
    const result = analyzeMessage(drill.input);
    const detected = new Set(result.tactics.filter((item) => item.status === 'detected').map((item) => item.id));
    for (const expected of drill.expectedTactics) assert.ok(detected.has(expected), `${drill.id} missing ${expected}`);
    if (drill.expectedTactics.length === 0) assert.equal(detected.size, 0, `${drill.id} unexpectedly detected ${[...detected].join(',')}`);
  }
});

test('analysis is deterministic across repeated runs', () => {
  const input = DRILLS[1].input;
  const first = analyzeMessage(input);
  const second = analyzeMessage(input);
  assert.deepEqual(second, first);
});

test('detector table exposes all eight required tactics', () => {
  assert.equal(DETECTOR_DEFINITIONS.length, 8);
  assert.deepEqual(DETECTOR_DEFINITIONS.map((item) => item.id), [
    'urgency-pressure',
    'payment-rail-switch',
    'sender-domain-mismatch',
    'lookalike-domain',
    'reply-to-divergence',
    'attachment-type',
    'credential-request',
    'family-emergency-script',
  ]);
});
