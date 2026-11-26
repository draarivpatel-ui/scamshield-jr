const CHANNELS = new Set(['sms', 'email', 'dm']);

const GENERIC_DISPLAY_WORDS = new Set([
  'account', 'accounts', 'alert', 'alerts', 'and', 'assistance', 'bank', 'center', 'centre',
  'company', 'corp', 'customer', 'delivery', 'department', 'help', 'inc', 'llc', 'mail',
  'notice', 'notification', 'office', 'official', 'online', 'security', 'service', 'services',
  'support', 'team', 'the',
]);

const INSTITUTION_WORDS = /\b(?:bank|credit union|school|college|university|delivery|parcel|postal|hospital|clinic|police|court|irs|treasury|utility|utilities|paypal|amazon|apple|netflix|microsoft|usps|ups|fedex|chase|wells fargo|bank of america)\b/i;

const KNOWN_BRANDS = [
  'paypal', 'amazon', 'apple', 'netflix', 'microsoft', 'usps', 'ups', 'fedex', 'chase',
  'wellsfargo', 'bankofamerica', 'bluecrest', 'parcelpost', 'riverschool',
];

const FREE_MAIL_DOMAINS = new Set([
  'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com', 'aol.com', 'proton.me',
  'protonmail.com', 'example.com', 'example.net', 'example.org',
]);

const TWO_PART_SUFFIXES = new Set([
  'ac.uk', 'co.uk', 'gov.uk', 'org.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'com.br',
  'com.mx', 'co.in', 'co.jp', 'com.sg', 'com.cn', 'com.tw', 'co.za',
]);

const LOOKALIKE_MAP = new Map(Object.entries({
  '0': 'o', '1': 'l', '3': 'e', '5': 's', '7': 't', '@': 'a',
  '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c', '\u0445': 'x', '\u0443': 'y', '\u0456': 'i', '\u0458': 'j', '\u0455': 's', '\u043a': 'k', '\u043c': 'm', '\u043d': 'n', '\u0442': 't', '\u0432': 'b',
  'α': 'a', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'τ': 't', 'κ': 'k', 'μ': 'm', 'η': 'n', 'ι': 'i', 'ε': 'e', 'χ': 'x',
  'ı': 'i', 'ł': 'l', 'ο': 'o', 'ϲ': 'c', '\u0501': 'd', 'ɡ': 'g', 'ᒥ': 'm',
}));

const DETECTOR_DEFINITIONS = [
  {
    id: 'urgency-pressure',
    name: 'Urgency pressure',
    weight: 12,
    whyItWorks: 'A deadline makes the listener feel there is no time to check with anyone. Scammers use speed to stop a careful second look.',
    nextStep: 'Pause the clock out loud. Say that real problems can wait long enough for one trusted phone call.',
  },
  {
    id: 'payment-rail-switch',
    name: 'Payment-rail switch',
    weight: 16,
    whyItWorks: 'Gift cards, wires, crypto and payment apps move money quickly and are hard to reverse. A sudden switch to one of these rails is a warning even when the story sounds familiar.',
    nextStep: 'Never buy cards, wire money, use crypto or send a payment-app transfer because a message told you to. Check with the person or organization through a trusted route.',
  },
  {
    id: 'sender-domain-mismatch',
    name: 'Sender-domain mismatch',
    weight: 13,
    whyItWorks: 'The display name is easy to fake. The actual sending domain may belong to someone else, even when the visible name looks official.',
    nextStep: 'Compare the name with the domain after the at sign. If they do not belong together, contact the organization through an address or number you already trust.',
  },
  {
    id: 'lookalike-domain',
    name: 'Lookalike characters in the domain',
    weight: 12,
    whyItWorks: 'One substituted letter, digit or foreign character can make a fake domain look almost right when read quickly.',
    nextStep: 'Read the domain character by character. Do not trust a domain only because it looks close at a glance.',
  },
  {
    id: 'reply-to-divergence',
    name: 'Reply-to divergence',
    weight: 9,
    whyItWorks: 'A message can appear to come from one place while sending replies somewhere else. That moves the conversation to the attacker.',
    nextStep: 'Check whether the reply address belongs to the same organization as the sender. If not, do not reply to either address.',
  },
  {
    id: 'attachment-type',
    name: 'Attachment type',
    weight: 10,
    whyItWorks: 'A file that looks like a document can carry a program or macro. The attachment name is chosen to make curiosity or worry do the opening.',
    nextStep: 'Do not open unexpected attachments. Ask the sender through a separate trusted channel whether they really sent the file.',
  },
  {
    id: 'credential-request',
    name: 'Credential-request phrasing',
    weight: 14,
    whyItWorks: 'Passwords and one-time codes are the keys to an account. A request for them can turn a small mistake into a full account takeover.',
    nextStep: 'Never type, read aloud or send a password, one-time code or full identity number because a message requested it.',
  },
  {
    id: 'family-emergency-script',
    name: 'Family emergency script',
    weight: 14,
    whyItWorks: 'A family emergency makes helping feel urgent and private. Secrecy keeps the target away from the people who could spot the trick.',
    nextStep: 'Call the family member at a number you already know, then call another relative. Secrecy plus money is a stop sign.',
  },
];

const UNEVALUATED = [
  {
    id: 'hidden-link-destination',
    name: 'Hidden link destination',
    explanation: 'This offline prototype does not open links or follow redirects, so it cannot tell where a shortened link, button or QR code really leads.',
  },
  {
    id: 'live-sender-verification',
    name: 'Live sender verification',
    explanation: 'This offline prototype cannot call, message or authenticate the sender, so it cannot prove that a person or account is genuine or uncompromised.',
  },
];

function asString(value) {
  if (typeof value === 'string') return value;
  if (value == null) return '';
  try {
    return String(value);
  } catch {
    return '';
  }
}

function clampSeverity(value) {
  return Math.max(0, Math.min(3, Math.round(value)));
}

function normalizeDomain(domain) {
  return asString(domain).trim().toLowerCase().replace(/^[.]+|[.]+$/g, '');
}

function extractEmailDomain(value) {
  let text = asString(value).trim();
  if (!text) return null;
  const angle = text.match(/<([^<>]+)>/);
  if (angle) text = angle[1].trim();
  text = text.replace(/^mailto:/i, '').trim();
  if (text.includes('@')) {
    const parts = text.split('@');
    text = parts[parts.length - 1].trim();
  }
  text = text.replace(/[;,>]+$/g, '').trim();
  text = normalizeDomain(text);
  if (!text || /\s/.test(text) || text.includes('@') || !text.includes('.')) return null;
  if (!/^(?:[^\s.]+\.)+[^\s.]+$/.test(text)) return null;
  return text;
}

function registrableDomain(domain) {
  const normalized = normalizeDomain(domain);
  if (!normalized) return '';
  const labels = normalized.split('.').filter(Boolean);
  if (labels.length <= 2) return normalized;
  const lastTwo = labels.slice(-2).join('.');
  if (TWO_PART_SUFFIXES.has(lastTwo) && labels.length >= 3) return labels.slice(-3).join('.');
  return lastTwo;
}

function sameDomainFamily(a, b) {
  const left = registrableDomain(a);
  const right = registrableDomain(b);
  return Boolean(left && right && left === right);
}

function domainOrganizationPart(domain) {
  const normalized = normalizeDomain(domain);
  const labels = normalized.split('.').filter(Boolean);
  if (labels.length < 2) return normalized;
  const lastTwo = labels.slice(-2).join('.');
  if (TWO_PART_SUFFIXES.has(lastTwo) && labels.length >= 3) return labels[labels.length - 3];
  return labels[labels.length - 2];
}

function normalizeLookalikeDomain(domain) {
  const raw = normalizeDomain(domain);
  let normalized = '';
  const transformations = [];
  for (let index = 0; index < raw.length; index += 1) {
    const char = raw[index];
    const lower = char.toLowerCase();
    const replacement = LOOKALIKE_MAP.get(lower);
    if (replacement) {
      normalized += replacement;
      transformations.push({ index, raw: char, replacement });
    } else {
      normalized += lower;
    }
  }
  return { raw, normalized, transformations };
}

function span(field, source, start, end, label) {
  const safeStart = Math.max(0, Math.min(source.length, start));
  const safeEnd = Math.max(safeStart, Math.min(source.length, end));
  return {
    field,
    start: safeStart,
    end: safeEnd,
    text: source.slice(safeStart, safeEnd),
    label,
  };
}

function findCaseInsensitive(source, needle) {
  return asString(source).toLowerCase().indexOf(asString(needle).toLowerCase());
}

function collectRegexSpans(field, source, entries) {
  const spans = [];
  const seen = new Set();
  for (const entry of entries) {
    const regex = new RegExp(entry.pattern.source, entry.pattern.flags.includes('g') ? entry.pattern.flags : `${entry.pattern.flags}g`);
    let match;
    while ((match = regex.exec(source)) !== null) {
      if (match[0].length === 0) {
        regex.lastIndex += 1;
        continue;
      }
      const key = `${match.index}:${match.index + match[0].length}:${entry.label}`;
      if (!seen.has(key)) {
        seen.add(key);
        spans.push({ ...span(field, source, match.index, match.index + match[0].length, entry.label), strength: entry.strength || 1 });
      }
    }
  }
  return spans.sort((a, b) => a.start - b.start || a.end - b.end);
}

function countDistinctLabels(spans) {
  return new Set(spans.map((item) => item.label)).size;
}

function normalizeInput(rawInput) {
  const issues = [];
  let source = rawInput;
  if (!source || typeof source !== 'object' || Array.isArray(source)) {
    issues.push({ code: 'input-not-object', message: 'Input was missing or not an object, so the engine used empty fields.' });
    source = {};
  }
  const channel = asString(source.channel).trim().toLowerCase() || 'email';
  if (!CHANNELS.has(channel)) {
    issues.push({ code: 'channel-unknown', message: `Channel "${channel}" is not one of sms, email or dm; it was treated as email.` });
  }
  const body = asString(source.body);
  if (!body.trim()) issues.push({ code: 'body-empty', message: 'The message body is empty.' });
  const displayName = asString(source.displayName);
  const sender = asString(source.sender);
  const replyTo = asString(source.replyTo);
  if (sender && !extractEmailDomain(sender) && /@/.test(sender)) {
    issues.push({ code: 'sender-domain-malformed', message: 'The sender address has an at sign but no readable domain.' });
  }
  if (replyTo && !extractEmailDomain(replyTo) && /@/.test(replyTo)) {
    issues.push({ code: 'reply-to-malformed', message: 'The reply-to address has an at sign but no readable domain.' });
  }
  const rawAttachments = source.attachments == null ? [] : source.attachments;
  const list = Array.isArray(rawAttachments) ? rawAttachments : [rawAttachments];
  const attachments = [];
  list.forEach((item, index) => {
    if (typeof item === 'string') {
      attachments.push({ name: item, type: '', index });
    } else if (item && typeof item === 'object') {
      attachments.push({ name: asString(item.name), type: asString(item.type), index });
    } else {
      issues.push({ code: 'attachment-malformed', message: `Attachment ${index + 1} could not be read.` });
    }
  });
  attachments.forEach((item) => {
    if (!item.name.trim()) issues.push({ code: 'attachment-name-empty', message: `Attachment ${item.index + 1} has no file name.` });
  });
  return {
    channel: CHANNELS.has(channel) ? channel : 'email',
    displayName,
    sender,
    replyTo,
    body,
    attachments,
    issues,
    malformed: issues.length > 0,
  };
}

const URGENCY_PATTERNS = [
  { label: 'urgent warning', pattern: /\burgent\b/giu, strength: 2 },
  { label: 'immediate action demand', pattern: /\b(?:immediately|right now|asap|as soon as possible)\b/giu, strength: 2 },
  { label: 'short countdown', pattern: /\bwithin\s+(?:\d+|one|two|three|four|five|six|seven|eight|nine|ten|a|an)\s+(?:minutes?|hours?|days?)\b/giu, strength: 2 },
  { label: 'final notice', pattern: /\bfinal\s+(?:notice|warning|chance)\b/giu, strength: 2 },
  { label: 'expiration pressure', pattern: /\bexpires?\s+(?:today|tonight|soon)\b/giu, strength: 2 },
  { label: 'account threat', pattern: /\baccount\s+(?:will be|is|has been|was)?\s*(?:locked|suspended|closed|frozen)\b/giu, strength: 2 },
  { label: 'do not delay', pattern: /\bdo(?:es)?\s*not\s+delay\b|\bdon'?t\s+delay\b/giu, strength: 2 },
  { label: 'act soon', pattern: /\b(?:act|respond|reply|call)\s+soon\b/giu, strength: 1 },
  { label: 'emergency framing', pattern: /\bemergency\b/giu, strength: 1 },
];

function detectUrgency(input) {
  const matches = collectRegexSpans('body', input.body, URGENCY_PATTERNS);
  const strong = new Set(matches.filter((item) => item.strength === 2).map((item) => item.label)).size;
  const weak = new Set(matches.filter((item) => item.strength === 1).map((item) => item.label)).size;
  let severity = 0;
  if (strong >= 3 || strong + weak >= 4) severity = 3;
  else if (strong + weak >= 2) severity = 2;
  else if (strong + weak === 1) severity = 1;
  return { severity, matchedSpans: matches.map(({ strength, ...item }) => item) };
}

const PAYMENT_PATTERNS = [
  { label: 'gift card rail', pattern: /\b(?:gift\s+cards?|apple\s+(?:gift\s+)?cards?|itunes\s+cards?|google\s+play\s+cards?|steam\s+cards?)\b/giu, strength: 2 },
  { label: 'wire transfer rail', pattern: /\b(?:wire\s+(?:transfer|money)|western\s+union|moneygram)\b/giu, strength: 2 },
  { label: 'crypto rail', pattern: /\b(?:crypto(?:currency)?|bitcoin|btc\b|usdt|ethereum|bitcoin\s+atm)\b/giu, strength: 2 },
  { label: 'payment app rail', pattern: /\b(?:cash\s*app|venmo|zelle|paypal\s+friends\s+(?:and|&)\s+family)\b/giu, strength: 2 },
  { label: 'generic payment app rail', pattern: /\bpayment\s+app\b/giu, strength: 1 },
  { label: 'scan-to-pay rail', pattern: /\b(?:scan\s+(?:this\s+)?qr\s+code|qr\s+code\s+to\s+pay)\b/giu, strength: 1 },
];

function detectPaymentRail(input) {
  const matches = collectRegexSpans('body', input.body, PAYMENT_PATTERNS);
  const specific = new Set(matches.filter((item) => item.strength === 2).map((item) => item.label)).size;
  const generic = new Set(matches.filter((item) => item.strength === 1).map((item) => item.label)).size;
  const hasAmount = /(?:[$€£]\s?\d|\b\d+(?:\.\d{2})?\s?(?:dollars|usd|euros?)\b)/iu.test(input.body);
  let severity = 0;
  if (specific >= 2 || (specific >= 1 && hasAmount)) severity = 3;
  else if (specific === 1) severity = 2;
  else if (generic >= 1) severity = 1;
  return { severity, matchedSpans: matches.map(({ strength, ...item }) => item) };
}

function tokenizeDisplayName(displayName) {
  return asString(displayName)
    .toLowerCase()
    .replace(/wells\s+fargo/g, ' wellsfargo ')
    .replace(/bank\s+of\s+america/g, ' bankofamerica ')
    .match(/[a-z0-9]+/g) || [];
}

function organizationHints(displayName) {
  const text = asString(displayName);
  if (!text.trim() || !INSTITUTION_WORDS.test(text)) return [];
  const compactKnown = KNOWN_BRANDS.filter((brand) => text.toLowerCase().replace(/[^a-z0-9]/g, '').includes(brand));
  const tokens = tokenizeDisplayName(text)
    .filter((token) => token.length >= 3)
    .filter((token) => !GENERIC_DISPLAY_WORDS.has(token))
    .filter((token) => !/^\d+$/.test(token));
  return [...new Set([...compactKnown, ...tokens])];
}

function displayHintSpan(input, hint) {
  const start = findCaseInsensitive(input.displayName, hint);
  if (start >= 0) return span('displayName', input.displayName, start, start + hint.length, 'organization display name');
  const loose = hint.replace(/([a-z])([A-Z])/g, '$1 $2');
  const looseStart = findCaseInsensitive(input.displayName, loose);
  if (looseStart >= 0) return span('displayName', input.displayName, looseStart, looseStart + loose.length, 'organization display name');
  return span('displayName', input.displayName, 0, Math.min(input.displayName.length, Math.max(1, hint.length)), 'organization display name');
}

function senderDomainSpan(input, domain, label = 'sender domain') {
  const start = findCaseInsensitive(input.sender, domain);
  if (start >= 0) return span('sender', input.sender, start, start + domain.length, label);
  return span('sender', input.sender, 0, input.sender.length, label);
}

function detectSenderMismatch(input) {
  const senderDomain = extractEmailDomain(input.sender);
  const hints = organizationHints(input.displayName);
  if (!senderDomain || hints.length === 0) return { severity: 0, matchedSpans: [] };
  const root = registrableDomain(senderDomain);
  const organizationPart = domainOrganizationPart(root).replace(/[^a-z0-9]/g, '');
  const matched = hints.some((hint) => organizationPart.includes(hint));
  if (matched) return { severity: 0, matchedSpans: [] };
  const displaySpan = displayHintSpan(input, hints[0]);
  const domainSpan = senderDomainSpan(input, senderDomain);
  const severity = FREE_MAIL_DOMAINS.has(root) || KNOWN_BRANDS.includes(hints[0]) ? 3 : 2;
  return { severity, matchedSpans: [displaySpan, domainSpan] };
}

function detectLookalikeDomain(input) {
  const domain = extractEmailDomain(input.sender);
  if (!domain) return { severity: 0, matchedSpans: [] };
  const normalizedResult = normalizeLookalikeDomain(domain);
  const labels = domain.split('.');
  const punycodeOffsets = [];
  let cursor = 0;
  for (const label of labels) {
    if (label.toLowerCase().startsWith('xn--')) punycodeOffsets.push({ start: cursor, end: cursor + label.length, label });
    cursor += label.length + 1;
  }
  const hasPunycode = punycodeOffsets.length > 0;
  const homoglyphs = normalizedResult.transformations.filter((item) => item.raw.charCodeAt(0) > 127);
  const compactRaw = normalizedResult.raw.replace(/[^a-z0-9]/g, '');
  const compactNormalized = normalizedResult.normalized.replace(/[^a-z0-9]/g, '');
  const brandCamouflage = KNOWN_BRANDS.find((brand) => compactNormalized.includes(brand) && !compactRaw.includes(brand));
  let severity = 0;
  if (hasPunycode || homoglyphs.length > 0) severity = 3;
  else if (brandCamouflage) severity = 2;
  if (!severity) return { severity, matchedSpans: [] };
  const domainStart = findCaseInsensitive(input.sender, domain);
  const base = domainStart >= 0 ? domainStart : 0;
  const spans = [];
  for (const item of normalizedResult.transformations) {
    spans.push(span('sender', input.sender, base + item.index, base + item.index + item.raw.length, `lookalike ${item.raw} read as ${item.replacement}`));
  }
  for (const item of punycodeOffsets) {
    spans.push(span('sender', input.sender, base + item.start, base + item.end, 'punycode-looking label'));
  }
  if (spans.length === 0) spans.push(senderDomainSpan(input, domain, 'lookalike domain'));
  return { severity, matchedSpans: spans.sort((a, b) => a.start - b.start || a.end - b.end) };
}

function detectReplyToDivergence(input) {
  const senderDomain = extractEmailDomain(input.sender);
  const replyDomain = extractEmailDomain(input.replyTo);
  if (!senderDomain || !replyDomain || sameDomainFamily(senderDomain, replyDomain)) return { severity: 0, matchedSpans: [] };
  const replyStart = findCaseInsensitive(input.replyTo, replyDomain);
  const senderRoot = registrableDomain(senderDomain);
  const replyRoot = registrableDomain(replyDomain);
  const severity = FREE_MAIL_DOMAINS.has(replyRoot) && !FREE_MAIL_DOMAINS.has(senderRoot) ? 3 : 2;
  return {
    severity,
    matchedSpans: [
      senderDomainSpan(input, senderDomain, 'sender domain'),
      span('replyTo', input.replyTo, Math.max(0, replyStart), Math.max(0, replyStart) + replyDomain.length, 'reply-to domain'),
    ],
  };
}

const ATTACHMENT_LEVELS = new Map([
  ['exe', 3], ['scr', 3], ['apk', 3], ['bat', 3], ['cmd', 3], ['com', 3], ['pif', 3], ['msi', 3], ['ps1', 3], ['vbs', 3], ['jar', 3], ['js', 3], ['hta', 3], ['iso', 3], ['dmg', 3],
  ['docm', 2], ['xlsm', 2], ['pptm', 2], ['htm', 2], ['html', 2], ['svg', 2],
  ['zip', 1], ['rar', 1], ['7z', 1], ['gz', 1],
]);

function extensionOf(name) {
  const clean = asString(name).trim().toLowerCase();
  const parts = clean.split('.').filter(Boolean);
  if (parts.length < 2) return { extension: '', doubleExtension: false, parts };
  const extension = parts[parts.length - 1];
  const doubleExtension = parts.length >= 3 && ATTACHMENT_LEVELS.has(extension) && /^(?:pdf|docx?|xlsx?|pptx?|jpg|jpeg|png|txt|csv)$/.test(parts[parts.length - 2]);
  return { extension, doubleExtension, parts };
}

function detectAttachmentType(input) {
  let highest = 0;
  const spans = [];
  for (const attachment of input.attachments) {
    const name = asString(attachment.name);
    const { extension, doubleExtension } = extensionOf(name);
    let level = ATTACHMENT_LEVELS.get(extension) || 0;
    if (doubleExtension) level = 3;
    if (!level) continue;
    highest = Math.max(highest, level);
    const field = `attachments[${attachment.index}].name`;
    const start = Math.max(0, name.toLowerCase().lastIndexOf(`.${extension}`) + 1);
    spans.push(span(field, name, start, start + extension.length, doubleExtension ? 'double-extension executable' : `risky .${extension} attachment`));
  }
  return { severity: highest, matchedSpans: spans };
}

const CREDENTIAL_PATTERNS = [
  { label: 'password or code request', pattern: /\b(?:enter|share|send|confirm|verify|type|provide|need|ask(?:ing)?\s+for)\s+(?:us\s+)?(?:your\s+)?(?:username\s+(?:and|&)\s+)?(?:password|passcode|credentials|one[- ]time\s+(?:pass)?code|verification\s+code|otp|2fa\s+code)\b/giu, strength: 3 },
  { label: 'credential noun request', pattern: /\b(?:username\s+(?:and|&)\s+password|login\s+(?:details|credentials)|sign[- ]in\s+(?:details|credentials))\b/giu, strength: 3 },
  { label: 'one-time code request', pattern: /\b(?:send|share|read|type|enter)\s+(?:us\s+)?(?:the\s+|your\s+)?(?:one[- ]time\s+(?:pass)?code|verification\s+code|otp|2fa\s+code)\b/giu, strength: 3 },
  { label: 'social security number', pattern: /\b(?:full\s+)?social\s+security\s+(?:number|no\.?)\b/giu, strength: 2 },
  { label: 'bank account number', pattern: /\b(?:full\s+)?bank\s+account\s+(?:number|no\.?)\b/giu, strength: 2 },
  { label: 'payment information update', pattern: /\bupdate\s+(?:your\s+)?payment\s+(?:information|details)\b/giu, strength: 2 },
  { label: 'verify account demand', pattern: /\bverify\s+your\s+(?:account|identity)\b/giu, strength: 1 },
];

function isNegated(source, start) {
  const prefix = source.slice(Math.max(0, start - 48), start).toLowerCase();
  return /\b(?:never|not|no longer|won't|will not|do not|don't|without)\b[^.!?]*$/.test(prefix);
}

function detectCredentialRequest(input) {
  const matches = collectRegexSpans('body', input.body, CREDENTIAL_PATTERNS)
    .filter((item) => !isNegated(input.body, item.start));
  let highest = 0;
  for (const item of matches) {
    const pattern = CREDENTIAL_PATTERNS.find((entry) => entry.label === item.label);
    highest = Math.max(highest, pattern ? pattern.strength : 1);
  }
  return { severity: highest, matchedSpans: matches.map(({ strength, ...item }) => item) };
}

const FAMILY_HIGH_PATTERNS = [
  { label: 'jail or arrest story', pattern: /\b(?:in jail|arrested|bail\b|court fine)\b/giu },
  { label: 'accident or hospital story', pattern: /\b(?:car accident|accident|hospital|emergency room|stranded)\b/giu },
  { label: 'lost access story', pattern: /\b(?:lost my wallet|phone broke|new number|stuck at the airport)\b/giu },
];

const FAMILY_SECRECY_PATTERN = /\b(?:don'?t|do\s+not)\s+tell\s+(?:mom|dad|your\s+parents?|anyone|anybody)\b/giu;
const FAMILY_MONEY_PATTERN = /\b(?:need|send|wire|borrow)\s+(?:me\s+)?(?:money|cash|\$?\d+)|\bbail\s+money\b|\bgift\s+cards?\b/giu;
const FAMILY_ROLE_PATTERN = /\b(?:grandma|grandpa|grandmother|grandfather|mom|dad|son|daughter|grandson|granddaughter)\b/giu;

function detectFamilyEmergency(input) {
  const high = collectRegexSpans('body', input.body, FAMILY_HIGH_PATTERNS);
  const secrecy = collectRegexSpans('body', input.body, [{ label: 'secrecy instruction', pattern: FAMILY_SECRECY_PATTERN }]);
  const money = collectRegexSpans('body', input.body, [{ label: 'emergency money request', pattern: FAMILY_MONEY_PATTERN }]);
  const roles = collectRegexSpans('body', input.body, [{ label: 'family role', pattern: FAMILY_ROLE_PATTERN }]);
  const triggerCount = countDistinctLabels(high) + secrecy.length + money.length;
  if (!triggerCount) return { severity: 0, matchedSpans: [] };
  const total = countDistinctLabels(high) + secrecy.length * 2 + money.length + (roles.length ? 1 : 0);
  const severity = total >= 4 ? 3 : total >= 2 ? 2 : 1;
  const matchedSpans = [...high, ...secrecy, ...money, ...(severity >= 2 ? roles.slice(0, 1) : [])]
    .map(({ strength, ...item }) => item)
    .sort((a, b) => a.start - b.start || a.end - b.end);
  return { severity, matchedSpans };
}

const DETECTOR_RUNNERS = {
  'urgency-pressure': detectUrgency,
  'payment-rail-switch': detectPaymentRail,
  'sender-domain-mismatch': detectSenderMismatch,
  'lookalike-domain': detectLookalikeDomain,
  'reply-to-divergence': detectReplyToDivergence,
  'attachment-type': detectAttachmentType,
  'credential-request': detectCredentialRequest,
  'family-emergency-script': detectFamilyEmergency,
};

const SEVERITY_MULTIPLIERS = [0, 0.45, 0.75, 1];

function verdictForScore(score) {
  if (score >= 35) {
    return {
      band: 'high-pressure-pattern',
      label: 'High-pressure pattern',
      summary: 'Several strong manipulation signals appear together. Stop and verify before anyone acts.',
    };
  }
  if (score >= 15) {
    return {
      band: 'suspicious-pattern',
      label: 'Suspicious pattern',
      summary: 'Some meaningful warning signals appear. Treat the message as unverified until checked through a trusted route.',
    };
  }
  if (score > 0) {
    return {
      band: 'low-signal-unverified',
      label: 'Low signal, still unverified',
      summary: 'Only weak or isolated signals appeared. That does not clear the message; verify anything important before acting.',
    };
  }
  return {
    band: 'no-rule-match-unverified',
    label: 'No rule match, still unverified',
    summary: 'None of the eight deterministic rules matched. The message still needs real-world verification before money, codes, links or attachments are involved.',
  };
}

function buildReadAloudScript(input, tactics) {
  const detected = tactics.filter((item) => item.status === 'detected').map((item) => item.name.toLowerCase());
  const lines = [
    'Pause. Nobody in this family is replying, clicking, opening a file or sending money yet.',
    'This message is unverified. We are going to check it through a phone number, app or website we already trust, not the contact information inside the message.',
  ];
  if (detected.length) {
    lines.push(`The highlighted parts show ${detected.slice(0, 3).join(', ')}${detected.length > 3 ? ' and more' : ''}. Those are pressure tactics, not proof.`);
  } else {
    lines.push('The checker found no matching rule, but that is not approval. It only means these exact patterns were not present.');
  }
  lines.push('If money, passwords, one-time codes, bail, gift cards or secrecy come up, we call another family member before doing anything.');
  return lines;
}

function analyzeMessage(rawInput = {}) {
  const input = normalizeInput(rawInput);
  const tactics = DETECTOR_DEFINITIONS.map((definition) => {
    const result = DETECTOR_RUNNERS[definition.id](input);
    const severity = clampSeverity(result.severity);
    const contribution = Math.round(definition.weight * SEVERITY_MULTIPLIERS[severity]);
    return {
      id: definition.id,
      name: definition.name,
      status: severity > 0 ? 'detected' : 'not-detected',
      severity,
      weight: definition.weight,
      contribution,
      matchedSpans: result.matchedSpans,
      whyItWorks: definition.whyItWorks,
      nextStep: definition.nextStep,
    };
  });
  const score = tactics.reduce((sum, item) => sum + item.contribution, 0);
  const verdict = verdictForScore(score);
  return {
    inputQuality: {
      status: input.malformed ? 'malformed' : 'ok',
      issues: input.issues,
    },
    normalizedInput: {
      channel: input.channel,
      displayName: input.displayName,
      sender: input.sender,
      replyTo: input.replyTo,
      body: input.body,
      attachments: input.attachments,
    },
    verdict: {
      score,
      maxScore: 100,
      ...verdict,
      residualRisk: 'Residual risk remains even when no rule matches. This offline checker cannot inspect live links or prove who controls the sender account.',
    },
    tactics,
    unevaluated: UNEVALUATED.map((item) => ({ ...item })),
    readAloudScript: buildReadAloudScript(input, tactics),
  };
}

const DRILLS = [
  {
    id: 'family-bail-secret',
    title: 'The late-night bail request',
    category: 'scam',
    input: {
      channel: 'sms',
      displayName: 'Maya',
      sender: '+1 555 0101',
      replyTo: '',
      body: 'Grandma, it is Maya. I was in a car accident and I am in jail. Please do not tell Mom. Send $850 in Apple gift cards right now.',
      attachments: [],
    },
    expectedTactics: ['urgency-pressure', 'payment-rail-switch', 'family-emergency-script'],
  },
  {
    id: 'bank-account-lock',
    title: 'The locked bank account',
    category: 'scam',
    input: {
      channel: 'email',
      displayName: 'BlueCrest Bank Security',
      sender: 'security@bluecrest-verify.example.net',
      replyTo: 'case-help@example.com',
      body: 'Your account is locked. Verify your username and password and send the one-time code within 30 minutes or access will be suspended.',
      attachments: [],
    },
    expectedTactics: ['urgency-pressure', 'sender-domain-mismatch', 'reply-to-divergence', 'credential-request'],
  },
  {
    id: 'package-label-attachment',
    title: 'The package label attachment',
    category: 'scam',
    input: {
      channel: 'email',
      displayName: 'ParcelPost Delivery',
      sender: 'notice@parcelpost-support.example.net',
      replyTo: 'notice@parcelpost-support.example.net',
      body: 'Final notice: your package is held. Open the attached label now and pay the customs fee with crypto.',
      attachments: [{ name: 'shipping-label.pdf.exe', type: 'application/x-msdownload' }],
    },
    expectedTactics: ['urgency-pressure', 'payment-rail-switch', 'sender-domain-mismatch', 'attachment-type'],
  },
  {
    id: 'school-pickup-change',
    title: 'The school pickup change',
    category: 'legitimate-but-suspicious',
    input: {
      channel: 'email',
      displayName: 'River School Office',
      sender: 'office@mail.riverschool.example',
      replyTo: 'office@mail.riverschool.example',
      body: 'Today buses leave at 2:15 PM for the planned early release. No action is needed. If your pickup plan changes, use the usual school portal or call the office number printed on your school card.',
      attachments: [],
    },
    expectedTactics: [],
  },
  {
    id: 'family-airport-update',
    title: 'The airport update',
    category: 'legitimate-but-suspicious',
    input: {
      channel: 'sms',
      displayName: 'Maya',
      sender: '+1 555 0101',
      replyTo: '',
      body: 'Grandma, I am at the airport and my battery is low. No rush and no money needed. Please call Mom when you can so she knows I landed.',
      attachments: [],
    },
    expectedTactics: [],
  },
  {
    id: 'bank-statement-notice',
    title: 'The bank statement notice',
    category: 'legitimate-but-suspicious',
    input: {
      channel: 'email',
      displayName: 'BlueCrest Bank',
      sender: 'statements@mail.bluecrest.example',
      replyTo: 'statements@mail.bluecrest.example',
      body: 'Your November statement is ready in the secure message center. We will never ask for your password or one-time code. The attached PDF is a copy for your records.',
      attachments: [{ name: 'november-statement.pdf', type: 'application/pdf' }],
    },
    expectedTactics: [],
  },
];

function drillById(drillId) {
  return DRILLS.find((drill) => drill.id === drillId) || null;
}

function gradeDrill(drillId, selectedTactics = [], declaredCategory = '') {
  const drill = drillById(drillId);
  if (!drill) {
    return {
      ok: false,
      error: `Unknown drill "${asString(drillId)}".`,
      score: 0,
      maxScore: 100,
    };
  }
  const selected = [...new Set((Array.isArray(selectedTactics) ? selectedTactics : []).map((item) => asString(item)))];
  const expected = new Set(drill.expectedTactics);
  const selectedSet = new Set(selected);
  const correct = [...expected].filter((id) => selectedSet.has(id));
  const missed = [...expected].filter((id) => !selectedSet.has(id));
  const falseAlarms = selected.filter((id) => !expected.has(id) && DETECTOR_RUNNERS[id]);
  const unknownSelections = selected.filter((id) => !DETECTOR_RUNNERS[id]);
  const categoryCorrect = declaredCategory === drill.category;
  const tacticTotal = expected.size + Math.max(0, 8 - expected.size);
  const tacticCorrect = correct.length + [...DETECTOR_DEFINITIONS.map((item) => item.id)].filter((id) => !expected.has(id) && !selectedSet.has(id)).length;
  const tacticScore = Math.round((tacticCorrect / tacticTotal) * 70);
  const categoryScore = categoryCorrect ? 30 : 0;
  const score = Math.max(0, Math.min(100, tacticScore + categoryScore - unknownSelections.length * 5));
  return {
    ok: true,
    drillId: drill.id,
    categoryCorrect,
    expectedCategory: drill.category,
    correct,
    missed,
    falseAlarms,
    unknownSelections,
    score,
    maxScore: 100,
    verdict: score >= 90 ? 'excellent' : score >= 70 ? 'ready with review' : 'practice again',
  };
}

export {
  DETECTOR_DEFINITIONS,
  DRILLS,
  UNEVALUATED,
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
};
