// 웹 주입 경보 판단 모듈입니다. decide(alert) 하나를 내보냅니다.
// 이 파일은 다른 파일을 불러오지 않고 혼자 동작합니다(심판이 이 파일만 가져가도 실행되도록).
// 순서: 경보에서 필요한 값만 뽑고 → MITRE T1190 근거 패턴과 맞춰 보고 → 명확하면 block, 정상이면 record,
// 애매한 것만 Jev 에게 확신도를 물어 0.85 이상 block · 0.5 이상 alert · 그 아래 record 로 나눕니다.
// Jev 가 응답하지 않거나 형식이 틀리면 alert 로 떨어집니다. 경보 원본은 고치지 않습니다.

export const BLOCK_AT = 0.85;
export const ALERT_AT = 0.5;
// 규칙 수준·반복 횟수 경계는 연습 경보의 분포(공격 수준 10~12·반복 8회 이상, 애매 수준 5~8·1회, 정상 수준 2~3)에 맞춘 값입니다.
// MITRE 가 정한 숫자가 아니라서 운영 기준이 생기면 이 상수만 바꿉니다. 수준 4·9 처럼 비어 있는 구간은 애매한 쪽(alert)으로 둡니다.
export const CLEAR_LEVEL = 10;
export const NORMAL_MAX_LEVEL = 3;
export const REPEAT_COUNT = 5;
const CLEAR_CONFIDENCE = 0.95;
const NORMAL_CONFIDENCE = 0.05;
const FALLBACK_CONFIDENCE = ALERT_AT; // Jev 무응답 → 정확히 alert 경계
const DEFAULT_TIMEOUT_MS = 5000;

// 근거가 있는 패턴만 둡니다(patterns.json 과 같은 이름). words 는 설명 문구, url 은 요청 주소 안의 실제 표기입니다.
// 단어 하나(select·script·sql)만으로는 맞지 않게, 문법 모양이 갖춰진 표기만 잡습니다.
const PATTERNS = [
  {
    id: 'sql-in-request-argument',
    name: '요청 인자 안의 SQL 구문',
    evidence: 'CISA AA23-158A SQL 주입(CVE-2023-34362)',
    words: /SQL\s*구문|SQL\s*표식|데이터베이스\s*조회[^.]*이어\s*붙/u,
    url: /\bunion\b\s+(?:all\s+)?select\b|\b(?:or|and)\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+|['"]\s*(?:or|and)\s|;\s*(?:drop|insert|update|delete|select)\b|\bselect\b[^&]{1,80}\bfrom\b/iu,
  },
  {
    id: 'script-tag-in-request-argument',
    name: '요청 인자 안의 스크립트 삽입 표기',
    evidence: 'OWASP XSS',
    words: /스크립트\s*(?:삽입|표식|표기)/u,
    url: /<\s*script|javascript\s*:|\bon(?:error|load)\s*=/iu,
  },
  {
    id: 'path-traversal-repeat',
    name: '경로 거슬러 올라가기(../) 반복',
    evidence: 'OWASP Path Traversal',
    words: /경로[^.]*(?:거슬러|이탈)/u,
    url: /(?:\.\.[/\\]){2,}/u,
  },
];
// 같은 사건을 여러 문구로 쓴 경우를 위해 설명에 "아닙니다·없습니다·않았" 같은 부정이 있으면 그 문구로는 패턴을 잡지 않습니다.
const NEGATED = /아닙니다|없습니다|않았|않습니다/u;

const SECRET_LIKE = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/giu,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/giu,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]{4,})?/gu,
  /\bsb_(?:secret|publishable)_[A-Za-z0-9_-]{8,}/giu,
  /\bsk-[A-Za-z0-9_-]{16,}/gu,
  /\b(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization)\s*[=:]\s*\S+/giu,
  /\b(?:비밀번호|암호|토큰|비밀키)\s*[=:]\s*\S+/gu,
  /\b[A-Fa-f0-9]{32,}\b/gu,
];
const redact = (text) => SECRET_LIKE.reduce((out, pattern) => out.replace(pattern, '[가림]'), text);
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/u;
const IPV6 = /^[0-9A-Fa-f:]{2,39}$/u;
const ACCOUNT = /^[A-Za-z0-9._@-]{1,64}$/u;

// 퍼센트 인코딩을 두 번까지 풉니다. 깨진 인코딩은 원문을 그대로 씁니다.
function decodeUrl(value) {
  let text = value;
  for (let i = 0; i < 2; i += 1) {
    try { const next = decodeURIComponent(text); if (next === text) break; text = next; } catch { break; }
  }
  return text;
}

// Jev 에 보낼 값만 뽑습니다(비밀값 가림 적용). 형식이 이상한 값은 null 입니다.
function summarize(alert) {
  const rawLevel = alert?.rule?.level;
  const level = (typeof rawLevel === 'number' || (typeof rawLevel === 'string' && rawLevel.trim() !== '')) && Number.isFinite(Number(rawLevel))
    ? Number(rawLevel) : null;
  const ip = typeof alert?.data?.srcip === 'string' && (IPV4.test(alert.data.srcip) || IPV6.test(alert.data.srcip)) ? alert.data.srcip : null;
  const account = typeof alert?.data?.srcuser === 'string' && ACCOUNT.test(alert.data.srcuser) ? alert.data.srcuser : null;
  const rawCount = alert?.data?.count;
  const count = (typeof rawCount === 'string' || typeof rawCount === 'number') && String(rawCount).trim() !== '' && Number.isFinite(Number(rawCount)) && Number(rawCount) >= 0
    ? Number(rawCount) : null;
  const rawUrl = typeof alert?.data?.url === 'string' ? alert.data.url.slice(0, 500) : null;
  return {
    at: typeof alert?.timestamp === 'string' ? alert.timestamp : null,
    srcIp: ip,
    account,
    failureCount: null,
    repeatCount: count,
    ruleLevel: level !== null && level >= 0 && level <= 15 ? level : null,
    description: typeof alert?.rule?.description === 'string' ? redact(alert.rule.description).slice(0, 200) : null,
    // 주소는 패턴 확인에만 쓰고 Jev 에는 보내지 않습니다(요청에 비밀값이 섞일 수 있어서).
    decodedUrl: rawUrl === null ? null : decodeUrl(rawUrl),
  };
}

function findPattern(fields) {
  const description = fields.description ?? '';
  if (!NEGATED.test(description)) {
    const byWords = PATTERNS.find((item) => item.words.test(description));
    if (byWords) return byWords;
  }
  if (fields.decodedUrl) {
    const byUrl = PATTERNS.find((item) => item.url.test(fields.decodedUrl));
    if (byUrl) return byUrl;
  }
  return null;
}

// Jev 연결 지점입니다. 기본값은 연결 없음이라 애매한 경보는 alert 가 됩니다.
let jevClient = null;
let jevTimeoutMs = DEFAULT_TIMEOUT_MS;
export function configureJev(client, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  if (client !== null && typeof client !== 'function') throw new TypeError('jev_client_must_be_function');
  jevClient = client;
  jevTimeoutMs = timeoutMs;
}

const withTimeout = (promise, ms) => new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error('jev_timeout')), ms);
  Promise.resolve(promise).then((value) => { clearTimeout(timer); resolve(value); },
    (error) => { clearTimeout(timer); reject(error); });
});

// 응답은 숫자 또는 { confidence } 입니다. 0~1 밖이거나 숫자가 아니면 무응답으로 봅니다.
async function askJev(summary) {
  if (!jevClient) return null;
  try {
    const answer = await withTimeout(jevClient(summary), jevTimeoutMs);
    const value = typeof answer === 'number' ? answer : answer?.confidence;
    return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1 ? value : null;
  } catch {
    return null;
  }
}

const actionFor = (confidence) => (confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');

export async function decide(alert) {
  const fields = summarize(alert);
  const pattern = findPattern(fields);
  const tagged = Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1190');
  const patternName = pattern ? pattern.name : tagged ? 'T1190 외부 공개 앱 악용(세부 패턴 없음)' : '일치하는 패턴 없음';
  const level = fields.ruleLevel;
  const repeated = pattern !== null && fields.repeatCount !== null && fields.repeatCount >= REPEAT_COUNT;

  // 규칙 수준이 낮고 반복도 없으면 정상으로 기록합니다.
  if (level !== null && level <= NORMAL_MAX_LEVEL && !repeated) {
    return { action: 'record', confidence: NORMAL_CONFIDENCE, reason: `${patternName} — 규칙 수준이 낮아 정상으로 기록` };
  }
  // 규칙 수준이 높거나, 패턴이 맞고 같은 요청이 여러 번 반복되면 Jev 에게 묻지 않고 명확한 공격으로 봅니다.
  if ((level !== null && level >= CLEAR_LEVEL) || repeated) {
    const basis = level !== null && level >= CLEAR_LEVEL ? '규칙 수준 높음' : `반복 ${fields.repeatCount}회`;
    return { action: 'block', confidence: CLEAR_CONFIDENCE, reason: `${patternName} — 명확한 공격(자체 판정, ${basis})` };
  }
  // 나머지는 애매한 경보입니다. Jev 확신도로 나누고, 응답이 없으면 alert 입니다.
  const { decodedUrl: _omitted, ...forJev } = fields;
  const asked = await askJev({ pattern: pattern ? patternName : null, ...forJev });
  if (asked === null) {
    return { action: 'alert', confidence: FALLBACK_CONFIDENCE, reason: `${patternName} — 애매함, Jev 응답 없어 alert` };
  }
  return { action: actionFor(asked), confidence: asked, reason: `${patternName} — 애매함, Jev 확신도 ${asked}` };
}
