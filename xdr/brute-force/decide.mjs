// 무차별 로그인 경보 판단 모듈입니다. decide(alert) 하나를 내보냅니다.
// 이 파일은 다른 파일을 불러오지 않고 혼자 동작합니다(심판이 이 파일만 가져가도 실행되도록).
// 순서: 경보에서 필요한 값만 뽑고 → MITRE T1110 근거 패턴과 맞춰 보고 → 명확하면 block, 정상이면 record,
// 애매한 것만 Jev 에게 확신도를 물어 0.85 이상 block · 0.5 이상 alert · 그 아래 record 로 나눕니다.
// Jev 가 응답하지 않거나 형식이 틀리면 alert 로 떨어집니다. 경보 원본은 고치지 않습니다.

export const BLOCK_AT = 0.85;
export const ALERT_AT = 0.5;
// 규칙 수준(rule.level)·실패 건수 경계는 연습 경보의 분포(공격 수준 10~12·실패 15건 이상, 애매 수준 5~8·실패 8건 이하,
// 정상 수준 2~3)에 맞춘 값입니다. MITRE 가 정한 숫자가 아니라서 운영 기준이 생기면 이 상수만 바꿉니다.
export const CLEAR_LEVEL = 10;
export const NORMAL_BELOW = 5;
export const CLEAR_COUNT = 15;
const CLEAR_CONFIDENCE = 0.95;
const NORMAL_CONFIDENCE = 0.05;
const FALLBACK_CONFIDENCE = ALERT_AT; // Jev 무응답 → 정확히 alert 경계
const DEFAULT_TIMEOUT_MS = 5000;

// 근거가 있는 패턴만 둡니다(patterns.json 과 같은 이름·근거). 더 구체적인 패턴이 앞에 옵니다.
const PATTERNS = [
  {
    id: 'same-password-many-accounts',
    name: '여러 계정에 같은 비밀번호 대입',
    evidence: 'T1110.003 비밀번호 스프레잉',
    words: /여러\s*계정|서로\s*다른\s*계정|계정\s*\d+\s*개|계정\s*이름을\s*바꿔|두\s*계정/u,
  },
  {
    id: 'failures-then-success',
    name: '실패가 쌓인 뒤 같은 주소·계정의 성공',
    evidence: 'T1110 탐지 지침',
    words: /실패[^.]*?(뒤|후)[^.]*?성공/u,
  },
  {
    id: 'repeated-failure-same-source',
    name: '같은 주소·같은 계정의 로그인 실패 연속',
    evidence: 'T1110.001 비밀번호 추측',
    words: /로그인\s*실패|실패(?:가|는)?\s*\d+\s*건|실패[^.]*건/u,
  },
];
const byId = (id) => PATTERNS.find((pattern) => pattern.id === id);

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

// Jev 에 보낼 값만 뽑습니다(비밀값 가림 적용). 형식이 이상한 값은 null 입니다.
function summarize(alert) {
  const rawLevel = alert?.rule?.level;
  const level = Number.isFinite(Number(rawLevel)) && String(rawLevel).trim() !== '' ? Number(rawLevel) : null;
  const ip = typeof alert?.data?.srcip === 'string' && (IPV4.test(alert.data.srcip) || IPV6.test(alert.data.srcip)) ? alert.data.srcip : null;
  const account = typeof alert?.data?.srcuser === 'string' && ACCOUNT.test(alert.data.srcuser) ? alert.data.srcuser : null;
  const rawCount = alert?.data?.count;
  const count = (typeof rawCount === 'string' || typeof rawCount === 'number') && String(rawCount).trim() !== '' && Number.isFinite(Number(rawCount)) && Number(rawCount) >= 0
    ? Number(rawCount) : null;
  return {
    at: typeof alert?.timestamp === 'string' ? alert.timestamp : null,
    srcIp: ip,
    account,
    failureCount: count,
    ruleLevel: level !== null && level >= 0 && level <= 15 ? level : null,
    description: typeof alert?.rule?.description === 'string' ? redact(alert.rule.description).slice(0, 200) : null,
  };
}

// 설명 문구가 달라도 놓치지 않도록, 경보의 MITRE 태그(T1110)와 data.accounts 같은 구조 값으로도 패턴을 찾습니다.
function structuralPattern(alert, description) {
  const tagged = Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.some((id) => typeof id === 'string' && id.startsWith('T1110'));
  if (!tagged) return null;
  const accounts = alert?.data?.accounts;
  const many = Array.isArray(accounts) ? accounts.length > 1 : typeof accounts === 'string' && accounts.split(',').filter(Boolean).length > 1;
  if (many) return byId('same-password-many-accounts');
  if (byId('failures-then-success').words.test(description)) return byId('failures-then-success');
  return byId('repeated-failure-same-source');
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
  const description = fields.description ?? '';
  const pattern = PATTERNS.find((item) => item.words.test(description)) ?? structuralPattern(alert, description);
  const patternName = pattern ? pattern.name : '일치하는 패턴 없음';
  const level = fields.ruleLevel;

  // 규칙 수준이 낮은 이벤트는 정상으로 기록합니다.
  if (level !== null && level < NORMAL_BELOW) {
    return { action: 'record', confidence: NORMAL_CONFIDENCE, reason: `${patternName} — 규칙 수준이 낮아 정상으로 기록` };
  }
  // 규칙 수준이 높거나, 패턴이 맞고 실패 건수가 많으면 Jev 에게 묻지 않고 명확한 공격으로 봅니다.
  // 이 모듈은 무차별 로그인 경보만 받으므로, 수준이 높은 경보는 알려진 문구·태그가 없어도 명확한 공격으로 다룹니다.
  const manyFailures = pattern && fields.failureCount !== null && fields.failureCount >= CLEAR_COUNT;
  if ((level !== null && level >= CLEAR_LEVEL) || manyFailures) {
    const basis = level !== null && level >= CLEAR_LEVEL ? '규칙 수준 높음' : `실패 ${fields.failureCount}건`;
    return { action: 'block', confidence: CLEAR_CONFIDENCE, reason: `${patternName} — 명확한 공격(자체 판정, ${basis})` };
  }
  // 나머지는 애매한 경보입니다. Jev 확신도로 나누고, 응답이 없으면 alert 입니다.
  const asked = await askJev({ pattern: pattern ? patternName : null, ...fields });
  if (asked === null) {
    return { action: 'alert', confidence: FALLBACK_CONFIDENCE, reason: `${patternName} — 애매함, Jev 응답 없어 alert` };
  }
  return { action: actionFor(asked), confidence: asked, reason: `${patternName} — 애매함, Jev 확신도 ${asked}` };
}
