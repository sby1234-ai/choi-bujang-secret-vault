// 무차별 로그인 경보 판단 모듈입니다. decide(alert) 하나를 내보냅니다.
// 순서: 경보에서 다섯 값을 뽑고 → patterns.json 의 패턴과 맞춰 보고 → 명확하면 block, 정상이면 record,
// 애매한 것만 Jev 에게 확신도를 물어 0.85 이상 block · 0.5 이상 alert · 그 아래 record 로 나눕니다.
// Jev 가 응답하지 않거나 형식이 틀리면 alert 로 떨어집니다. 경보 원본은 고치지 않습니다.
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pickFields } from './read-alerts.mjs';

export const BLOCK_AT = 0.85;
export const ALERT_AT = 0.5;
// 규칙 수준(rule.level) 경계는 연습 경보의 분포(공격 10~12, 애매 5~8, 정상 2~3)에 맞춘 값입니다.
export const CLEAR_LEVEL = 10;
export const NORMAL_BELOW = 5;
const CLEAR_CONFIDENCE = 0.95;
const NORMAL_CONFIDENCE = 0.05;
const FALLBACK_CONFIDENCE = ALERT_AT; // Jev 무응답 → 정확히 alert 경계
const DEFAULT_TIMEOUT_MS = 5000;

const PATTERNS_FILE = join(fileURLToPath(new URL('.', import.meta.url)), 'patterns.json');

// 패턴 id → 설명에서 찾는 말. 더 구체적인 패턴이 앞에 옵니다.
const MATCHERS = [
  ['same-password-many-accounts', /여러\s*계정|서로\s*다른\s*계정|계정\s*\d+\s*개|계정\s*이름을\s*바꿔|두\s*계정/u],
  ['failures-then-success', /실패[^.]*?(뒤|후)[^.]*?성공/u],
  ['repeated-failure-same-source', /로그인\s*실패|실패(?:가|는)?\s*\d+\s*건|실패[^.]*건/u],
];

let patternNames = null;
async function loadPatternNames() {
  if (patternNames) return patternNames;
  const file = JSON.parse(await readFile(PATTERNS_FILE, 'utf8'));
  if (file?.schema !== 'aleph.xdr.patterns.v1' || !Array.isArray(file.patterns)) throw new Error('patterns.json 형식이 아닙니다.');
  const names = new Map();
  for (const pattern of file.patterns) {
    if (typeof pattern?.id === 'string' && typeof pattern.name === 'string' && typeof pattern.evidence === 'string' && pattern.evidence.trim()) {
      names.set(pattern.id, pattern.name); // 근거가 없는 패턴은 쓰지 않습니다.
    }
  }
  if (!MATCHERS.every(([id]) => names.has(id))) throw new Error('patterns.json 에 근거가 있는 패턴이 부족합니다.');
  patternNames = names;
  return names;
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

// Jev 에는 뽑아 둔 값만 보냅니다(비밀값 가림 적용 후). 응답은 숫자 또는 { confidence } 입니다.
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

// 설명 문구가 달라도 놓치지 않도록, 경보의 MITRE 태그(T1110)와 data.accounts 같은 구조 값으로도 패턴을 찾습니다.
function structuralPattern(alert, description) {
  const tagged = Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.some((id) => typeof id === 'string' && id.startsWith('T1110'));
  if (!tagged) return null;
  const accounts = alert?.data?.accounts;
  const manyAccounts = Array.isArray(accounts) ? accounts.length > 1 : typeof accounts === 'string' && accounts.split(',').filter(Boolean).length > 1;
  if (manyAccounts) return 'same-password-many-accounts';
  if (MATCHERS[1][1].test(description)) return 'failures-then-success';
  return 'repeated-failure-same-source';
}

export async function decide(alert) {
  const names = await loadPatternNames();
  const fields = pickFields(alert);
  const description = fields.description ?? '';
  const matched = MATCHERS.find(([, pattern]) => pattern.test(description))?.[0] ?? structuralPattern(alert, description);
  const patternName = matched ? names.get(matched) : '일치하는 패턴 없음';
  const level = fields.ruleLevel;

  // 규칙 수준이 낮은 이벤트는 정상으로 기록합니다.
  if (level !== null && level < NORMAL_BELOW) {
    return { action: 'record', confidence: NORMAL_CONFIDENCE, reason: `${patternName} — 규칙 수준이 낮아 정상으로 기록` };
  }
  // 패턴이 맞고 규칙 수준이 높으면 Jev 에게 묻지 않고 명확한 공격으로 봅니다.
  if (matched && level !== null && level >= CLEAR_LEVEL) {
    return { action: 'block', confidence: CLEAR_CONFIDENCE, reason: `${patternName} — 명확한 공격(자체 판정)` };
  }
  // 나머지는 애매한 경보입니다. Jev 확신도로 나누고, 응답이 없으면 alert 입니다.
  const asked = await askJev({
    pattern: matched ? patternName : null,
    at: fields.at, srcIp: fields.srcIp, account: fields.account, ruleLevel: level, description: fields.description,
  });
  if (asked === null) {
    return { action: 'alert', confidence: FALLBACK_CONFIDENCE, reason: `${patternName} — 애매함, Jev 응답 없어 alert` };
  }
  return { action: actionFor(asked), confidence: asked, reason: `${patternName} — 애매함, Jev 확신도 ${asked}` };
}
