// 웹 주입 경보 읽기 모듈입니다. 경보 원본은 읽기만 하고 고치지 않습니다.
// 경보마다 시각·출발 주소·계정·규칙 수준·설명만 뽑습니다(경보 번호는 로그에서 찾으려는 표식입니다).
// 네트워크와 파일 쓰기는 하지 않습니다. 비밀값처럼 보이는 값은 [가림] 으로 바꿔 출력합니다.
import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

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
const REDACTED = '[가림]';
const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/u;
const IPV6 = /^[0-9A-Fa-f:]{2,39}$/u;
const ACCOUNT = /^[A-Za-z0-9._@-]{1,64}$/u;

export function redact(text) {
  let out = text;
  for (const pattern of SECRET_LIKE) out = out.replace(pattern, REDACTED);
  return out;
}

const cleanText = (value, max) => (typeof value === 'string' ? redact(value).slice(0, max) : null);

// 경보 한 건에서 값만 꺼냅니다. 형식이 이상하거나 없는 값은 버리지 않고 null 로 남겨 건수를 맞춥니다.
export function pickFields(alert) {
  const when = typeof alert?.timestamp === 'string' && !Number.isNaN(Date.parse(alert.timestamp)) ? alert.timestamp : null;
  const ip = typeof alert?.data?.srcip === 'string' && (IPV4.test(alert.data.srcip) || IPV6.test(alert.data.srcip))
    ? alert.data.srcip : null;
  const account = typeof alert?.data?.srcuser === 'string' && ACCOUNT.test(alert.data.srcuser) ? alert.data.srcuser : null;
  const rawLevel = alert?.rule?.level;
  const level = (typeof rawLevel === 'number' || (typeof rawLevel === 'string' && rawLevel.trim() !== ''))
    && Number.isInteger(Number(rawLevel)) && Number(rawLevel) >= 0 && Number(rawLevel) <= 15
    ? Number(rawLevel) : null;
  return {
    alertId: cleanText(alert?.id, 40),
    at: when,
    srcIp: ip,
    account,
    ruleLevel: level,
    description: cleanText(alert?.rule?.description, 200),
  };
}

export async function readAlerts({ root }) {
  const file = join(root, 'xdr', 'fixtures', 'web-injection.json');
  const fixture = JSON.parse(await readFile(file, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'web-injection' || !Array.isArray(fixture.alerts)) {
    throw new Error('경보 묶음 형식이 아닙니다.');
  }
  const rows = fixture.alerts.map(pickFields);
  return { alertCount: fixture.alerts.length, rows };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
  try {
    const { alertCount, rows } = await readAlerts({ root });
    for (const row of rows) {
      console.log([row.alertId, row.at, row.srcIp, row.account ?? '-', `수준 ${row.ruleLevel}`, row.description].join(' | '));
    }
    console.log(`경보 ${alertCount}건 · 뽑은 줄 ${rows.length}줄 · ${alertCount === rows.length ? '일치' : '불일치'}`);
    if (alertCount !== rows.length) process.exitCode = 1;
  } catch (error) {
    console.error(error instanceof Error ? error.message : '실행 오류');
    process.exitCode = 1;
  }
}
