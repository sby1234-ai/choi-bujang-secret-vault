// 웹 주입 차단 후보를 거부 규칙으로 만들고, 알림을 xdr/alerts.log 에 한 줄씩 쌓는 연결 모듈입니다.
// src/decider.mjs 는 건드리지 않습니다. 판정기는 이 모듈의 isBlocked() 를 확인 단계로 부르면 됩니다.
// 경보 원본은 읽기만 합니다. 규칙은 주소 하나(정확히 일치)만 막고, 반드시 만료 시각과 근거 경보 번호를 가집니다.
// 규칙은 보너스 xdr-01 규칙과 섞이지 않게 xdr/web-injection/block-rules.json 에 따로 둡니다
// (같은 주소가 두 경보 묶음에 모두 나올 수 있고, xdr-01 은 주소 하나당 규칙 하나로 합치기 때문입니다).
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { pickFields } from './read-alerts.mjs';
import { decide as defaultDecide, REPEAT_COUNT } from './decide.mjs';

export const RULE_ID = 'xdr.web_injection_block';
// 만료 시간과 규칙 상한은 제가 정한 시작값입니다. 운영 기준이 생기면 이 두 상수만 바꿉니다.
export const BLOCK_TTL_SECONDS = 3600;
export const MAX_RULES = 100;
const NEVER_BLOCK = /^(?:127\.|0\.0\.0\.0$|::1?$)/u; // 자기 자신(루프백)은 규칙으로 막지 않습니다.

const iso = (ms) => new Date(ms).toISOString();
const oneLine = (value) => String(value ?? '-').replace(/[\r\n\t|]+/gu, ' ').trim() || '-';

// 반복 여부: 경보가 알려 준 반복 횟수가 기준 이상이거나, 같은 주소에서 차단 후보가 두 건 이상 나온 경우입니다.
function repeatCountOf(alert) {
  const raw = alert?.data?.count;
  const value = (typeof raw === 'string' || typeof raw === 'number') && String(raw).trim() !== '' ? Number(raw) : null;
  return Number.isFinite(value) && value >= 0 ? value : null;
}

// 새 규칙을 만듭니다. 같은 주소에서 정상(record)으로 판단된 이벤트가 있거나, 반복이 확인되지 않는 단발 후보는 막지 않고 보류합니다.
export function buildRules(entries, { ttlSeconds = BLOCK_TTL_SECONDS, nowMs = Date.now() } = {}) {
  const protectedIps = new Set(entries.filter((e) => e.decision?.action === 'record' && e.fields?.srcIp).map((e) => e.fields.srcIp));
  const blocksPerIp = new Map();
  for (const entry of entries) {
    if (entry.decision?.action === 'block' && entry.fields?.srcIp) {
      blocksPerIp.set(entry.fields.srcIp, (blocksPerIp.get(entry.fields.srcIp) ?? 0) + 1);
    }
  }
  const bySource = new Map();
  const skipped = [];
  for (const entry of entries) {
    if (entry.decision?.action !== 'block') continue;
    const { srcIp, at } = entry.fields;
    if (!srcIp) { skipped.push({ alertId: entry.alertId, reason: '출발 주소가 없어 규칙을 만들지 않음' }); continue; }
    if (NEVER_BLOCK.test(srcIp)) { skipped.push({ alertId: entry.alertId, reason: '자기 자신 주소라 규칙을 만들지 않음' }); continue; }
    if (protectedIps.has(srcIp)) { skipped.push({ alertId: entry.alertId, reason: '같은 주소의 정상 이벤트가 있어 차단 보류' }); continue; }
    const repeated = (entry.repeatCount !== null && entry.repeatCount >= REPEAT_COUNT) || (blocksPerIp.get(srcIp) ?? 0) >= 2;
    if (!repeated) { skipped.push({ alertId: entry.alertId, reason: '반복이 확인되지 않아 차단 보류' }); continue; }
    const createdMs = at ? Date.parse(at) : nowMs;
    const existing = bySource.get(srcIp);
    if (existing) {
      existing.evidenceAlertIds.push(entry.alertId);
      existing.expiresAt = iso(Math.max(Date.parse(existing.expiresAt), createdMs + ttlSeconds * 1000));
    } else {
      bySource.set(srcIp, {
        ruleId: RULE_ID, srcIp, evidenceAlertIds: [entry.alertId],
        createdAt: iso(createdMs), expiresAt: iso(createdMs + ttlSeconds * 1000),
      });
    }
  }
  const rules = [...bySource.values()];
  for (const extra of rules.slice(MAX_RULES)) skipped.push({ alertId: extra.evidenceAlertIds[0], reason: '규칙 상한을 넘어 제외' });
  return { rules: rules.slice(0, MAX_RULES), skipped };
}

export function activeRules(rules, nowMs = Date.now()) {
  return rules.filter((rule) => Date.parse(rule.expiresAt) > nowMs);
}

// 판정기가 부를 확인 단계입니다. 정확히 같은 주소의, 만료되지 않은 규칙만 찾아 돌려줍니다.
export function isBlocked(rules, srcIp, nowMs = Date.now()) {
  if (typeof srcIp !== 'string' || !srcIp) return null;
  return activeRules(rules, nowMs).find((rule) => rule.srcIp === srcIp) ?? null;
}

function mergeRules(oldRules, newRules, nowMs) {
  const merged = new Map();
  for (const rule of [...activeRules(oldRules, nowMs), ...newRules]) {
    const prior = merged.get(rule.srcIp);
    if (!prior) { merged.set(rule.srcIp, { ...rule, evidenceAlertIds: [...rule.evidenceAlertIds] }); continue; }
    prior.evidenceAlertIds = [...new Set([...prior.evidenceAlertIds, ...rule.evidenceAlertIds])];
    if (Date.parse(rule.expiresAt) > Date.parse(prior.expiresAt)) prior.expiresAt = rule.expiresAt;
    if (Date.parse(rule.createdAt) < Date.parse(prior.createdAt)) prior.createdAt = rule.createdAt;
  }
  return [...merged.values()].slice(0, MAX_RULES);
}

async function readJsonOr(file, fallback) {
  try { return JSON.parse(await readFile(file, 'utf8')); } catch { return fallback; }
}

// 같은 경보·같은 행동은 한 번만 쌓아서 다시 흘려도 줄이 늘어나지 않습니다. 다른 묶음이 쌓은 줄은 건드리지 않고 뒤에 덧붙이기만 합니다.
async function appendAlertLog(file, lines) {
  let known = new Set();
  try {
    known = new Set((await readFile(file, 'utf8')).split('\n').filter(Boolean).map((line) => {
      const parts = line.split(' | ');
      return `${parts[2]}|${parts[1]}`;
    }));
  } catch { /* 처음에는 파일이 없습니다. */ }
  const fresh = lines.filter((line) => !known.has(`${line.alertId}|${line.action}`));
  if (fresh.length) {
    await mkdir(dirname(file), { recursive: true });
    await appendFile(file, `${fresh.map((line) => line.text).join('\n')}\n`, 'utf8');
  }
  return fresh.length;
}

// 경보 묶음을 판단하고, 차단 후보만 규칙으로 만들고, block·alert 알림을 로그에 쌓습니다.
export async function applyXdr({ root, alerts, decideFn = defaultDecide, nowMs = Date.now() }) {
  const entries = [];
  for (const alert of alerts) {
    const fields = pickFields(alert);
    let decision;
    try { decision = await decideFn(alert); } catch { decision = { action: 'record', confidence: 0, reason: '판단 오류' }; }
    entries.push({ alertId: fields.alertId ?? '-', fields, decision, repeatCount: repeatCountOf(alert) });
  }
  const { rules: fresh, skipped } = buildRules(entries, { nowMs });
  const heldReasons = new Map(skipped.map((s) => [s.alertId, s.reason]));
  const logLines = [];
  for (const entry of entries) {
    const { action, confidence, reason } = entry.decision;
    if (action === 'record') continue;
    const held = action === 'block' && heldReasons.has(entry.alertId);
    const logged = held ? 'hold' : action;
    const text = [entry.fields.at ?? iso(nowMs), logged, entry.alertId, entry.fields.srcIp, entry.fields.account, confidence,
      held ? `${reason} (${heldReasons.get(entry.alertId)})` : reason].map(oneLine).join(' | ');
    logLines.push({ alertId: entry.alertId, action: logged, text });
  }
  const rulesFile = join(root, 'xdr', 'web-injection', 'block-rules.json');
  const stored = await readJsonOr(rulesFile, { rules: [] });
  const rules = mergeRules(Array.isArray(stored.rules) ? stored.rules : [], fresh, nowMs);
  await mkdir(dirname(rulesFile), { recursive: true });
  await writeFile(rulesFile, `${JSON.stringify({ schema: 'aleph.xdr.block-rules.v1', rules }, null, 2)}\n`, 'utf8');
  const logged = await appendAlertLog(join(root, 'xdr', 'alerts.log'), logLines);
  return { entries, rules, skipped, logged };
}
