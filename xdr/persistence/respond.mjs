// 몰래 심어진 프로그램(persistence) 경보의 차단 후보를 거부 규칙으로 만들고, 알림을 xdr/alerts.log 에 한 줄씩 쌓는 연결 모듈입니다.
// decide.mjs 는 판단 결과만 돌려주고 파일 쓰기·판정기 연결은 하지 않으므로 그대로 둡니다. src/decider.mjs 도 건드리지 않습니다.
// 판정기는 이 모듈의 isBlocked() 를 확인 단계로 부르면 됩니다(아직 연결하지 않았습니다. 판정기 요청 계약에 출발 주소가 없습니다).
// 경보 원본은 읽기만 합니다. 규칙은 그 PC 의 출발 주소 하나(정확히 일치)만 격리하고, 반드시 만료 시각과 근거 경보 번호를 가집니다.
// 정상 사용자를 막지 않으려고: 같은 주소에서 정상(record)으로 판단된 이벤트가 있으면 격리를 보류하고,
// 자기 자신(루프백) 주소는 막지 않으며, 확신도가 block 기준 미만이면 규칙을 만들지 않습니다.
// 규칙은 xdr/persistence/block-rules.json 에 따로 둡니다(다른 보너스 묶음의 규칙 파일과 섞이지 않게).
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide as defaultDecide, BLOCK_AT } from './decide.mjs';
import { pickFields } from './read-alerts.mjs';

export const RULE_ID = 'xdr.persistence_isolate';
// 만료 시간과 규칙 상한은 제가 정한 시작값입니다. 운영 기준이 생기면 이 두 상수만 바꿉니다.
export const BLOCK_TTL_SECONDS = 3600;
export const MAX_RULES = 100;
const NEVER_BLOCK = /^(?:127\.|0\.0\.0\.0$|::1?$)/u; // 자기 자신(루프백)은 규칙으로 막지 않습니다.

const iso = (ms) => new Date(ms).toISOString();
const oneLine = (value) => String(value ?? '-').replace(/[\r\n\t|]+/gu, ' ').trim() || '-';

// 차단 후보로 만든 경보에서 규칙을 만듭니다. 같은 주소는 규칙 하나로 합치고 근거 경보 번호를 모읍니다.
export function buildRules(entries, { ttlSeconds = BLOCK_TTL_SECONDS, nowMs = Date.now() } = {}) {
  const protectedIps = new Set(entries.filter((e) => e.decision?.action === 'record' && e.fields?.srcIp).map((e) => e.fields.srcIp));
  const bySource = new Map();
  const skipped = [];
  for (const entry of entries) {
    if (entry.decision?.action !== 'block') continue;
    const { srcIp, at } = entry.fields;
    if (!(entry.decision.confidence >= BLOCK_AT)) { skipped.push({ alertId: entry.alertId, reason: '확신도가 차단 기준 미만이라 규칙을 만들지 않음' }); continue; }
    if (!srcIp) { skipped.push({ alertId: entry.alertId, reason: '출발 주소가 없어 규칙을 만들지 않음' }); continue; }
    if (NEVER_BLOCK.test(srcIp)) { skipped.push({ alertId: entry.alertId, reason: '자기 자신 주소라 규칙을 만들지 않음' }); continue; }
    if (protectedIps.has(srcIp)) { skipped.push({ alertId: entry.alertId, reason: '같은 주소의 정상 이벤트가 있어 차단 보류' }); continue; }
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
// 알림 줄에는 경보 속 실행 파일 경로를 옮기지 않고, 시각·행동·경보 번호·주소·계정·확신도·이유(패턴 이름)만 적습니다.
export async function applyXdr({ root, alerts, decideFn = defaultDecide, nowMs = Date.now() }) {
  const entries = [];
  for (const alert of alerts) {
    const fields = pickFields(alert);
    let decision;
    try { decision = await decideFn(alert); } catch { decision = { action: 'record', confidence: 0, reason: '판단 오류' }; }
    entries.push({ alertId: fields.alertId ?? '-', fields, decision });
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
  const rulesFile = join(root, 'xdr', 'persistence', 'block-rules.json');
  const stored = await readJsonOr(rulesFile, { rules: [] });
  const rules = mergeRules(Array.isArray(stored.rules) ? stored.rules : [], fresh, nowMs);
  await mkdir(dirname(rulesFile), { recursive: true });
  await writeFile(rulesFile, `${JSON.stringify({ schema: 'aleph.xdr.block-rules.v1', rules }, null, 2)}\n`, 'utf8');
  const logged = await appendAlertLog(join(root, 'xdr', 'alerts.log'), logLines);
  return { entries, rules, skipped, logged };
}

// 직접 실행하면 시험 경보를 다시 흘려 봅니다: node xdr/persistence/respond.mjs
// 시각은 경보 안의 시각을 기준으로 맞춥니다(가상 경보라 현재 시각으로 보면 규칙이 이미 만료됩니다). 경보 원본은 고치지 않습니다.
const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
  try {
    const fixture = JSON.parse(await readFile(join(root, 'xdr', 'fixtures', 'persistence.json'), 'utf8'));
    if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'persistence' || !Array.isArray(fixture.alerts)) {
      throw new Error('경보 묶음 형식이 아닙니다.');
    }
    const times = fixture.alerts.map((alert) => Date.parse(pickFields(alert).at)).filter(Number.isFinite);
    const nowMs = Math.max(...times);
    const { entries, rules, skipped, logged } = await applyXdr({ root, alerts: fixture.alerts, nowMs });

    // 경보를 판단한 직후 1분 뒤에 같은 주소에서 요청이 다시 온다고 보고 규칙이 막는지 봅니다.
    let blocked = 0;
    let passed = 0;
    let wrong = 0;
    let normalBlocked = 0;
    for (const entry of entries) {
      const eventMs = Date.parse(entry.fields.at);
      const hit = isBlocked(rules, entry.fields.srcIp, eventMs + 60 * 1000);
      const shouldBlock = entry.decision.action === 'block' && !skipped.some((s) => s.alertId === entry.alertId);
      if (hit) blocked += 1; else passed += 1;
      if (Boolean(hit) !== shouldBlock) wrong += 1;
      if (hit && entry.decision.action === 'record') normalBlocked += 1;
      console.log(`${entry.alertId} | ${entry.fields.srcIp} | 판단 ${entry.decision.action} | ${hit ? `막힘(근거 ${hit.evidenceAlertIds.join(',')} · 만료 ${hit.expiresAt})` : '통과'}`);
    }
    // 만료: 각 규칙은 만료 시각 직전까지 막고, 만료 시각부터는 통과해야 합니다.
    const expiryErrors = rules.filter((rule) => isBlocked(rules, rule.srcIp, Date.parse(rule.expiresAt)) !== null
      || isBlocked(rules, rule.srcIp, Date.parse(rule.expiresAt) - 1) === null).length;
    console.log(`규칙 ${rules.length}개 · 알림 새로 쌓은 줄 ${logged}줄 · 보류 ${skipped.length}건`);
    console.log(`막힘 ${blocked} · 통과 ${passed} · 정상 이벤트 막힘 ${normalBlocked} · 판단과 다른 결과 ${wrong} · 만료 규칙 오류 ${expiryErrors}`);
    if (wrong > 0 || expiryErrors > 0 || normalBlocked > 0) process.exitCode = 1;
  } catch (error) {
    console.error(error instanceof Error ? error.message : '실행 오류');
    process.exitCode = 1;
  }
}
