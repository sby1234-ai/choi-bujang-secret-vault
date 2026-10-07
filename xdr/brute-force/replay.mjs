// 시험 경보를 다시 흘려 보는 확인 도구입니다. 경보 원본은 고치지 않습니다.
// 시각은 경보 안의 시각을 기준으로 맞춥니다(가상 경보라 현재 시각으로 보면 규칙이 이미 만료됩니다).
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { applyXdr, isBlocked } from './block-rules.mjs';
import { pickFields } from './read-alerts.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

try {
  const fixture = JSON.parse(await readFile(join(root, 'xdr', 'fixtures', 'brute-force.json'), 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'brute-force' || !Array.isArray(fixture.alerts)) {
    throw new Error('경보 묶음 형식이 아닙니다.');
  }
  const times = fixture.alerts.map((alert) => Date.parse(pickFields(alert).at)).filter(Number.isFinite);
  const nowMs = Math.max(...times);
  const { entries, rules, skipped, logged } = await applyXdr({ root, alerts: fixture.alerts, nowMs });

  // 경보를 판단한 직후 1분 뒤에 같은 주소에서 요청이 다시 온다고 보고 규칙이 막는지 봅니다.
  let blocked = 0;
  let passed = 0;
  let wrong = 0;
  for (const entry of entries) {
    const eventMs = Date.parse(entry.fields.at);
    const hit = isBlocked(rules, entry.fields.srcIp, eventMs + 60 * 1000);
    const shouldBlock = entry.decision.action === 'block' && !skipped.some((s) => s.alertId === entry.alertId);
    if (hit) blocked += 1; else passed += 1;
    if (Boolean(hit) !== shouldBlock) wrong += 1;
    console.log(`${entry.alertId} | ${entry.fields.srcIp} | 판단 ${entry.decision.action} | ${hit ? `막힘(근거 ${hit.evidenceAlertIds.join(',')} · 만료 ${hit.expiresAt})` : '통과'}`);
  }
  // 만료: 각 규칙은 만료 시각 직전까지 막고, 만료 시각부터는 통과해야 합니다.
  const stillBlocked = rules.filter((rule) => isBlocked(rules, rule.srcIp, Date.parse(rule.expiresAt)) !== null
    || isBlocked(rules, rule.srcIp, Date.parse(rule.expiresAt) - 1) === null).length;
  console.log(`규칙 ${rules.length}개 · 알림 새로 쌓은 줄 ${logged}줄 · 보류 ${skipped.length}건`);
  console.log(`막힘 ${blocked} · 통과 ${passed} · 판단과 다른 결과 ${wrong} · 만료 규칙 오류 ${stillBlocked}`);
  if (wrong > 0 || stillBlocked > 0) process.exitCode = 1;
} catch (error) {
  console.error(error instanceof Error ? error.message : '실행 오류');
  process.exitCode = 1;
}
