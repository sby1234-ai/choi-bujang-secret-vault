import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { hashPolicy } from '../src/restore-plan.mjs';
import { mergeRoutes, restoreConfig, runRestore } from '../src/restore-apply.mjs';

const RULES = ['device_registered', 'zone_known_resource'];
const SAVED = ['GET /api/notes/:id', 'PUT /api/notes/:id'];

function makeRoot({ rules = RULES, routes = SAVED, snapshotTamper = false } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'restore-'));
  mkdirSync(join(root, 'src')); mkdirSync(join(root, 'backup'));
  writeFileSync(join(root, 'src', 'decider.mjs'), `export const RULE_IDS = ${JSON.stringify(rules)};\n`);
  const config = { step: 10, judgeIssuer: 'https://judge.invalid/x', allowedRoutes: routes, restoreRoute: null };
  writeFileSync(join(root, 'aleph.config.json'), `${JSON.stringify(config, null, 2)}\n`);
  const policy = { ruleIds: RULES, allowedRoutes: SAVED };
  const snap = { schema: 'vault.policy.snapshot.v1', version: 'pre-breach-test', sourceCommit: '13e3b09', policy, sha256: hashPolicy(policy) };
  if (snapshotTamper) snap.policy = { ruleIds: [...RULES, 'sneaky_rule'], allowedRoutes: SAVED };
  writeFileSync(join(root, 'backup', 'policy-snapshot.json'), `${JSON.stringify(snap, null, 2)}\n`);
  return { root, short: hashPolicy(policy).slice(0, 12) };
}
const readConfig = (root) => JSON.parse(readFileSync(join(root, 'aleph.config.json'), 'utf8'));
const EXTRA = [...SAVED.slice(0, 1), 'DELETE /api/notes/:id'];

test('순서는 지키고, 사본에 없는 경로는 빼고, 빠진 경로는 뒤에 붙인다', () => {
  assert.deepEqual(mergeRoutes(['B', 'X', 'A'], ['A', 'B', 'C']), ['B', 'A', 'C']);
});

test('restoreConfig는 allowedRoutes 밖을 바꾸지 않는다', () => {
  const config = { step: 10, judgeIssuer: 'j', allowedRoutes: ['X'] };
  assert.deepEqual(restoreConfig(config, { allowedRoutes: ['A'] }), { step: 10, judgeIssuer: 'j', allowedRoutes: ['A'] });
});

test('미리보기는 바뀔 항목을 보여 주고 아무것도 쓰지 않는다', async () => {
  const { root } = makeRoot({ routes: EXTRA });
  const result = await runRestore({ root });
  assert.equal(result.wrote, false);
  assert.match(result.lines.join('\n'), /되살림: PUT \/api\/notes\/:id/u);
  assert.match(result.lines.join('\n'), /제거: DELETE \/api\/notes\/:id/u);
  assert.deepEqual(readConfig(root).allowedRoutes, EXTRA);
  assert.equal(existsSync(join(root, 'backup', 'restore-audit.log')), false);
});

test('확인 값이 없거나 틀리면 쓰지 않고 중단한다', async () => {
  const { root } = makeRoot({ routes: EXTRA });
  await assert.rejects(runRestore({ root, apply: true }), /해시와 다릅니다/u);
  await assert.rejects(runRestore({ root, apply: true, confirm: 'wrong' }), /해시와 다릅니다/u);
  assert.deepEqual(readConfig(root).allowedRoutes, EXTRA);
});

test('확인하면 허용 경로만 사본으로 되돌리고 감사 기록에 한 줄을 남긴다', async () => {
  const { root, short } = makeRoot({ routes: EXTRA });
  const before = readConfig(root);
  const result = await runRestore({ root, apply: true, confirm: short, now: new Date('2026-10-13T00:00:00Z') });
  assert.equal(result.wrote, true);
  const after = readConfig(root);
  assert.deepEqual(after.allowedRoutes, SAVED);
  assert.equal(after.judgeIssuer, before.judgeIssuer);
  assert.equal(after.step, before.step);
  assert.equal(after.restoreRoute, null);
  const audit = readFileSync(join(root, 'backup', 'restore-audit.log'), 'utf8');
  assert.match(audit, /^2026-10-13T00:00:00.000Z\trestore\tversion=pre-breach-test\tsha=/u);
  assert.equal(audit.trim().split('\n').length, 1);
  const again = await runRestore({ root, apply: true, confirm: short });
  assert.equal(again.wrote, false);
});

test('규칙 이름이 사본과 다르면 아무것도 바꾸지 않고 중단한다', async () => {
  const { root, short } = makeRoot({ rules: [...RULES, 'attacker_rule'], routes: EXTRA });
  await assert.rejects(runRestore({ root, apply: true, confirm: short }), /규칙 이름이 사본과 다릅니다/u);
  assert.deepEqual(readConfig(root).allowedRoutes, EXTRA);
});

test('사본이 바뀌어 검증에 실패하면 미리보기도 하지 않고 중단한다', async () => {
  const { root } = makeRoot({ routes: EXTRA, snapshotTamper: true });
  await assert.rejects(runRestore({ root }), /해시가 내용과 맞지 않습니다/u);
});
