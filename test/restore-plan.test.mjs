import assert from 'node:assert/strict';
import { test } from 'node:test';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { hashPolicy, verifySnapshot, readSnapshot, diffPolicy, formatPlan, canonicalPolicy } from '../src/restore-plan.mjs';

const policy = {
  ruleIds: ['device_registered', 'zone_known_resource'],
  allowedRoutes: ['GET /api/notes', 'PUT /api/notes/:id'],
};
const make = (overrides = {}) => ({
  schema: 'vault.policy.snapshot.v1', version: 'pre-breach-test', sourceCommit: '13e3b09',
  policy, sha256: hashPolicy(policy), ...overrides,
});

test('올바른 사본은 검증을 통과한다', () => {
  assert.equal(verifySnapshot(make()).version, 'pre-breach-test');
});

test('사본이 없으면 중단한다', () => {
  assert.throws(() => readSnapshot(join(tmpdir(), 'no-such-snapshot.json')), /검증된 정책 사본이 없습니다/u);
});

test('내용이 바뀌어 해시가 안 맞으면 중단한다', () => {
  const bad = make({ policy: { ...policy, ruleIds: [...policy.ruleIds, 'extra_rule'] } });
  assert.throws(() => verifySnapshot(bad), /해시가 내용과 맞지 않습니다/u);
});

test('알 수 없는 항목이나 비밀값처럼 보이는 내용은 거부한다', () => {
  assert.throws(() => verifySnapshot({ ...make(), note: 'x' }), /계약과 다릅니다/u);
  assert.throws(() => verifySnapshot(make({ version: 'a b' })), /version/u);
});

test('차이가 없으면 변경 범위가 없다', () => {
  const diff = diffPolicy(policy, policy);
  assert.equal(diff.changed, false);
  assert.match(formatPlan(make(), diff), /변경 범위: 없음/u);
});

test('사본에만 있는 것은 되살림, 현재에만 있는 것은 제거로 보인다', () => {
  const current = canonicalPolicy({
    ruleIds: ['device_registered', 'attacker_rule'],
    allowedRoutes: ['GET /api/notes', 'PUT /api/notes/:id', 'DELETE /api/notes/:id'],
  });
  const diff = diffPolicy(policy, current);
  assert.deepEqual(diff.ruleIds, { restored: ['zone_known_resource'], removed: ['attacker_rule'] });
  assert.deepEqual(diff.allowedRoutes, { restored: [], removed: ['DELETE /api/notes/:id'] });
  assert.equal(diff.count, 3);
  assert.match(formatPlan(make(), diff), /변경 범위: 3건/u);
});
