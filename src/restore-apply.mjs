// 10단계: 검증한 안전 정책 사본으로 시험 정책(aleph.config.json의 allowedRoutes)을 되돌립니다.
// 기본은 미리보기이고, 아무것도 쓰지 않습니다. 실제로 쓰려면 --apply 와 --confirm <해시 앞 12자>가 모두 필요합니다.
// 바꾸는 것은 allowedRoutes 목록 하나뿐입니다. 다른 설정 항목, 판정기 코드(src/decider.mjs), 자료,
// 학습 DB, xdr 기록은 읽지도 쓰지도 않고, 감사 기록 파일에는 한 줄을 덧붙이기만 합니다.
import { appendFileSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SNAPSHOT_PATH, diffPolicy, formatPlan, loadCurrentPolicy, readSnapshot } from './restore-plan.mjs';

export const AUDIT_PATH = join('backup', 'restore-audit.log');
const CONFIG_PATH = 'aleph.config.json';

const fail = (message) => { throw new Error(message); };

// 지금 목록의 순서를 최대한 지키고, 사본에 없는 것은 빼고, 사본에만 있는 것은 뒤에 붙입니다.
export function mergeRoutes(currentRoutes, snapshotRoutes) {
  const kept = currentRoutes.filter(route => snapshotRoutes.includes(route));
  const restored = snapshotRoutes.filter(route => !currentRoutes.includes(route));
  return [...kept, ...restored];
}

// allowedRoutes 말고는 한 글자도 바꾸지 않은 새 설정을 돌려줍니다.
export function restoreConfig(config, snapshotPolicy) {
  if (config === null || typeof config !== 'object' || !Array.isArray(config.allowedRoutes)) {
    fail('aleph.config.json의 allowedRoutes를 읽을 수 없습니다.');
  }
  return { ...config, allowedRoutes: mergeRoutes(config.allowedRoutes, snapshotPolicy.allowedRoutes) };
}

export async function runRestore({ root, apply = false, confirm = null, now = new Date() }) {
  const snapshot = readSnapshot(join(root, SNAPSHOT_PATH));
  const current = await loadCurrentPolicy(root);
  const diff = diffPolicy(snapshot.policy, current);
  const plan = formatPlan(snapshot, diff).split('\n');
  // 적용 모드에서는 미리보기 전용 문구(첫 줄과 마지막 줄)를 바꿉니다.
  if (apply) { plan[0] = '복원 계획 (적용 전 확인)'; plan.pop(); }
  const lines = [plan.join('\n')];
  const short = snapshot.sha256.slice(0, 12);

  if (!apply) {
    lines.push(`적용하지 않았습니다. 위 항목을 확인한 뒤 실행하려면: npm run restore:apply -- --apply --confirm ${short}`);
    return { lines, wrote: false };
  }
  if (confirm !== short) {
    fail('확인 값이 복원할 버전의 해시와 다릅니다. 위 미리보기의 해시 앞 12자를 --confirm 뒤에 적어 주세요. 아무것도 바꾸지 않았습니다.');
  }
  if (diff.ruleIds.restored.length || diff.ruleIds.removed.length) {
    fail('규칙 이름이 사본과 다릅니다. 규칙의 동작은 코드이므로 이 절차로 복원하지 않습니다. git 기록으로 확인해 주세요. 아무것도 바꾸지 않았습니다.');
  }
  if (!diff.changed) {
    lines.push('바꿀 항목이 없어 아무것도 쓰지 않았습니다.');
    return { lines, wrote: false };
  }

  const configFile = join(root, CONFIG_PATH);
  const before = JSON.parse(readFileSync(configFile, 'utf8'));
  const after = restoreConfig(before, snapshot.policy);
  const others = (config) => Object.fromEntries(Object.entries(config).filter(([key]) => key !== 'allowedRoutes'));
  if (!isDeepStrictEqual(others(before), others(after))) fail('allowedRoutes 밖의 설정이 바뀌려 해서 중단했습니다. 아무것도 바꾸지 않았습니다.');

  const temp = `${configFile}.restore.tmp`;
  writeFileSync(temp, `${JSON.stringify(after, null, 2)}\n`, { encoding: 'utf8', flag: 'w' });
  renameSync(temp, configFile);

  const verified = diffPolicy(snapshot.policy, await loadCurrentPolicy(root));
  if (verified.changed) fail('복원 뒤에도 차이가 남았습니다. git diff로 aleph.config.json을 확인해 주세요.');

  appendFileSync(join(root, AUDIT_PATH), [
    now.toISOString(), 'restore', `version=${snapshot.version}`, `sha=${short}`,
    `routesRestored=${diff.allowedRoutes.restored.length}`, `routesRemoved=${diff.allowedRoutes.removed.length}`,
  ].join('\t') + '\n', 'utf8');
  lines.push(`복원했습니다: ${snapshot.version} (허용 경로 되살림 ${diff.allowedRoutes.restored.length}건, 제거 ${diff.allowedRoutes.removed.length}건).`);
  lines.push('판정기 코드, 다른 설정 항목, 자료, 기존 감사 기록은 바꾸지 않았고 backup/restore-audit.log에 한 줄만 덧붙였습니다.');
  return { lines, wrote: true };
}

function readArgs(argv) {
  const args = { apply: false, confirm: null };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--apply') args.apply = true;
    else if (argv[i] === '--confirm' && typeof argv[i + 1] === 'string') { args.confirm = argv[i + 1]; i += 1; }
    else fail(`알 수 없는 입력: ${argv[i]}`);
  }
  return args;
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    const root = resolve(import.meta.dirname, '..');
    const { lines } = await runRestore({ root, ...readArgs(process.argv.slice(2)) });
    process.stdout.write(`${lines.join('\n')}\n`);
  } catch (error) {
    process.stderr.write(`복원 중단: ${error.message}\n`);
    process.exitCode = 1;
  }
}
