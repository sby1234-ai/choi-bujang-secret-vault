// 10단계: 검증된 정책 사본으로 시험 정책(작업 폴더의 정책 파일)만 되돌립니다.
// 10단계 복원 묶음: 사본을 다시 읽어 검증하고(실패하면 중단), 실행 전에 버전·바뀔 항목을 보여 주며, 한 건만 ID·소유자·내용 해시로 대조해 되살리는 경로의 일부입니다.
// 1) 인자 없이 실행하면 복원할 버전·바뀔 항목·확인 번호만 보여 주고 아무것도 바꾸지 않습니다.
// 2) --apply --confirm=<확인 번호>로 다시 실행해야 되돌립니다. 그사이 파일이 바뀌면 번호가 달라 중단합니다.
// 사본 목록에 없는 파일(다른 서비스 규칙)과 기존 감사 기록은 건드리지 않고, 복원 기록은 감사 로그 끝에 덧붙이기만 합니다.
// 학습 DB·배포 같은 실제 운영 정책에는 접속하지 않습니다.
import { applyRestore, changeSetId, comparePolicy, defaultRoot, formatPlan, loadVerifiedPolicy } from './policy-lib.mjs';

const args = process.argv.slice(2);
const apply = args.includes('--apply');
const confirm = args.find((arg) => arg.startsWith('--confirm='))?.slice('--confirm='.length);
const unknown = args.filter((arg) => arg !== '--apply' && !arg.startsWith('--confirm='));

try {
  if (unknown.length) throw new Error(`알 수 없는 입력: ${unknown.join(' ')}`);
  if (apply) {
    const { lines } = applyRestore({ root: defaultRoot, confirm });
    process.stdout.write(`${lines.join('\n')}\n`);
  } else {
    const policy = loadVerifiedPolicy(defaultRoot);
    const results = comparePolicy(policy, defaultRoot);
    const { lines, changed } = formatPlan(policy, results, defaultRoot);
    process.stdout.write(`${lines.join('\n')}\n`);
    if (!changed.length) {
      process.stdout.write('\n되돌릴 항목이 없습니다. 아무것도 바꾸지 않았습니다.\n');
    } else {
      const id = changeSetId(policy.manifest, results);
      process.stdout.write(`\n확인 번호: ${id}\n위 항목을 사본으로 되돌리려면 다음을 실행합니다.\n`
        + `  npm run policy:restore -- --apply --confirm=${id}\n아직 아무것도 바꾸지 않았습니다.\n`);
    }
  }
} catch (error) {
  process.stderr.write(`정책 복원 중단: ${error.message}\n`);
  process.exitCode = 1;
}
