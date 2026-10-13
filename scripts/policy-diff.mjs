// 10단계: 검증된 정책 사본과 지금 정책 파일의 차이만 보여 줍니다. 읽기만 하며 아무것도 복원하거나 고치지 않습니다.
// 10단계 복원 묶음: 사본을 다시 읽어 검증하고(실패하면 중단), 실행 전에 버전·바뀔 항목을 보여 주며, 한 건만 ID·소유자·내용 해시로 대조해 되살리는 경로의 일부입니다.
// 사본이 없거나 검증에 실패하면 차이를 보여 주지 않고 중단합니다.
// 학습 DB·배포 같은 실제 운영 정책에는 접속하지 않습니다.
import { comparePolicy, defaultRoot, formatPlan, loadVerifiedPolicy } from './policy-lib.mjs';

try {
  const policy = loadVerifiedPolicy(defaultRoot);
  const { lines } = formatPlan(policy, comparePolicy(policy, defaultRoot), defaultRoot);
  process.stdout.write(`${lines.join('\n')}\n\n이 명령은 차이만 보여 주며 아무것도 복원하거나 고치지 않았습니다.\n`);
} catch (error) {
  process.stderr.write(`정책 비교 중단: ${error.message}\n`);
  process.exitCode = 1;
}
