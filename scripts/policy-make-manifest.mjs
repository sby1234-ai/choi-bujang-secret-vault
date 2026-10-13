// 10단계: 통과한 저장점 커밋에서 정책 사본 목록(policy/verified-policy.json)을 한 번 만듭니다.
// 사용: node scripts/policy-make-manifest.mjs <저장점 커밋> [--label=이름]
// 목록에는 파일 이름과 지문(sha256)만 적습니다. 파일 내용·비밀값은 적지 않으며, 이미 있는 목록은 덮어쓰지 않습니다.
import { buildManifest, defaultRoot } from './policy-lib.mjs';

// 사본에 넣는 정책 파일: 판정기·탐지 규칙·허용 경로·로그인 검증·메모 API·배포 헤더입니다.
// aleph.config.json은 정책 항목(policyKeys)만 사본 대상이고, 단계·주소 같은 다른 설정은 사본 대상이 아닙니다.
const POLICY_FILES = [
  { path: 'src/decider.mjs' },
  { path: 'src/resources.mjs' },
  { path: 'src/detect.mjs' },
  { path: 'src/verify-login.mjs' },
  { path: 'api/notes.js' },
  { path: 'api/notes/[id].js' },
  { path: 'api/_lib/notes-api.js' },
  { path: 'aleph.config.json', policyKeys: ['identityProvider', 'allowedRoutes', 'originalApiUrl'] },
  { path: 'vercel.json' },
];

try {
  const args = process.argv.slice(2);
  const label = args.find((arg) => arg.startsWith('--label='))?.slice('--label='.length);
  const commit = args.find((arg) => !arg.startsWith('--'));
  if (!commit) throw new Error('저장점 커밋을 알려 주세요. 예: node scripts/policy-make-manifest.mjs 13e3b09');
  const manifest = buildManifest({ root: defaultRoot, commit, files: POLICY_FILES, label });
  process.stdout.write(`정책 사본 목록을 만들었습니다: policy/verified-policy.json\n커밋 ${manifest.verifiedCommit.slice(0, 12)} · 파일 ${Object.keys(manifest.files).length}개\n`);
} catch (error) {
  process.stderr.write(`사본 목록 만들기 중단: ${error.message}\n`);
  process.exitCode = 1;
}
