// 12단계 탈환 작전실: GET /api/ops 는 판정기 규칙·탐지·회수·복구의 요약을 돌려줍니다.
// 로그인과 승인된 기기가 필요하고(11단계 검사 그대로), 로그인한 사용자 본인의 기기·복원 기록만 읽습니다.
// 각 칸은 출처를 밝힙니다: "executed"(이 요청에서 배포 서버가 실제로 실행·조회함), "not_run"(연결이 없어 실행하지 않음), "error"(조회 실패).
// 판정기·탐지는 배포된 코드에 가상 요청 연습을 그 자리에서 실행한 결과이며, 실제 접속 판정·실제 사건이 아닙니다.
// 메모 제목·본문은 읽지 않고, 서버 기록은 src/ops-summary.mjs로 가린 모양만 돌려줍니다.
import { createClient } from '@supabase/supabase-js';
import manifest from '../policy/verified-policy.json' with { type: 'json' };
import { checkDecider } from '../scripts/decider-test.mjs';
import { checkDetection } from '../scripts/detect-test.mjs';
import { RULE_IDS, decide } from '../src/decider.mjs';
import { detect } from '../src/detect.mjs';
import { policyVersion, practiceSummary, summarizeAudit, summarizeDevices } from '../src/ops-summary.mjs';
import { requireApprovedDevice } from './_lib/device-api.js';
import { methodNotAllowed, reply, requireLogin } from './_lib/notes-api.js';

const AUDIT_LIMIT = 200;
const liveFetch = (...args) => globalThis.fetch(...args);
const db = () => createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }, global: { fetch: liveFetch },
});

async function section(work) {
  try { return { status: 'executed', ...(await work()) }; } catch { return { status: 'error' }; }
}

export default async function handler(request, response) {
  if (request.method !== 'GET') return methodNotAllowed(response, ['GET']);
  const login = await requireLogin(request, response);
  if (!login) return undefined;
  if (!(await requireApprovedDevice(request, response, login, reply))) return undefined;
  const client = db();

  const [decider, detection, devices, audit] = await Promise.all([
    section(async () => ({ ruleIds: [...RULE_IDS], practice: practiceSummary(await checkDecider({ decide, ruleIds: RULE_IDS })) })),
    section(async () => ({ practice: practiceSummary(await checkDetection(detect)) })),
    section(async () => {
      const { data, error } = await client.from('devices')
        .select('code, status, requested_at, approved_at').eq('owner_id', login.userId).order('requested_at', { ascending: false });
      if (error) throw error;
      return summarizeDevices(data);
    }),
    section(async () => {
      const { data, error, count } = await client.from('notes_restore_audit')
        .select('note_id, result, before_sha256, after_sha256, at', { count: 'exact' })
        .eq('owner_id', login.userId).order('id', { ascending: false }).limit(AUDIT_LIMIT);
      if (error) throw error;
      return summarizeAudit(data, count);
    }),
  ]);

  return reply(response, 200, {
    schema: 'byteback.ops.v1',
    generatedAt: new Date().toISOString(),
    decider: { ...decider, live: { status: 'not_run', reason: '판정기가 실제 API 앞에 연결되지 않아 실제 접속 판정 기록이 없습니다.' } },
    detection: { ...detection, live: { status: 'not_run', reason: '운영 엔진이 검증한 실제 접속 사건을 받는 경로가 없어 실제 사건 탐지는 하지 않았습니다.' } },
    revocation: {
      devices,
      proposals: { status: 'not_run', reason: '탐지의 회수 제안(propose_revocation)을 실제 세션·기기 회수로 집행하는 연결이 없습니다.' },
    },
    recovery: {
      policy: { status: 'executed', ...policyVersion(manifest) },
      policyDiff: { status: 'not_run', reason: '배포 서버에는 git 기록이 없어 정책 사본 비교는 PC에서 npm run policy:diff로만 합니다.' },
      restoreAudit: audit,
    },
  });
}
