// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
function appUrl(config) {
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  return app;
}

async function readJson(url) {
  const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(10000) });
  let data = null;
  if (response.ok) {
    try {
      data = await response.json();
    } catch {
      // A non-JSON response is a failed check, not a successful deployment.
    }
  }
  return { status: response.status, data };
}

export async function runAttackChecks(config) {
  if (config.step !== 1 && config.step !== 2) {
    throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  }
  const app = appUrl(config);
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');

  if (config.step === 1) {
    const { status, data } = await readJson(new URL('/data.json', app));
    const visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
      && data.notes.length > 0;
    return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
      observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${status})` }];
  }

  // 2단계: 옛 공개 파일에는 메모가 없어야 하고, 서버 API는 아직 로그인 없이 열려 있습니다.
  const file = await readJson(new URL('/data.json', app));
  const fileNotes = Array.isArray(file.data?.notes) ? file.data.notes.length : 0;
  const api = await readJson(new URL('/api/notes', app));
  const apiNotes = Array.isArray(api.data?.notes) ? api.data.notes.length : 0;
  return [
    { attackId: 'public_data_json_read', expected: '/data.json에서 메모가 보이지 않음',
      observed: fileNotes === 0 ? `/data.json에서 메모 0건 (HTTP ${file.status})` : `/data.json에서 메모 ${fileNotes}건이 보임` },
    { attackId: 'anonymous_api_read', expected: '3단계 전이라 비로그인 요청으로 서버 API 호출이 가능함(남은 약점)',
      observed: apiNotes > 0 ? `비로그인 요청에서 /api/notes 메모 ${apiNotes}건이 보임 (HTTP ${api.status})` : `비로그인 요청에서 /api/notes 메모가 보이지 않음 (HTTP ${api.status})` },
  ];
}
