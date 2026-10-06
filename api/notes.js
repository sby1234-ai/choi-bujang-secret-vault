// 3단계: 로그인한 요청에만 가상 메모를 돌려주는 서버 함수입니다.
// 토큰 검사는 틀이 준 src/verify-login.mjs 도우미에 맡기고, 여기서는 고치거나 흉내 내지 않습니다.
// 브라우저가 보낸 userId·role·본문·쿼리는 읽지도 믿지도 않습니다. 오직 Authorization 헤더의 토큰만 검사합니다.
// 서버 전용 키는 Vercel 환경변수(SUPABASE_URL, SUPABASE_SECRET_KEY)에서만 읽고, 응답·로그에 넣지 않습니다.
// 주의: 로그인만 확인할 뿐 다른 사람의 자료를 막지는 않습니다(4단계에서 처리).
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';

let verifier;
function getVerifier() {
  verifier ??= createLoginVerifier({ config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY });
  return verifier;
}

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) {
    return response.status(500).json({ error: 'SERVER_NOT_CONFIGURED' });
  }

  let login;
  try {
    login = await getVerifier()(request.headers.authorization);
  } catch {
    console.error('login verifier setup failed');
    return response.status(500).json({ error: 'SERVER_NOT_CONFIGURED' });
  }
  if (!login) {
    // 토큰이 없거나 검사에 실패하면 자료 없이 거부합니다.
    response.setHeader('WWW-Authenticate', 'Bearer');
    return response.status(401).json({ error: 'LOGIN_REQUIRED' });
  }

  try {
    const supabase = createClient(url, secretKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data, error } = await supabase
      .from('notes')
      .select('title, content')
      .order('created_at', { ascending: true });
    if (error) {
      console.error('notes query failed', error.code ?? 'unknown');
      return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    }
    return response.status(200).json({ notes: data ?? [] });
  } catch {
    console.error('notes handler failed');
    return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
  }
}
