// 2단계: 가상 메모를 서버에서만 DB로 읽어 돌려주는 함수입니다.
// 서버 전용 키는 Vercel 환경변수(SUPABASE_URL, SUPABASE_SECRET_KEY)에서만 읽습니다.
// 키는 브라우저 파일·응답·로그에 넣지 않습니다.
// 주의: 3단계 로그인 전까지 이 주소는 누구나 부를 수 있습니다(README의 남은 약점 참고).
import { createClient } from '@supabase/supabase-js';

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) {
    // 어떤 값이 없는지만 알리고, 값 자체는 쓰지 않습니다.
    return response.status(500).json({ error: 'SERVER_NOT_CONFIGURED' });
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
      // 오류 문구에 요청 내용이 섞일 수 있으니 코드만 기록합니다.
      console.error('notes query failed', error.code ?? 'unknown');
      return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
    }
    return response.status(200).json({ notes: data ?? [] });
  } catch {
    console.error('notes handler failed');
    return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
  }
}
