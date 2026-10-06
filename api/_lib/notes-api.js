// 메모 API 공통 도우미입니다. (api/_lib 아래 파일은 Vercel이 따로 주소로 열지 않습니다.)
// 로그인 토큰 검사는 틀이 준 src/verify-login.mjs 도우미에 맡기고, 여기서는 고치거나 흉내 내지 않습니다.
// 브라우저가 보낸 userId·role은 읽지도 믿지도 않습니다. 소유자 ID는 서버가 검사한 토큰에서만 얻습니다.
// 본문에 owner_id가 있고 로그인한 본인 ID와 다르면 소유자 변경 시도로 보고 403으로 거부합니다.
// 서버 전용 키는 환경변수에서만 읽고, 응답·로그에 넣지 않습니다.
import { createClient } from '@supabase/supabase-js';
import config from '../../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../../src/verify-login.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const TITLE_MAX = 100;
const BODY_MAX = 2000;

let verifier;
let database;

export const isUuid = (value) => typeof value === 'string' && UUID.test(value);

export function reply(response, status, body) {
  response.setHeader('Cache-Control', 'no-store');
  if (body === undefined) return response.status(status).end();
  return response.status(status).json(body);
}

export function methodNotAllowed(response, allowed) {
  response.setHeader('Allow', allowed.join(', '));
  return reply(response, 405, { error: 'METHOD_NOT_ALLOWED' });
}

// 로그인한 요청이면 { userId }를, 아니면 이미 거부 응답을 보내고 null을 돌려줍니다.
export async function requireLogin(request, response) {
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) {
    reply(response, 500, { error: 'SERVER_NOT_CONFIGURED' });
    return null;
  }
  let login;
  try {
    verifier ??= createLoginVerifier({ config, supabaseSecretKey: process.env.SUPABASE_SECRET_KEY });
    login = await verifier(request.headers.authorization);
  } catch {
    console.error('login verifier setup failed');
    reply(response, 500, { error: 'SERVER_NOT_CONFIGURED' });
    return null;
  }
  if (!login) {
    response.setHeader('WWW-Authenticate', 'Bearer');
    reply(response, 401, { error: 'LOGIN_REQUIRED' });
    return null;
  }
  return { userId: login.userId };
}

export function notes() {
  database ??= createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  return database.from('notes');
}

// 본문에서 id(선택), title, body만 꺼냅니다. owner_id는 저장에 쓰지 않고, 본인 ID와 다르면 거부합니다.
export function readNoteInput(request, { allowId, userId }) {
  let data = request.body;
  if (typeof data === 'string') {
    try { data = JSON.parse(data); } catch { return { error: 'INVALID_BODY' }; }
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) return { error: 'INVALID_BODY' };
  for (const key of ['owner_id', 'ownerId', 'userId']) {
    if (data[key] !== undefined && String(data[key]).toLowerCase() !== String(userId).toLowerCase()) {
      return { error: 'OWNER_FORBIDDEN' };
    }
  }
  const { title, body } = data;
  if (typeof title !== 'string' || !title.trim() || title.trim().length > TITLE_MAX) return { error: 'INVALID_TITLE' };
  if (typeof body !== 'string' || body.length > BODY_MAX) return { error: 'INVALID_BODY_TEXT' };
  const input = { title: title.trim(), body };
  if (allowId && data.id !== undefined) {
    if (!isUuid(data.id)) return { error: 'INVALID_ID' };
    input.id = data.id.toLowerCase();
  }
  return { input };
}

// 입력 오류 응답: 소유자 변경 시도는 403, 나머지는 400입니다.
export const rejectInput = (response, error) => reply(response, error === 'OWNER_FORBIDDEN' ? 403 : 400, { error });

export const toApi = (row) => ({ id: row.id, title: row.title, body: row.content });

export function failed(response, error) {
  console.error('notes query failed', error?.code ?? 'unknown');
  return reply(response, 502, { error: 'NOTES_UNAVAILABLE' });
}
