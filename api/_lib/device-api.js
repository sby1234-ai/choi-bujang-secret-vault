// 11단계: 기기 승인 상태를 서버가 정하는 도우미입니다. (api/_lib 아래 파일은 Vercel이 따로 주소로 열지 않습니다.)
// 기기 증표는 서버가 만든 무작위 값이며, 브라우저에는 자바스크립트가 읽을 수 없는 HttpOnly·Secure·SameSite=Strict 쿠키로만 둡니다.
// localStorage·sessionStorage·IndexedDB에는 넣지 않고, DB에는 증표의 SHA-256 지문만 저장합니다(증표 원문은 저장·로그하지 않습니다).
// 서버 함수는 기기를 "승인 대기"로 등록만 할 수 있고 승인할 수 없습니다(DB 권한으로 status 열을 쓰지 못함).
// 승인은 자료실 관리자가 Supabase SQL Editor에서 확인 코드로 직접 바꿉니다(db/devices.sql 아래 예시).
import { createHash, randomBytes } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';

export const DEVICE_COOKIE = '__Host-byteback-device';
const TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const MAX_AGE = 60 * 60 * 24 * 30;
const liveFetch = (...args) => globalThis.fetch(...args);

let database;
function devices() {
  database ??= createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, {
    auth: { persistSession: false, autoRefreshToken: false },
    global: { fetch: liveFetch },
  });
  return database.from('devices');
}

const fingerprint = (token) => createHash('sha256').update(token, 'utf8').digest('hex');
// 확인 코드: 지문 앞 8자리를 4-4로 끊은 대문자입니다. 비밀값이 아니며, 관리자가 승인할 기기를 고를 때만 씁니다.
const codeOf = (hash) => `${hash.slice(0, 4)}-${hash.slice(4, 8)}`.toUpperCase();

export function readDeviceToken(request) {
  const header = request.headers?.cookie;
  if (typeof header !== 'string') return null;
  for (const part of header.split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (name === DEVICE_COOKIE) {
      const value = rest.join('=');
      return TOKEN.test(value) ? value : null;
    }
  }
  return null;
}

function setDeviceCookie(response, token) {
  response.setHeader('Set-Cookie',
    `${DEVICE_COOKIE}=${token}; Path=/; Max-Age=${MAX_AGE}; HttpOnly; Secure; SameSite=Strict`);
}

// 이 브라우저의 기기 증표로 등록된 기기를 로그인한 사용자 기준으로 찾습니다.
// 돌려주는 값: { status: 'none' | 'pending' | 'approved' | 'revoked', code? }
export async function deviceStatus(request, login) {
  const token = readDeviceToken(request);
  if (!token) return { status: 'none' };
  const hash = fingerprint(token);
  const { data, error } = await devices()
    .select('owner_id, status, code').eq('token_sha256', hash).maybeSingle();
  if (error) throw error;
  if (!data || typeof data.owner_id !== 'string'
      || data.owner_id.toLowerCase() !== String(login.userId).toLowerCase()) return { status: 'none' };
  if (!['pending', 'approved', 'revoked'].includes(data.status)) return { status: 'none' };
  return data.status === 'pending' ? { status: 'pending', code: data.code } : { status: data.status };
}

// 이 브라우저를 로그인한 사용자의 "승인 대기" 기기로 등록합니다. 이미 등록돼 있으면 그대로 둡니다(승인 상태를 바꾸지 않음).
export async function requestDevice(request, response, login) {
  const current = await deviceStatus(request, login);
  if (current.status !== 'none') return current;
  const token = randomBytes(32).toString('base64url');
  const hash = fingerprint(token);
  const code = codeOf(hash);
  const { error } = await devices().insert({ owner_id: login.userId, token_sha256: hash, code });
  if (error) throw error;
  setDeviceCookie(response, token);
  return { status: 'pending', code };
}

// 보호 자료 경로가 쓰는 검사입니다. 승인된 기기가 아니면 403을 보내고 false를 돌려줍니다.
// 학생(Supabase) 로그인에만 적용합니다. 심판 로그인(심판 발급자의 ES256 서명)은 심판의 가상 요청이라 이 브라우저 기기 쿠키가 없고,
// 기기 확인은 운영 엔진이 따로 하므로(docs/DECIDER_REQUEST.md의 deviceRegistered) 여기서 막지 않습니다. 이 구분은 제가 정한 가정입니다.
export async function requireApprovedDevice(request, response, login, reply) {
  if (login.kind === 'judge') return true;
  let status;
  try {
    ({ status } = await deviceStatus(request, login));
  } catch {
    console.error('device check failed');
    reply(response, 503, { error: 'DEVICE_CHECK_UNAVAILABLE' });
    return false;
  }
  if (status === 'approved') return true;
  console.warn(`device not approved: ${status}`);
  reply(response, 403, { error: 'DEVICE_NOT_APPROVED', device: status });
  return false;
}
