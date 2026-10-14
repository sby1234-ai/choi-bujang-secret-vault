// 설치형 웹앱의 오프라인 안내만 맡는 서비스 워커입니다.
// 오프라인 안내 화면(offline.html) 한 장만 미리 받아 두고, 화면 이동 요청이 네트워크에 닿지 못할 때만 그 화면을 보여 줍니다.
// /api/... 요청(로그인·메모·복원)과 다른 요청은 가로채거나 저장하지 않습니다. 토큰·메모·기기 정보는 여기 저장하지 않습니다.
const CACHE = 'byteback-offline-v1';
const OFFLINE_URL = '/offline.html';

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.add(new Request(OFFLINE_URL, { cache: 'reload' }))));
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) if (key !== CACHE) await caches.delete(key);
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.mode !== 'navigate') return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin || url.pathname.startsWith('/api/')) return;
  event.respondWith(fetch(request).catch(async () => (await caches.match(OFFLINE_URL))
    ?? new Response('오프라인입니다. 연결을 확인해 주세요.', { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' } })));
});
