// 내 자료실 화면 스크립트입니다(public/index.html이 불러옴).
// 로그인 토큰과 기기 증표는 서버가 HttpOnly 쿠키로만 두므로 이 스크립트는 읽을 수 없고, 브라우저 저장소도 쓰지 않습니다.
// 화면은 이메일과 만료 시각만 메모리에 두며, 기기 승인 여부는 서버(/api/device)가 정합니다.
let session = null; // { expires_at, email } — 토큰 없음

const form = document.querySelector('#login-form');
const emailInput = document.querySelector('#email');
const passwordInput = document.querySelector('#password');
const loginButton = document.querySelector('#login-button');
const signedIn = document.querySelector('#signed-in');
const signedInText = document.querySelector('#signed-in-text');
const logoutButton = document.querySelector('#logout-button');
const authTitle = document.querySelector('#auth-title');
const authError = document.querySelector('#auth-error');

function showError(message) {
  authError.textContent = message;
  authError.hidden = !message;
}

function reasonFor(code) {
  const reasons = {
    INVALID_LOGIN: '이메일 또는 비밀번호가 맞지 않습니다.',
    EMAIL_NOT_CONFIRMED: '이메일 확인이 끝나지 않은 계정입니다.',
    RATE_LIMITED: '요청이 너무 많습니다. 잠시 뒤에 다시 시도해 주세요.',
    USER_BANNED: '이용이 제한된 계정입니다.',
    SERVER_NOT_CONFIGURED: '서버 설정이 끝나지 않았습니다.',
    AUTH_UNAVAILABLE: '로그인 서버에 연결하지 못했습니다. 잠시 뒤에 다시 시도해 주세요.',
  };
  return reasons[code] ?? '로그인에 실패했습니다.';
}

function setSession(next) {
  session = next && typeof next.expires_at === 'number' ? { expires_at: next.expires_at, email: next.email ?? null } : null;
}

function render() {
  const loggedIn = Boolean(session);
  form.hidden = loggedIn;
  signedIn.hidden = !loggedIn;
  authTitle.textContent = loggedIn ? '로그인됨' : '로그인';
  signedInText.textContent = loggedIn ? `${session.email ?? '알 수 없는 계정'} 계정으로 로그인했습니다.` : '';
}

async function postJson(path, payload) {
  return fetch(path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
    cache: 'no-store', body: JSON.stringify(payload ?? {}),
  });
}

let refreshing = null;
function refreshSession() {
  refreshing ??= (async () => {
    try {
      const response = await postJson('/api/refresh', {});
      if (response.ok) setSession(await response.json());
      else if (response.status === 401) setSession(null);
    } catch { }
    return session;
  })().finally(() => { refreshing = null; });
  return refreshing;
}

async function currentSession() {
  if (!session) return null;
  if (session.expires_at - Date.now() / 1000 > 60) return session;
  return refreshSession();
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  showError('');
  loginButton.disabled = true;
  try {
    const response = await postJson('/api/login', { email: emailInput.value.trim(), password: passwordInput.value });
    if (response.ok) {
      setSession(await response.json());
      setDevice({ status: 'checking' });
      render();
      await loadNotes();
    } else {
      let code = null;
      try { code = (await response.json()).error; } catch { }
      showError(reasonFor(code));
    }
  } catch {
    showError('로그인 서버에 연결하지 못했습니다. 네트워크를 확인해 주세요.');
  } finally {
    passwordInput.value = '';
    loginButton.disabled = false;
  }
});

logoutButton.addEventListener('click', async () => {
  showError('');
  logoutButton.disabled = true;
  try {
    await postJson('/api/logout', {});
  } catch { }
  setSession(null);
  setDevice({ status: 'signed_out' });
  render();
  await loadNotes();
  logoutButton.disabled = false;
});

const list = document.querySelector('#notes');
const composer = document.querySelector('#composer');
const noteForm = document.querySelector('#note-form');
const noteTitle = document.querySelector('#note-title');
const noteBody = document.querySelector('#note-body');
const noteAdd = document.querySelector('#note-add');
const notesError = document.querySelector('#notes-error');
let loadId = 0;

function showNotesError(message) {
  notesError.textContent = message;
  notesError.hidden = !message;
}

function showMessage(text) {
  const item = document.createElement('li');
  item.textContent = text;
  list.replaceChildren(item);
}

async function api(method, path, payload) {
  let current = await currentSession();
  if (!current) throw new Error('로그인이 필요합니다.');
  const send = () => fetch(path, {
    method, credentials: 'same-origin', cache: 'no-store',
    headers: payload === undefined ? {} : { 'Content-Type': 'application/json' },
    body: payload === undefined ? undefined : JSON.stringify(payload),
  });
  let response = await send();
  if (response.status === 401) {
    current = await refreshSession();
    if (current) response = await send();
  }
  if (response.status === 401) {
    setSession(null);
    render();
    throw new Error('로그인이 확인되지 않았습니다. 다시 로그인해 주세요.');
  }
  if (response.status === 403) {
    let body = null;
    try { body = await response.json(); } catch { }
    if (body?.error === 'DEVICE_NOT_APPROVED') {
      setDevice({ status: typeof body.device === 'string' ? body.device : 'none' });
      throw new Error('승인된 기기에서만 자료를 볼 수 있습니다.');
    }
    throw new Error('요청이 거부되었습니다.');
  }
  if (response.status === 404) throw new Error('메모를 찾을 수 없습니다.');
  if (response.status === 400) throw new Error('입력을 확인해 주세요. 제목은 1~100자, 내용은 2000자 이하여야 합니다.');
  if (!response.ok) throw new Error('서버 요청에 실패했습니다.');
  return response.status === 204 ? null : response.json();
}

function button(label, className, onClick) {
  const el = document.createElement('button');
  el.type = 'button';
  el.textContent = label;
  if (className) el.className = className;
  el.addEventListener('click', onClick);
  return el;
}

function noteItem(note) {
  const item = document.createElement('li');
  const title = document.createElement('strong');
  const body = document.createElement('span');
  body.className = 'note-body';
  title.textContent = note.title;
  body.textContent = note.body;
  const actions = document.createElement('div');
  actions.className = 'note-actions';
  actions.append(
    button('수정', 'secondary', () => item.replaceWith(editItem(note))),
    button('삭제', 'danger', async (event) => {
      event.currentTarget.disabled = true;
      showNotesError('');
      try {
        await api('DELETE', `/api/notes/${note.id}`);
        await loadNotes();
      } catch (error) {
        showNotesError(error.message);
        event.currentTarget.disabled = false;
      }
    }),
  );
  item.append(title, body, actions);
  return item;
}

function editItem(note) {
  const item = document.createElement('li');
  const form = document.createElement('form');
  form.className = 'note-edit';
  const titleLabel = document.createElement('label');
  titleLabel.textContent = '제목';
  const titleInput = document.createElement('input');
  titleInput.type = 'text';
  titleInput.maxLength = 100;
  titleInput.required = true;
  titleInput.value = note.title;
  titleLabel.append(titleInput);
  const bodyLabel = document.createElement('label');
  bodyLabel.textContent = '내용';
  const bodyInput = document.createElement('textarea');
  bodyInput.maxLength = 2000;
  bodyInput.value = note.body;
  bodyLabel.append(bodyInput);
  const row = document.createElement('div');
  row.className = 'row';
  const save = document.createElement('button');
  save.type = 'submit';
  save.textContent = '저장';
  row.append(save, button('취소', 'secondary', () => item.replaceWith(noteItem(note))));
  form.append(titleLabel, bodyLabel, row);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    save.disabled = true;
    showNotesError('');
    try {
      await api('PUT', `/api/notes/${note.id}`, { title: titleInput.value, body: bodyInput.value });
      await loadNotes();
    } catch (error) {
      showNotesError(error.message);
      save.disabled = false;
    }
  });
  item.append(form);
  return item;
}

async function loadNotes() {
  const mine = ++loadId;
  composer.hidden = true;
  if (!session) {
    setDevice({ status: 'signed_out' });
    showNotesError('');
    showMessage('로그인하면 가상 메모를 볼 수 있습니다.');
    return;
  }
  if (device.status !== 'approved') await checkDevice();
  if (mine !== loadId) return;
  if (device.status !== 'approved') {
    list.replaceChildren();
    showNotesError('');
    showMessage(LOCKED_TEXT[device.status] ?? LOCKED_TEXT.none);
    return;
  }
  composer.hidden = false;
  try {
    const notes = await api('GET', '/api/notes');
    if (mine !== loadId) return;
    if (!Array.isArray(notes)) throw new Error('자료 형식이 맞지 않습니다.');
    if (!notes.length) {
      showMessage('내 메모가 없습니다. 위에서 추가해 보세요.');
      return;
    }
    list.replaceChildren(...notes.map(noteItem));
  } catch (error) {
    if (mine === loadId) {
      composer.hidden = !(session && device.status === 'approved');
      if (device.status !== 'approved') list.replaceChildren();
      showMessage(error.message);
    }
  }
}

noteForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  noteAdd.disabled = true;
  showNotesError('');
  try {
    await api('POST', '/api/notes', { title: noteTitle.value, body: noteBody.value });
    noteTitle.value = '';
    noteBody.value = '';
    await loadNotes();
  } catch (error) {
    showNotesError(error.message);
  } finally {
    noteAdd.disabled = false;
  }
});

const deviceApproval = document.querySelector('#device-approval');
const deviceCodeLabel = document.querySelector('#device-code-label');
const deviceCode = document.querySelector('#device-code');
const deviceActions = document.querySelector('#device-actions');
const deviceRequest = document.querySelector('#device-request');
const deviceRefresh = document.querySelector('#device-refresh');
const deviceHelp = document.querySelector('#device-help');
let device = { status: 'signed_out' };
const DEVICE_TEXT = {
  signed_out: '로그인하면 서버에 이 기기의 승인 상태를 묻습니다',
  checking: '서버에 확인하는 중입니다',
  none: '미등록 · 이 기기는 승인 요청 전입니다',
  pending: '승인 대기 · 서버가 아직 이 기기를 승인하지 않았습니다',
  approved: '승인됨 · 서버가 이 기기를 등록 기기로 확인했습니다',
  revoked: '회수됨 · 이 기기의 승인이 취소되었습니다',
  error: '확인 실패 · 서버에 연결하지 못해 자료를 열지 않습니다',
};
const LOCKED_TEXT = {
  none: '이 기기는 아직 승인되지 않아 자료를 표시하지 않습니다. 위에서 기기 승인을 요청해 주세요.',
  pending: '승인 대기 중이라 자료를 표시하지 않습니다. 관리자가 확인 코드로 승인한 뒤 「승인 상태 다시 확인」을 눌러 주세요.',
  revoked: '이 기기의 승인이 회수되어 자료를 표시하지 않습니다. 관리자에게 문의해 주세요.',
  error: '서버에서 기기 승인 상태를 확인하지 못해 자료를 표시하지 않습니다. 잠시 뒤 「승인 상태 다시 확인」을 눌러 주세요.',
};
function setDevice(next) {
  device = next;
  deviceApproval.textContent = DEVICE_TEXT[device.status] ?? DEVICE_TEXT.none;
  const showCode = device.status === 'pending' && typeof device.code === 'string';
  deviceCode.textContent = showCode ? device.code : '';
  deviceCode.hidden = deviceCodeLabel.hidden = !showCode;
  const canAct = Boolean(session) && ['none', 'pending', 'revoked', 'error'].includes(device.status);
  deviceActions.hidden = !canAct;
  deviceRequest.hidden = device.status !== 'none';
  deviceHelp.hidden = !(canAct && device.status !== 'revoked');
  if (device.status !== 'approved') composer.hidden = true;
}
async function checkDevice() {
  if (!session) { setDevice({ status: 'signed_out' }); return; }
  setDevice({ status: 'checking' });
  try {
    const result = await api('GET', '/api/device');
    setDevice(result && typeof result.status === 'string' ? result : { status: 'error' });
  } catch {
    if (device.status === 'checking') setDevice({ status: session ? 'error' : 'signed_out' });
  }
}
deviceRequest.addEventListener('click', async () => {
  deviceRequest.disabled = true;
  showNotesError('');
  try {
    const result = await api('POST', '/api/device');
    setDevice(result && typeof result.status === 'string' ? result : { status: 'error' });
  } catch (error) {
    showNotesError(error.message);
  } finally {
    deviceRequest.disabled = false;
  }
  await loadNotes();
});
deviceRefresh.addEventListener('click', async () => {
  deviceRefresh.disabled = true;
  await checkDevice();
  await loadNotes();
  deviceRefresh.disabled = false;
});

const deviceInstall = document.querySelector('#device-install');
const standalone = window.matchMedia('(display-mode: standalone)');
function renderInstall() {
  const installed = standalone.matches || window.navigator.standalone === true;
  deviceInstall.textContent = installed
    ? '앱 화면으로 열림 (설치 여부는 기기 승인이 아닙니다)'
    : '브라우저 탭으로 열림 (설치 여부는 기기 승인이 아닙니다)';
}
standalone.addEventListener?.('change', renderInstall);
renderInstall();

const offlineBanner = document.querySelector('#offline-banner');
function renderOnline() { offlineBanner.hidden = navigator.onLine; }
window.addEventListener('offline', renderOnline);
window.addEventListener('online', () => { renderOnline(); loadNotes(); });
renderOnline();

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {});
}

session = null;
await refreshSession();
render();
await loadNotes();
  
