# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

배포가 끝나면 `/`에서 점령된 가상 자료실을 볼 수 있습니다. `/data.json`에는 같은 가상 메모가 공개됩니다. 이 공개 상태를 확인하는 것이 1단계의 출발점입니다. 1단계 접수와 심판 판정은 포털에서 확인합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 실제 배포가 된 뒤 `/data.json`을 비로그인으로 요청해 공개 가상 메모의 확인 표시를 읽습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.

## 2단계: 자료를 코드 밖으로 (2단계 기록)

가상 메모 네 건은 이제 코드·정적 파일이 아니라 학습용 Supabase 테이블 `notes`에 있습니다. 테이블은 `db/notes.sql`로 만들고, RLS를 켰으며 anon·authenticated에는 권한을 주지 않았습니다. 메모 자체는 SQL Editor에서 한 번 넣었고, 공개 저장소에는 메모 문장을 남기지 않았습니다. 화면(`public/index.html`)은 `/api/notes`(서버 함수 `api/notes.js`)를 통해서만 메모를 읽습니다. `data.json`과 `public/data.json`에는 메모가 없습니다(`"notes": []`).

### 다시 실행하는 방법

1. Supabase SQL Editor에서 `db/notes.sql`을 실행해 테이블을 만들고(이미 있으면 그대로 둡니다), 가상 메모는 SQL Editor에서 직접 입력합니다.
2. Vercel 프로젝트의 Settings > Environment Variables에 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`를 직접 입력합니다. 값은 코드·Git·채팅에 적지 않습니다.
3. 변경을 푸시하면 Vercel이 다시 배포합니다. 환경변수를 새로 넣었다면 Redeploy가 필요합니다.

### 2단계 당시 남은 약점 (3단계에서 로그인 확인으로 막음)

- 2단계의 `/api/notes`는 공개 주소여서 누구나 가상 메모를 읽을 수 있었습니다. 3단계에서 서버가 로그인 토큰을 검사하도록 바꿨습니다.
- 서버 전용 키는 이 함수만 환경변수로 읽습니다. 키를 브라우저 파일·응답·로그에 넣지 않습니다.

### 메모가 밖으로 새지 않았는지 확인하는 방법

배포 주소는 `https://choi-bujang-secret-vault-eight-psi.vercel.app`입니다. PowerShell에서 실행합니다.

1. 배포된 정적 파일: `/data.json`과 첫 화면 어디에도 메모 문장이 없어야 합니다. 메모 한 건에서 뽑은 짧은 단어를 `찾을단어` 자리에 넣어 검색합니다. 결과가 비어 있으면 통과입니다.

```powershell
curl.exe -s https://choi-bujang-secret-vault-eight-psi.vercel.app/data.json
curl.exe -s https://choi-bujang-secret-vault-eight-psi.vercel.app/ | Select-String "찾을단어"
```

2. GitHub 최신 파일: 저장소 폴더에서 메모 단어를 검색합니다. 아무것도 나오지 않으면 통과입니다.

```powershell
git grep -n "찾을단어"
```

3. 결과 기록 방법: 검색 결과(없음 또는 나온 파일 이름)와 아래 남은 약점을 각각 적어 둡니다. `npm run bundle`의 직접 점검 항목(`public_data_json_read`, `anonymous_api_read`)도 실제로 보낸 요청의 결과만 담습니다.

### 지난 공개 이력은 해소되지 않았습니다

옛 공개 커밋(`Initial commit`)과 1단계 때의 옛 배포에는 가상 메모가 그대로 남아 있습니다. 최신 파일에서 메모를 지웠다고 해서 과거에 노출된 사실이 없어지지는 않으므로, 과거 노출은 해소됐다고 볼 수 없습니다. 실제 자료였다면 이력 삭제와 키 교체가 따로 필요합니다.

### 2단계 기록의 남은 약점 정리

- 로그인 없이 `/api/notes`를 호출하는 약점은 3단계에서 막았습니다(아래 3단계 참고).
- 옛 공개 커밋과 옛 배포에는 가상 메모가 그대로 남아 있습니다.

## 3단계: 진짜 로그인을 붙입니다 (3단계 기록)

Supabase Auth 이메일·비밀번호 로그인과 로그아웃 화면이 있고, 서버가 요청의 로그인 토큰을 검사한 뒤에만 메모 API가 응답합니다. 로그인한 계정은 가상 메모를 추가·수정·삭제할 수 있습니다. 로그인 화면은 공식 SDK(`signInWithPassword`, `signOut`)만 쓰고, 비밀번호나 토큰을 직접 만들지 않습니다. 화면 코드에는 공개용 주소와 publishable 키만 있고 서버 전용 키는 없습니다.

### 3단계 당시 작동하던 기능

- 로그인하지 않으면 화면에 메모가 보이지 않고, 로그인하면 내 메모 목록과 새 메모 입력창이 나타납니다.
- 서버 함수는 틀이 준 `src/verify-login.mjs`로 `Authorization: Bearer` 토큰을 검사합니다. 토큰이 없거나 검사에 실패하면 자료 없이 `401`로 거부합니다.
- 소유자 ID(`owner_id`)는 서버가 검사한 토큰의 사용자 ID로만 저장합니다. 요청 본문에 보낸 `owner_id`, `userId`, `role`은 읽지 않습니다.
- 목록 GET은 로그인한 사용자의 메모만 배열로 돌려줍니다. 2단계에서 넣은 가상 메모 네 건은 소유자가 비어 있어 목록에 나오지 않습니다.

### API (실제 경로는 `aleph.config.json`의 `allowedRoutes`와 같습니다)

| 요청 | 하는 일 | 응답 |
|---|---|---|
| `GET /api/notes` | 로그인 사용자의 메모 목록 | `[{id,title,body}]` |
| `POST /api/notes` | 메모 추가. 본문 `{id?,title,body}` (`id`는 UUID, 없으면 서버가 만듭니다) | `201 {id}`, 같은 id면 `409` |
| `GET /api/notes/:id` | 메모 한 건 | `{id,title,body}`, 없으면 `404` |
| `PUT /api/notes/:id` | 메모 수정. 본문 `{title,body}` | `{id,title,body}` |
| `DELETE /api/notes/:id` | 메모 삭제 | `204`, 지운 뒤 GET은 `404` |

### 다시 실행하는 방법

1. Supabase SQL Editor에서 `db/notes.sql`의 권한 줄(`grant select, insert, update, delete ... to service_role`)을 실행합니다.
2. Supabase 대시보드 Authentication > Users에서 시험 계정을 만들고, 비밀번호는 코드·Git·채팅에 적지 않습니다.
3. Vercel 환경변수 `SUPABASE_URL`, `SUPABASE_SECRET_KEY`는 2단계에서 넣은 값을 그대로 씁니다.
4. 푸시하면 Vercel이 다시 배포합니다.

### 확인 방법

- 시크릿 창에서 배포 주소를 열면 메모가 보이지 않아야 합니다. `/api/notes`를 직접 열면 `401 LOGIN_REQUIRED`가 나옵니다.
- 시험 계정으로 로그인하면 메모를 추가·수정·삭제할 수 있어야 합니다.
- `npm run bundle`의 직접 점검은 로그인 없는 GET·POST·PUT·DELETE와 가짜 토큰이 거부되는지(상태 코드만) 기록합니다. 로그인 후 추가·수정·삭제는 비밀번호가 필요해 자동 점검에 포함하지 않았고 미실행으로 남겼습니다.

### 3단계 당시 남은 약점 (소유자 검사는 4단계에서 막음)

- 소유자 검사를 하지 않았습니다. `GET·PUT·DELETE /api/notes/:id`는 로그인한 사람이면 누구의 메모든 읽고 고치고 지울 수 있습니다. 예를 들어 B 계정이 A의 메모 id를 알면 접근할 수 있습니다. 4단계에서 소유자 검사를 붙일 예정입니다.
- 로그인 화면이 공식 SDK를 외부 배포망(jsdelivr)에서 버전을 고정해 불러옵니다.
- 옛 공개 커밋(`Initial commit`)과 1단계 때의 옛 배포에는 가상 메모가 그대로 남아 있습니다. 최신 파일에서 지웠다고 과거 노출이 해소된 것은 아닙니다.

## 4단계: 로그인해도 내 자료만 보이게 합니다 (4단계 기록)

로그인한 사람이라도 자기 메모만 읽고 추가·수정·삭제할 수 있습니다. 서버가 요청에 적힌 메모 번호를 믿지 않고, 매번 서버가 확인한 사용자 ID와 DB의 `owner_id`를 비교합니다. 이중으로, 학습 DB도 직접 접근할 때 본인 행만 허용합니다.

### 현재 작동하는 기능

- `GET /api/notes`는 내 메모만 돌려주고, `POST`는 `owner_id`를 항상 서버가 확인한 사용자 ID로 저장합니다.
- `GET·PUT·DELETE /api/notes/:id`는 `id`와 `owner_id`를 함께 조건으로 질의합니다. 남의 메모는 없는 메모와 같이 `404`로 거부하므로 그 번호가 있는지도 알 수 없습니다.
- 수정은 기존 행의 소유자가 본인일 때만 되고, 새 행의 `owner_id`도 본인 ID로 고정됩니다.
- 요청 본문에 본인과 다른 `owner_id`가 있으면 `403`으로 거부합니다. 응답 모양 `{id,title,body}`와 수정 본문 `{title,body}`는 그대로입니다.
- DB(`public.notes`): `anon`에는 권한이 없고, `authenticated`에는 SELECT·INSERT·UPDATE·DELETE만 있습니다. RLS 정책 4개가 모두 `auth.uid() = owner_id`일 때만 허용합니다(읽기·삭제는 기존 행, 추가는 새 행, 수정은 기존 행과 새 행 모두). 서버 함수는 `service_role`로 접근하며, 소유자 검사는 서버 코드가 합니다.
- 실제 경로는 `aleph.config.json`의 `allowedRoutes`와 같습니다: `GET·POST /api/notes`, `GET·PUT·DELETE /api/notes/:id`.

### 다시 실행하는 방법

1. Supabase SQL Editor에 `db/notes.sql` 전체를 붙여 넣고 Run 합니다(여러 번 실행해도 됩니다).
2. Authentication > Users에 시험 계정 둘(A, B)을 만들고, 비밀번호는 코드·Git·채팅에 적지 않습니다.
3. 기존 가상 메모를 A 소유로 연결하고 B 소유 시험 메모를 넣으려면, 계정 ID를 `auth.users`에서 이메일로 찾아 `owner_id`에 넣는 SQL을 SQL Editor에서 한 번 실행합니다(`db/notes.sql` 맨 아래 예시 참고).
4. Vercel 환경변수 `SUPABASE_URL`, `SUPABASE_SECRET_KEY`는 그대로 쓰고, 푸시하면 Vercel이 다시 배포합니다.

### 확인 방법

- A와 B로 각각 로그인하면 자기 메모만 보이고, 각자 추가·수정·삭제가 됩니다.
- B로 로그인한 탭의 개발자 도구 콘솔에서 A 메모의 번호로 읽기·수정·삭제를 요청하면 모두 `404`, 본문의 `owner_id`를 A의 ID로 바꿔 추가하면 `403`이 나옵니다. 끝난 뒤 A 화면의 메모는 그대로입니다.
- SQL Editor에서 `has_table_privilege`로 `anon`은 네 가지 모두 `false`, `authenticated`는 모두 `true`인지 확인합니다.
- `npm run bundle`의 직접 점검은 로그인 없는 요청 5건과 가짜 토큰, 공개용 키로 DB Data API를 직접 읽기·삭제하는 요청이 거부되는지(상태 코드만) 기록합니다. 계정 비밀번호·토큰이 필요한 A/B 정상 사용과 교차 접근은 자동 점검에서 보내지 않고 미실행으로 남겼습니다.

### 4단계 당시 남은 약점 (직접 접근 길은 5단계에서 닫음)

- 로그인한 사용자(authenticated)가 자기 토큰으로 학습 DB를 직접 부를 수 있었습니다(본인 행만).
- 로그인 화면이 공식 SDK를 외부 배포망(jsdelivr)에서 버전을 고정해 불러옵니다.
- 옛 공개 커밋(`Initial commit`)과 1단계 때의 옛 배포에는 가상 메모가 그대로 남아 있습니다. 최신 파일에서 지웠다고 과거 노출이 해소된 것은 아닙니다.
- 직접 Data API로 `authenticated` 역할이 본인 행을 접근하는 경우는 자동 점검 대상이 아닙니다(심판이 재현할 수 없어 점수에서 제외).

## 5단계: 자료 요청을 서버 한곳으로 모읍니다 (현재 상태)

브라우저의 메모 읽기·추가·수정·삭제는 모두 Vercel 서버 함수(`/api/notes`, `/api/notes/:id`)를 거칩니다. 학습 DB(`public.notes`)를 공개 키나 로그인 토큰으로 직접 부르는 길은 권한을 회수해서 닫았습니다.

### 현재 작동하는 기능

- 화면 코드(`public/index.html`)에는 Supabase 주소·키·SDK가 없습니다. 로그인(`POST /api/login`)·토큰 갱신(`POST /api/refresh`)·로그아웃(`POST /api/logout`)과 메모 요청 모두 같은 사이트의 서버 함수만 부릅니다. 서버 함수는 공식 SDK(`signInWithPassword`, `refreshSession`, `admin.signOut`)만 쓰고 비밀번호나 토큰을 직접 만들지 않습니다.
- 공개용(publishable) 키는 서버 환경변수 `SUPABASE_PUBLISHABLE_KEY`에만 있습니다. 로그인 세션은 이 브라우저에만 저장하고, 만료가 가까우면 서버 함수로 갱신합니다.
- 배포된 `/aleph.json`에 `allowedRoutes`가 함께 나옵니다(`scripts/deployment-identity.mjs`가 `aleph.config.json`의 값을 내보냅니다). 로그인·갱신·로그아웃 경로는 자료 API가 아니라서 `allowedRoutes`에 넣지 않았습니다.
- 서버 함수는 서버 전용 키(`service_role`)로 DB에 접근하고, 4단계의 로그인 검사와 소유자 검사(남의 메모 404, 소유자 변경 시도 403)를 그대로 유지합니다.
- `public.notes`에서 PUBLIC·`anon`·`authenticated`의 직접 권한을 모두 회수했습니다. 남은 것은 `service_role`뿐입니다. RLS와 정책 4개는 두 번째 방어선으로 남겨 두었습니다.
- `aleph.config.json`의 `originalApiUrl`에 쿼리 없는 원본 자료 경로(Supabase Data API의 `notes` 테이블 주소)를 적었습니다. 이 경로는 공개 키로 직접 부르면 거부되어야 합니다.
- 실제 서버 경로는 `allowedRoutes`와 같습니다: `GET·POST /api/notes`, `GET·PUT·DELETE /api/notes/:id`.

### 다시 실행하는 방법

1. Supabase SQL Editor에 `db/notes.sql` 전체를 붙여 넣고 Run 합니다(여러 번 실행해도 됩니다). 이미 만든 DB에서 권한만 거두려면 `revoke all on table public.notes from public, anon, authenticated;`만 실행해도 됩니다.
2. 시험 계정 둘(A, B)과 소유자 연결은 4단계 방법 그대로입니다. 비밀번호는 코드·Git·채팅에 적지 않습니다.
3. Vercel 환경변수 `SUPABASE_URL`, `SUPABASE_SECRET_KEY`는 그대로 쓰고, 새로 `SUPABASE_PUBLISHABLE_KEY`(Supabase의 공개용 키)를 Production에 추가합니다. 추가한 뒤에 푸시하면 Vercel이 다시 배포하면서 새 값을 씁니다. 이름은 정확히 `SUPABASE_PUBLISHABLE_KEY`여야 합니다. 철자가 다르면 로그인 함수가 `SERVER_NOT_CONFIGURED`(HTTP 500)로 답하고, `npm run bundle`의 `wrong_password_login` 점검이 401이 아니라 500으로 기록됩니다.

### 확인 방법

- 배포 주소 첫 화면의 소스(`Ctrl+U`)에서 `sb_`, `supabase`를 검색해도 나오지 않아야 하고, `/aleph.json`에 `allowedRoutes`가 있어야 합니다.
- SQL Editor에서 `has_table_privilege`로 `anon`·`authenticated`가 네 가지 모두 `false`인지, `role_table_grants`에 `service_role`만 남았는지 확인합니다.
- A와 B로 각각 로그인해서 새로고침 후 자기 메모만 보이고 추가·수정·삭제가 되는지 화면에서 확인합니다(5단계 뒤에도 다시 확인합니다).
- `npm run bundle`의 직접 점검은 로그인 없는 요청과 가짜 토큰이 거부되는지, 공개용 키로 원본 자료 경로(`originalApiUrl`)를 직접 조회·삭제하면 거부되는지를 상태 코드만 기록합니다. 계정 토큰이 필요한 정상 사용과 교차 접근은 미실행으로 남깁니다.

### 아직 남은 약점

- 로그인 요청이 모두 서버 함수를 거치므로, Supabase의 로그인 시도 제한이 사용자별이 아니라 서버 주소 기준으로 걸릴 수 있습니다. 학습용이라 별도 제한은 두지 않았습니다.
- 옛 공개 커밋(`Initial commit`)과 1단계 때의 옛 배포에는 가상 메모가 그대로 남아 있습니다. 최신 파일에서 지웠다고 과거 노출이 해소된 것은 아닙니다.
- 서버 전용 키가 유출되면 서버 함수의 검사와 상관없이 DB에 접근됩니다. 키는 Vercel 환경변수에만 두고 Git·로그에 남기지 않습니다.

## 보너스 xdr-01: 무차별 로그인 공격을 잡아 냅니다 (현재 상태)

`xdr/brute-force/`의 모듈이 수업용 Wazuh 모양 경보(`xdr/fixtures/brute-force.json`, 실제 로그가 아닙니다)를 읽어 `block`·`alert`·`record`로 나눕니다. 경보 원본은 고치지 않습니다.

### 현재 작동하는 기능

- `read-alerts.mjs`: 경보마다 시각·출발 주소·계정·규칙 수준·설명만 뽑습니다. 비밀값처럼 보이는 값은 `[가림]`으로 바꿉니다. 경보 건수와 뽑은 줄 수가 같아야 합니다.
- `patterns.json`: MITRE ATT&CK T1110(무차별 대입) 근거가 있는 패턴 3개(같은 주소·같은 계정의 로그인 실패 연속, 여러 계정에 같은 비밀번호 대입, 실패 뒤 성공)입니다. 패턴마다 근거 한 줄과 출처가 있습니다.
- `decide.mjs`: `decide(alert)`가 패턴과 규칙 수준으로 나눕니다. 명확하면 `block`, 정상이면 `record`이고 애매한 경보만 Jev 확신도(0.85 이상 `block`, 0.5 이상 `alert`, 그 아래 `record`)로 나눕니다. Jev가 응답하지 않으면 `alert`입니다. Jev 연결은 `configureJev()`로 하며 지금은 연결되어 있지 않습니다. 명확한 공격은 규칙 수준 10 이상이거나(패턴이 맞고) 실패 15건 이상이고, 규칙 수준 5 미만은 정상입니다. 이 경계는 MITRE가 정한 값이 아니라 연습 경보의 분포에 맞춘 값이며 `decide.mjs` 위쪽 상수(`CLEAR_LEVEL`, `NORMAL_BELOW`, `CLEAR_COUNT`)로 바꿉니다. `decide.mjs`는 다른 파일을 불러오지 않고 혼자 동작합니다.
- `block-rules.mjs`, `replay.mjs`: 차단 후보만 만료 시각(기본 1시간)과 근거 경보 번호가 붙은 규칙으로 만들고, 알림을 `xdr/alerts.log`에 한 줄씩 쌓습니다. 같은 주소에 정상 이벤트가 있으면 차단을 보류합니다. `src/decider.mjs`는 고치지 않았고, 아직 판정기에 연결하지 않았습니다. 판정기 요청 계약에 출발 주소가 없어서, 운영 엔진이 주소를 제공하는 계약이 생긴 뒤 `isBlocked()`를 확인 단계로 붙일 수 있습니다.

### 다시 실행하는 방법

```
npm run xdr:run -- brute-force
node xdr/brute-force/read-alerts.mjs
node xdr/brute-force/replay.mjs
```

`xdr:run`은 `xdr/brute-force/result.json`을 씁니다. 정상이면 `counts`가 `block 10 · alert 9 · record 9`이고 정상 이벤트를 `block`한 경우가 없어야 합니다. `replay.mjs`는 `xdr/block-rules.json`과 `xdr/alerts.log`를 만들며, 마지막 줄이 `막힘 10 · 통과 18 · 판단과 다른 결과 0 · 만료 규칙 오류 0`이어야 합니다.

### 아직 남은 약점

- Jev(확신도를 주는 쪽)와 판정기에 연결하지 않아서, 지금은 애매한 경보가 모두 `alert`이고 규칙이 실제 접속을 막지는 않습니다.
- 위 시험은 가상 경보 28건에 대한 연습이며 실제 공격 차단이나 심판 판정이 아닙니다.
