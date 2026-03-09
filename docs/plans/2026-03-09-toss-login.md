# 토스로 로그인 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 돈성 앱에 `appLogin()` SDK를 통한 토스 로그인을 추가해 결과 화면에서 이름을 개인화하고 userKey를 확보한다.

**Architecture:**
- **Frontend** — `src/login.js` 모듈이 SDK `appLogin()`을 호출해 authorizationCode를 얻고, Cloudflare Worker로 전달한다.
- **Backend** — Cloudflare Worker(`worker/index.js`)가 Toss Partner API로 토큰 교환 → `/login-me` 호출 → AES-256-GCM 복호화 → `{ userKey, name }` 반환.
- **UI** — 랜딩 페이지에 선택적(비차단) 로그인 버튼 추가. 로그인 시 결과 화면에 이름 표시.

**Tech Stack:** Cloudflare Workers (Web Crypto API), `@apps-in-toss/web-framework` SDK v2, Vite, vanilla JS

---

## 사전 조건 — 콘솔 설정 (개발자가 수동으로)

앱인토스 콘솔(https://apps-in-toss.toss.im) 에서 아래를 완료해야 한다:

1. **토스 로그인 약관 동의** — 대표 계정 관리자만 가능
2. **동의 항목(Scope) 설정** — `name` 체크 (이름 표시용)
3. **약관 등록** — 서비스 이용약관 URL, 개인정보처리방침 URL 등록
4. **복호화 키 저장** — 콘솔에서 발급된 Base64 복호화 키를 복사해 둔다 (`DECRYPTION_KEY` 시크릿으로 사용)

---

## Task 1: Cloudflare Worker 생성

**Files:**
- Create: `worker/index.js`
- Create: `worker/wrangler.toml`

**Step 1: wrangler.toml 작성**

```toml
# worker/wrangler.toml
name = "donseong-auth"
main = "index.js"
compatibility_date = "2024-09-23"

# 시크릿은 CLI로 등록: wrangler secret put DECRYPTION_KEY
# DECRYPTION_KEY: 앱인토스 콘솔에서 발급받은 Base64 복호화 키
```

**Step 2: worker/index.js 작성**

```javascript
// worker/index.js
const TOSS_API = 'https://apps-in-toss-api.toss.im';
const ALLOWED_ORIGIN = 'https://grinbi-snap.github.io';

export default {
  async fetch(request, env) {
    // CORS preflight
    if (request.method === 'OPTIONS') {
      return cors(null, 204);
    }

    const { pathname } = new URL(request.url);

    if (pathname === '/login' && request.method === 'POST') {
      return handleLogin(request, env);
    }

    return new Response('Not Found', { status: 404 });
  },
};

async function handleLogin(request, env) {
  try {
    const { authorizationCode, referrer } = await request.json();

    // 1. authorizationCode → accessToken
    const tokenRes = await fetch(
      `${TOSS_API}/api-partner/v1/apps-in-toss/user/oauth2/generate-token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ authorizationCode, referrer }),
      }
    );

    if (!tokenRes.ok) {
      const detail = await tokenRes.text();
      return cors({ error: 'token_failed', detail }, 400);
    }

    const { accessToken } = await tokenRes.json();

    // 2. accessToken → 사용자 정보 (암호화된 상태)
    const userRes = await fetch(
      `${TOSS_API}/api-partner/v1/apps-in-toss/user/oauth2/login-me`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    if (!userRes.ok) {
      return cors({ error: 'user_info_failed' }, 400);
    }

    const userInfo = await userRes.json();

    // 3. name 복호화 (AES-256-GCM, IV = 앞 12바이트)
    let name = null;
    if (userInfo.name && env.DECRYPTION_KEY) {
      name = await decryptAesGcm(userInfo.name, env.DECRYPTION_KEY, String(userInfo.userKey));
    }

    return cors({ userKey: userInfo.userKey, name });
  } catch (err) {
    return cors({ error: err.message }, 500);
  }
}

async function decryptAesGcm(encryptedB64, keyB64, aad) {
  const keyBytes = Uint8Array.from(atob(keyB64), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']
  );

  const cipher = Uint8Array.from(atob(encryptedB64), (c) => c.charCodeAt(0));
  const iv = cipher.slice(0, 12);
  const data = cipher.slice(12);

  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(aad) },
    key,
    data
  );
  return new TextDecoder().decode(plain);
}

function cors(body, status = 200) {
  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
  return new Response(body != null ? JSON.stringify(body) : null, { status, headers });
}
```

**Step 3: Wrangler CLI 설치 & 배포**

```bash
# 설치
npm install -g wrangler

# 로그인 (Cloudflare 계정 필요, 무료)
wrangler login

# Worker 배포
cd /Users/ihyeon-yong/donseong/worker
wrangler deploy

# 복호화 키 시크릿 등록 (콘솔에서 발급한 Base64 키를 붙여넣기)
wrangler secret put DECRYPTION_KEY
```

배포 후 출력되는 URL 확인:
```
https://donseong-auth.<YOUR-SUBDOMAIN>.workers.dev
```

**Step 4: 커밋**

```bash
cd /Users/ihyeon-yong/donseong
git add worker/
git commit -m "feat: add Cloudflare Worker for Toss login backend"
```

---

## Task 2: Frontend SDK 브리지 모듈

**Files:**
- Create: `src/login.js`

**Step 1: src/login.js 작성**

```javascript
// src/login.js
// Vite가 이 파일을 번들링해 @apps-in-toss/web-framework의 appLogin을 사용 가능하게 함

import {
  appLogin,
  getIsTossLoginIntegratedService,
} from '@apps-in-toss/web-framework';

// Worker 배포 후 실제 URL로 교체
const WORKER_URL = 'https://donseong-auth.<YOUR-SUBDOMAIN>.workers.dev';

/**
 * 토스 로그인 실행 → { userKey, name } 반환
 * 앱인토스(Toss WebView) 환경에서만 동작
 */
window.__tossLogin = async function () {
  const { authorizationCode, referrer } = await appLogin();

  const res = await fetch(`${WORKER_URL}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ authorizationCode, referrer }),
  });

  if (!res.ok) throw new Error('로그인에 실패했어요. 다시 시도해 주세요.');

  return res.json(); // { userKey: string, name: string | null }
};

window.__isTossLoginAvailable = getIsTossLoginIntegratedService;
```

**Step 2: Vite entry로 등록 — index.html `<head>` 안에 추가**

```html
<!-- 기존 <script> 태그 바로 위에 추가 -->
<script type="module" src="/src/login.js"></script>
```

---

## Task 3: index.html — 로그인 버튼 & 개인화 UI

**Files:**
- Modify: `index.html`

**Step 1: CSS 추가 (기존 `<style>` 블록 안 맨 아래)**

```css
/* ── 토스 로그인 ───────────────────────── */
.login-wrap {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  margin-top: 12px;
}

.btn-toss-login {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  background: #3182f6;
  color: #fff;
  border: none;
  border-radius: 12px;
  font-size: 15px;
  font-weight: 700;
  cursor: pointer;
  width: 100%;
  justify-content: center;
}

.btn-toss-login:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.login-skip {
  font-size: 13px;
  color: var(--gray-400);
  background: none;
  border: none;
  cursor: pointer;
  text-decoration: underline;
}

.user-greeting {
  font-size: 18px;
  font-weight: 700;
  color: var(--gray-900);
  text-align: center;
  margin-bottom: 4px;
}
```

**Step 2: 랜딩 화면(#screen-landing)에 로그인 블록 추가**

기존 시작 버튼 아래에 추가:

```html
<!-- 로그인 블록 — 랜딩 화면 안, 기존 .landing-cta 아래 -->
<div class="login-wrap" id="loginWrap">
  <button class="btn-toss-login" id="btnTossLogin" onclick="handleTossLogin()">
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="12" fill="white" opacity="0.2"/>
      <path d="M8 12h8M12 8v8" stroke="white" stroke-width="2" stroke-linecap="round"/>
    </svg>
    토스로 로그인하기
  </button>
  <button class="login-skip" onclick="skipLogin()">로그인 없이 시작하기</button>
</div>
```

**Step 3: 결과 화면 상단에 인사말 추가**

결과 화면 `#screen-result`의 `.result-header` 안 `<h2>` 바로 위:

```html
<p class="user-greeting" id="userGreeting" style="display:none"></p>
```

**Step 4: JS 함수 추가 (기존 `<script>` 블록 안)**

```javascript
// ── 토스 로그인 ──────────────────────────────────
let tossUser = null; // { userKey, name }

async function handleTossLogin() {
  const btn = document.getElementById('btnTossLogin');
  btn.disabled = true;
  btn.textContent = '로그인 중...';

  try {
    if (typeof window.__tossLogin !== 'function') {
      throw new Error('토스 앱 환경에서만 로그인할 수 있어요.');
    }
    tossUser = await window.__tossLogin();
    sessionStorage.setItem('tossUser', JSON.stringify(tossUser));

    // 로그인 블록 숨기기 & 피드백
    document.getElementById('loginWrap').style.display = 'none';
    const name = tossUser.name || '고객';
    showToast(`${name}님, 반가워요!`);
  } catch (err) {
    alert(err.message);
    btn.disabled = false;
    btn.textContent = '토스로 로그인하기';
  }
}

function skipLogin() {
  document.getElementById('loginWrap').style.display = 'none';
}

function showToast(msg) {
  const t = document.createElement('div');
  t.textContent = msg;
  Object.assign(t.style, {
    position: 'fixed', bottom: '32px', left: '50%',
    transform: 'translateX(-50%)', background: '#111827',
    color: '#fff', padding: '10px 20px', borderRadius: '20px',
    fontSize: '14px', zIndex: '9999', whiteSpace: 'nowrap',
  });
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2500);
}

// showResult() 안에서 개인화 인사말 주입
// 기존 showResult() 함수 내부 맨 앞에 아래 코드 삽입:
//
//   const saved = sessionStorage.getItem('tossUser');
//   if (saved) {
//     tossUser = JSON.parse(saved);
//     const el = document.getElementById('userGreeting');
//     const name = tossUser.name || '';
//     if (name) { el.textContent = `${name}님의 소비 유형은?`; el.style.display = 'block'; }
//   }
```

> **주의:** `showResult()` 함수 내부 맨 앞에 위의 sessionStorage 복원 코드를 직접 삽입해야 한다. (주석으로만 표기한 이유는 기존 함수 라인을 파악한 후 정확히 삽입하기 위함)

**Step 5: 커밋**

```bash
git add src/ index.html
git commit -m "feat: add Toss login UI and SDK bridge"
```

---

## Task 4: granite.config.ts 업데이트

`permissions` 배열은 토스 로그인에 해당하지 않는다 (기기 권한 전용). 변경 불필요.

단, Vite가 `src/login.js`를 인식하도록 `index.html`에 `<script type="module" src="/src/login.js"></script>` 태그가 있는지 확인한다.

---

## Task 5: 빌드 & 배포

**Step 1: Worker URL을 src/login.js에 반영**

`WORKER_URL` 상수를 실제 Workers.dev URL로 교체:

```javascript
const WORKER_URL = 'https://donseong-auth.YOUR-SUBDOMAIN.workers.dev';
```

**Step 2: .ait 빌드**

```bash
cd /Users/ihyeon-yong/donseong
npx ait build
```

기대 출력:
```
◆  AIT build completed (donseong.ait)
●  deploymentId: ...
```

**Step 3: GitHub Pages 배포**

```bash
git add donseong.ait
git commit -m "build: rebuild .ait with Toss login"
git push origin main
```

**Step 4: 앱인토스 콘솔에서 새 버전 업로드**

1. 앱인토스 콘솔 → 버전 등록 → `donseong.ait` 업로드
2. 테스트 → 검토 요청

---

## QA 체크리스트 (docs 기준)

- [ ] 처음 로그인 시 약관 동의 화면 뜨고, 완료 후 결과로 돌아옴
- [ ] 재방문 시 약관 동의 없이 즉시 로그인됨
- [ ] 이름이 결과 화면 상단에 "OO님의 소비 유형은?" 형태로 표시됨
- [ ] 로그인 없이 시작하기 클릭 시 정상 진행됨
- [ ] 토스 앱 밖(GitHub Pages 직접 접근)에서 로그인 버튼 클릭 시 에러 메시지 표시
- [ ] Worker URL이 잘못된 경우 alert 표시됨

---

## 참고 링크

- [토스 로그인 개요](https://developers-apps-in-toss.toss.im/login/intro.html)
- [콘솔 설정](https://developers-apps-in-toss.toss.im/login/console.html)
- [개발 가이드](https://developers-apps-in-toss.toss.im/login/develop.html)
- [QA 가이드](https://developers-apps-in-toss.toss.im/login/qa.html)
