/**
 * donseong-auth — Cloudflare Worker
 *
 * 역할: 앱인토스 토스 로그인의 토큰 교환 + 사용자 정보 복호화를 서버 사이드에서 처리
 *
 * 환경 변수 (wrangler secret put으로 등록):
 *   DECRYPTION_KEY  앱인토스 콘솔에서 발급한 Base64 AES-256 복호화 키
 */

const TOSS_API = 'https://apps-in-toss-api.toss.im';
// 앱인토스 WebView 내부 Origin은 CDN 주소라 사전에 알 수 없으므로 * 허용
// 보안은 Toss OAuth authorizationCode 검증으로 보장됨
const ALLOWED_ORIGIN = '*';

export default {
  async fetch(request, env) {
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

    if (!authorizationCode || !referrer) {
      return cors({ error: 'invalid_request', detail: 'authorizationCode and referrer required' }, 400);
    }

    // ── Step 1: authorizationCode → accessToken ──────────────────
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

    // ── Step 2: accessToken → 사용자 정보 ────────────────────────
    const userRes = await fetch(
      `${TOSS_API}/api-partner/v1/apps-in-toss/user/oauth2/login-me`,
      { headers: { Authorization: `Bearer ${accessToken}` } }
    );

    if (!userRes.ok) {
      return cors({ error: 'user_info_failed' }, 400);
    }

    const userInfo = await userRes.json();

    // ── Step 3: name 복호화 (AES-256-GCM, AAD = "TOSS") ────────
    let name = null;
    if (userInfo.name && env.DECRYPTION_KEY) {
      name = await decryptAesGcm(
        userInfo.name,
        env.DECRYPTION_KEY,
        'TOSS'   // 앱인토스 콘솔에서 확인된 고정 AAD값
      );
    }

    return cors({ userKey: userInfo.userKey, name });
  } catch (err) {
    return cors({ error: 'server_error', detail: err.message }, 500);
  }
}

/**
 * AES-256-GCM 복호화
 * @param {string} encryptedB64 - Base64 인코딩된 암호문 (IV 12바이트 + 암호문 + 태그)
 * @param {string} keyB64       - Base64 인코딩된 256비트 키
 * @param {string} aad          - 추가 인증 데이터 (보통 userKey)
 */
async function decryptAesGcm(encryptedB64, keyB64, aad) {
  const keyBytes = Uint8Array.from(atob(keyB64), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
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
