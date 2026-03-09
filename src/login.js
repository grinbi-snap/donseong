/**
 * src/login.js — 토스 로그인 SDK 브리지
 *
 * Vite가 이 파일을 번들링해 @apps-in-toss/web-framework의 appLogin을 사용 가능하게 함.
 * 빌드 후 window.__tossLogin() / window.__isTossLoginAvailable() 으로 호출 가능.
 *
 * ⚠️  Worker 배포 후 WORKER_URL을 실제 URL로 교체해야 함.
 */

import {
  appLogin,
  getIsTossLoginIntegratedService,
} from '@apps-in-toss/web-framework';

// ── Cloudflare Worker URL ─────────────────────────────────────────────
// wrangler deploy 후 출력된 URL로 교체: https://donseong-auth.XXX.workers.dev
const WORKER_URL = 'https://donseong-auth.grinbi.workers.dev';

/**
 * 토스 로그인 실행
 * @returns {Promise<{ userKey: string, name: string | null }>}
 */
// 진단용: appLogin() 단독 호출 (handleTossLogin에서 단계별 사용)
window.__appLoginRaw = () => appLogin();

window.__tossLogin = async function () {
  const { authorizationCode, referrer } = await appLogin();

  const res = await fetch(`${WORKER_URL}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ authorizationCode, referrer }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || '로그인에 실패했어요. 다시 시도해 주세요.');
  }

  return res.json();
};

/**
 * 현재 환경이 토스 로그인 연동 서비스인지 확인
 * @returns {Promise<boolean>}
 */
window.__isTossLoginAvailable = getIsTossLoginIntegratedService;
