/**
 * Farasdanga API — Cloudflare Worker
 * A free public directory (no login needed to browse or call) plus one paid
 * feature: businesses can pay to post an ad, which the admin approves.
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try {
      if (url.pathname.startsWith('/api/')) return await router(request, env, url);
      return env.ASSETS.fetch(request);
    } catch (err) {
      return json({ error: 'Server error', detail: String(err) }, 500);
    }
  }
};

/* ============================== ROUTER ============================== */
async function router(request, env, url) {
  const { pathname } = url;
  const method = request.method;

  // ---- Public: browse ----
  if (pathname === '/api/categories' && method === 'GET') return listCategories(env);
  if (pathname === '/api/providers' && method === 'GET') return listProviders(env);
  if (pathname === '/api/ads' && method === 'GET') return listAds(env);
  if (pathname === '/api/ad-plans' && method === 'GET') return listAdPlans(env);
  if (pathname === '/api/settings' && method === 'GET') return getSettings(env);

  // ---- Public: free provider suggestion (no login, no payment) ----
  if (pathname === '/api/providers/suggest' && method === 'POST') return suggestProvider(request, env);

  // ---- Public: paid ad flow ----
  if (pathname === '/api/ads/create-order' && method === 'POST') return createAdOrder(request, env);
  if (pathname === '/api/ads/verify-payment' && method === 'POST') return verifyAdPayment(request, env);
  if (pathname.match(/^\/api\/ads\/\d+\/impression$/) && method === 'POST') return recordAdEvent(env, idFromPath(pathname), 'impressions');
  if (pathname.match(/^\/api\/ads\/\d+\/click$/) && method === 'POST') return recordAdEvent(env, idFromPath(pathname), 'clicks');

  // ---- Admin ----
  if (pathname === '/api/admin/login' && method === 'POST') return adminLogin(request, env);
  if (pathname === '/api/admin/logout' && method === 'POST') return adminLogout(request, env);
  if (pathname === '/api/admin/diagnostics' && method === 'GET') return adminOnly(request, env, adminDiagnostics);
  if (pathname === '/api/admin/dashboard' && method === 'GET') return adminOnly(request, env, adminDashboard);
  if (pathname === '/api/admin/providers' && method === 'GET') return adminOnly(request, env, adminListProviders);
  if (pathname === '/api/admin/providers' && method === 'POST') return adminOnly(request, env, (r, e) => adminSaveProvider(r, e, null));
  if (pathname.match(/^\/api\/admin\/providers\/\d+$/) && method === 'PUT') return adminOnly(request, env, (r, e) => adminSaveProvider(r, e, idFromPath(pathname)));
  if (pathname.match(/^\/api\/admin\/providers\/\d+$/) && method === 'DELETE') return adminOnly(request, env, () => adminDeleteProvider(env, idFromPath(pathname)));
  if (pathname.match(/^\/api\/admin\/providers\/\d+\/approve$/) && method === 'POST') return adminOnly(request, env, () => adminApproveProvider(env, idFromPath(pathname)));
  if (pathname.match(/^\/api\/admin\/providers\/\d+\/reject$/) && method === 'POST') return adminOnly(request, env, () => adminRejectProvider(env, idFromPath(pathname)));
  if (pathname === '/api/admin/categories' && method === 'POST') return adminOnly(request, env, adminSaveCategory);
  if (pathname.match(/^\/api\/admin\/categories\/\d+$/) && method === 'DELETE') return adminOnly(request, env, () => adminDeleteCategory(env, idFromPath(pathname)));
  if (pathname === '/api/admin/ads' && method === 'GET') return adminOnly(request, env, adminListAds);
  if (pathname.match(/^\/api\/admin\/ads\/\d+$/) && method === 'PUT') return adminOnly(request, env, (r, e) => adminUpdateAd(r, e, idFromPath(pathname)));
  if (pathname.match(/^\/api\/admin\/ads\/\d+\/approve$/) && method === 'POST') return adminOnly(request, env, () => adminApproveAd(env, idFromPath(pathname)));
  if (pathname.match(/^\/api\/admin\/ads\/\d+\/reject$/) && method === 'POST') return adminOnly(request, env, () => adminRejectAd(env, idFromPath(pathname)));
  if (pathname.match(/^\/api\/admin\/ads\/\d+$/) && method === 'DELETE') return adminOnly(request, env, () => adminDeleteAd(env, idFromPath(pathname)));
  if (pathname === '/api/admin/settings' && method === 'POST') return adminOnly(request, env, adminSaveSettings);
  if (pathname === '/api/admin/ad-plans' && method === 'GET') return adminOnly(request, env, adminListAdPlans);
  if (pathname === '/api/admin/ad-plans' && method === 'POST') return adminOnly(request, env, adminSaveAdPlan);
  if (pathname.match(/^\/api\/admin\/ad-plans\/\d+$/) && method === 'DELETE') return adminOnly(request, env, () => adminDeleteAdPlan(env, idFromPath(pathname)));

  return json({ error: 'Not found' }, 404);
}

function idFromPath(pathname) { return Number(pathname.match(/\d+/)[0]); }

/* ============================== HELPERS ============================== */
function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), { status, headers: { 'Content-Type': 'application/json', ...extraHeaders } });
}
function getCookie(request, name) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return match ? decodeURIComponent(match[1]) : null;
}
function cookieHeader(name, value, maxAgeSeconds) {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSeconds}`;
}
function clearCookieHeader(name) { return `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`; }
function randomToken() { return crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, ''); }

async function hmacHex(secret, message) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function adminOnly(request, env, handler) {
  const token = getCookie(request, 'admin_session');
  if (!token) return json({ error: 'Admin login required' }, 401);
  const row = await env.DB.prepare("SELECT * FROM admin_sessions WHERE token = ? AND expires_at > datetime('now')").bind(token).first();
  if (!row) return json({ error: 'Admin login required' }, 401);
  return handler(request, env);
}

/* ============================== ADMIN: DIAGNOSTICS ============================== */
// Visit /api/admin/diagnostics in your browser right after logging into Admin
// (same browser, same tab is fine) to see exactly what's configured and what
// isn't — no DevTools needed.
async function adminDiagnostics(request, env) {
  const checks = {};

  try {
    await env.DB.prepare('SELECT 1').first();
    checks.database = 'OK — connected';
  } catch (e) {
    checks.database = 'ERROR — ' + String(e);
  }

  try {
    const { results } = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
    checks.tables_found = results.map(r => r.name);
    const adsCols = await env.DB.prepare("PRAGMA table_info(ads)").all();
    checks.ads_columns = adsCols.results.map(c => c.name);
  } catch (e) {
    checks.tables_found = 'ERROR — ' + String(e);
  }

  checks.admin_password_set = !!env.ADMIN_PASSWORD;

  checks.razorpay_key_id_set = !!env.RAZORPAY_KEY_ID;
  checks.razorpay_key_id_starts_with = env.RAZORPAY_KEY_ID ? env.RAZORPAY_KEY_ID.slice(0, 9) : null;
  checks.razorpay_key_id_looks_like_test_key = env.RAZORPAY_KEY_ID ? env.RAZORPAY_KEY_ID.startsWith('rzp_test_') : false;
  checks.razorpay_key_id_looks_like_live_key = env.RAZORPAY_KEY_ID ? env.RAZORPAY_KEY_ID.startsWith('rzp_live_') : false;

  checks.razorpay_key_secret_set = !!env.RAZORPAY_KEY_SECRET;
  checks.razorpay_key_secret_length = env.RAZORPAY_KEY_SECRET ? env.RAZORPAY_KEY_SECRET.length : 0;

  if (env.RAZORPAY_KEY_ID && env.RAZORPAY_KEY_SECRET) {
    try {
      const auth = btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`);
      const res = await fetch('https://api.razorpay.com/v1/orders?count=1', {
        headers: { 'Authorization': `Basic ${auth}` }
      });
      const data = await res.json();
      checks.razorpay_live_auth_test = res.ok
        ? 'SUCCESS — Razorpay accepted these keys'
        : 'FAILED — ' + (data.error?.description || JSON.stringify(data));
    } catch (e) {
      checks.razorpay_live_auth_test = 'ERROR — ' + String(e);
    }
  } else {
    checks.razorpay_live_auth_test = 'SKIPPED — one or both keys are not set';
  }

  return json(checks);
}

/* ============================== PUBLIC: BROWSE ============================== */
async function listCategories(env) {
  const { results } = await env.DB.prepare('SELECT * FROM categories ORDER BY id').all();
  return json({ categories: results });
}
async function listProviders(env) {
  const { results } = await env.DB.prepare("SELECT id, name, service, icon, phone, whatsapp, bio FROM providers WHERE status = 'approved' ORDER BY id DESC").all();
  return json({ providers: results });
}
async function listAds(env) {
  // expires_at is stored as a plain integer (milliseconds since epoch) — see
  // adminApproveAd. Comparing two numbers directly sidesteps every date-string
  // formatting/timezone ambiguity that caused approved ads to vanish before.
  const nowMs = Date.now();
  const { results } = await env.DB.prepare(
    `SELECT id, business_name, description, icon, phone, email, website_url, whatsapp, image_data, placement, featured
     FROM ads
     WHERE status = 'approved' AND (expires_at IS NULL OR expires_at > ?)
     ORDER BY featured DESC, id DESC`
  ).bind(nowMs).all();
  return json({ ads: results });
}
async function recordAdEvent(env, id, column) {
  // column is never user input (only 'impressions' or 'clicks' from the two
  // routes above), so it's safe to interpolate directly into the SQL here.
  await env.DB.prepare(`UPDATE ads SET ${column} = COALESCE(${column}, 0) + 1 WHERE id = ?`).bind(id).run();
  return json({ ok: true });
}
async function listAdPlans(env) {
  const { results } = await env.DB.prepare('SELECT * FROM ad_plans WHERE active = 1 ORDER BY placement, price_rupees').all();
  return json({ plans: results });
}
async function getSettings(env) {
  const { results } = await env.DB.prepare('SELECT * FROM settings').all();
  const settings = {};
  results.forEach(r => settings[r.key] = r.value);
  return json({ settings });
}

/* ============================== PUBLIC: FREE PROVIDER SUGGESTION ============================== */
async function suggestProvider(request, env) {
  const body = await request.json();
  const { name, service, phone, whatsapp, bio, suggestedByName, suggestedByContact } = body;
  if (!name || !service || !phone) return json({ error: 'Name, service and phone are required.' }, 400);

  const category = await env.DB.prepare('SELECT icon FROM categories WHERE name = ?').bind(service).first();
  const icon = category ? category.icon : '🔧';

  await env.DB.prepare(
    `INSERT INTO providers (name, service, icon, phone, whatsapp, bio, status, suggested_by_name, suggested_by_contact)
     VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)`
  ).bind(name, service, icon, phone, whatsapp || null, bio || '', suggestedByName || '', suggestedByContact || '').run();

  return json({ ok: true, message: 'Thanks! Submitted for review.' });
}

/* ============================== PUBLIC: PAID BUSINESS ADS ============================== */
// The client already compresses images to ~1000px JPEG @0.72 quality before
// sending, so this is just a safety net against something unexpectedly large.
const MAX_IMAGE_DATA_URL_LENGTH = 1_500_000; // ~1.1MB decoded

async function createAdOrder(request, env) {
  // Fail fast with a clear message instead of letting Razorpay return a
  // confusing "Authentication failed" when keys simply aren't set.
  if (!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET) {
    return json({ error: "Payments aren't set up yet — RAZORPAY_KEY_ID and/or RAZORPAY_KEY_SECRET are missing. Check /api/admin/diagnostics." }, 500);
  }

  const body = await request.json();
  const { planId, businessName, description, phone, email, icon, imageData, websiteUrl, whatsapp } = body;
  if (!businessName || !phone) return json({ error: 'Business name and phone are required.' }, 400);
  if (!planId) return json({ error: 'Please choose an ad plan.' }, 400);

  // The price, placement and duration always come from the plan record on the
  // server — never trust a price sent by the client, or anyone could pay ₹1
  // for a premium banner slot by editing the request.
  const plan = await env.DB.prepare('SELECT * FROM ad_plans WHERE id = ? AND active = 1').bind(planId).first();
  if (!plan) return json({ error: 'That ad plan is no longer available. Please choose another.' }, 400);

  let image = null;
  if (imageData) {
    if (typeof imageData !== 'string' || !imageData.startsWith('data:image/')) {
      return json({ error: 'Invalid image data.' }, 400);
    }
    if (imageData.length > MAX_IMAGE_DATA_URL_LENGTH) {
      return json({ error: 'Image is too large — please choose a smaller one.' }, 400);
    }
    image = imageData;
  }

  let website = null;
  if (websiteUrl && websiteUrl.trim()) {
    website = websiteUrl.trim();
    if (!/^https?:\/\//i.test(website)) website = 'https://' + website;
  }

  const amountPaise = plan.price_rupees * 100;

  const auth = btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`);
  const orderRes = await fetch('https://api.razorpay.com/v1/orders', {
    method: 'POST',
    headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ amount: amountPaise, currency: 'INR', receipt: `ad_${Date.now()}` })
  });
  const order = await orderRes.json();
  if (!order.id) return json({ error: 'Could not create payment order.', detail: order }, 502);

  const result = await env.DB.prepare(
    `INSERT INTO ads (business_name, description, icon, phone, email, website_url, whatsapp, image_data, amount, placement, duration_days, plan_name, razorpay_order_id, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_payment')`
  ).bind(businessName, description || '', icon || '📢', phone, email || '', website, whatsapp || null, image, amountPaise, plan.placement, plan.duration_days, plan.name, order.id).run();

  return json({ adId: result.meta.last_row_id, orderId: order.id, amount: amountPaise, keyId: env.RAZORPAY_KEY_ID });
}

async function verifyAdPayment(request, env) {
  const { adId, razorpay_order_id, razorpay_payment_id, razorpay_signature } = await request.json();
  const expected = await hmacHex(env.RAZORPAY_KEY_SECRET, `${razorpay_order_id}|${razorpay_payment_id}`);
  if (expected !== razorpay_signature) return json({ error: 'Payment verification failed.' }, 400);

  const ad = await env.DB.prepare('SELECT * FROM ads WHERE id = ?').bind(adId).first();
  if (!ad) return json({ error: 'Ad not found.' }, 404);

  await env.DB.prepare("UPDATE ads SET status = 'pending_review', razorpay_payment_id = ? WHERE id = ?").bind(razorpay_payment_id, adId).run();
  return json({ ok: true, message: 'Payment received. Your ad will go live once approved.' });
}

/* ============================== ADMIN: AUTH ============================== */
async function adminLogin(request, env) {
  const { password } = await request.json();
  if (password !== env.ADMIN_PASSWORD) return json({ error: 'Incorrect password.' }, 401);
  const token = randomToken();
  const expires = new Date(Date.now() + 12 * 3600 * 1000).toISOString();
  await env.DB.prepare('INSERT INTO admin_sessions (token, expires_at) VALUES (?, ?)').bind(token, expires).run();
  return json({ ok: true }, 200, { 'Set-Cookie': cookieHeader('admin_session', token, 12 * 3600) });
}
async function adminLogout(request, env) {
  return json({ ok: true }, 200, { 'Set-Cookie': clearCookieHeader('admin_session') });
}

/* ============================== ADMIN: DASHBOARD ============================== */
async function adminDashboard(request, env) {
  const providers = await env.DB.prepare("SELECT COUNT(*) as n FROM providers WHERE status = 'approved'").first();
  const pendingProviders = await env.DB.prepare("SELECT COUNT(*) as n FROM providers WHERE status = 'pending'").first();
  const liveAds = await env.DB.prepare('SELECT COUNT(*) as n FROM ads WHERE status = \'approved\' AND (expires_at IS NULL OR expires_at > ?)').bind(Date.now()).first();
  const pendingAds = await env.DB.prepare("SELECT COUNT(*) as n FROM ads WHERE status = 'pending_review'").first();
  const revenue = await env.DB.prepare("SELECT COALESCE(SUM(amount),0) as total FROM ads WHERE status IN ('pending_review','approved','expired')").first();
  return json({
    totalProviders: providers.n, pendingProviders: pendingProviders.n,
    liveAds: liveAds.n, pendingAds: pendingAds.n, adRevenue: revenue.total
  });
}

/* ============================== ADMIN: PROVIDERS ============================== */
async function adminListProviders(request, env) {
  const { results } = await env.DB.prepare('SELECT * FROM providers ORDER BY id DESC').all();
  return json({ providers: results });
}
async function adminSaveProvider(request, env, id) {
  const b = await request.json();
  const category = await env.DB.prepare('SELECT icon FROM categories WHERE name = ?').bind(b.service).first();
  const icon = category ? category.icon : '🔧';
  if (id) {
    await env.DB.prepare('UPDATE providers SET name=?, service=?, icon=?, phone=?, whatsapp=?, bio=?, status=? WHERE id=?')
      .bind(b.name, b.service, icon, b.phone, b.whatsapp || null, b.bio, b.status, id).run();
  } else {
    await env.DB.prepare("INSERT INTO providers (name, service, icon, phone, whatsapp, bio, status) VALUES (?,?,?,?,?,?, 'approved')")
      .bind(b.name, b.service, icon, b.phone, b.whatsapp || null, b.bio).run();
  }
  return json({ ok: true });
}
async function adminDeleteProvider(env, id) {
  await env.DB.prepare('DELETE FROM providers WHERE id = ?').bind(id).run();
  return json({ ok: true });
}
async function adminApproveProvider(env, id) {
  await env.DB.prepare("UPDATE providers SET status = 'approved' WHERE id = ?").bind(id).run();
  return json({ ok: true });
}
async function adminRejectProvider(env, id) {
  await env.DB.prepare("UPDATE providers SET status = 'rejected' WHERE id = ?").bind(id).run();
  return json({ ok: true });
}

/* ============================== ADMIN: CATEGORIES ============================== */
async function adminSaveCategory(request, env) {
  const { id, name, icon } = await request.json();
  if (id) await env.DB.prepare('UPDATE categories SET name=?, icon=? WHERE id=?').bind(name, icon, id).run();
  else await env.DB.prepare('INSERT INTO categories (name, icon) VALUES (?, ?)').bind(name, icon).run();
  return json({ ok: true });
}
async function adminDeleteCategory(env, id) {
  await env.DB.prepare('DELETE FROM categories WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

/* ============================== ADMIN: ADS ============================== */
async function adminListAds(request, env) {
  const { results } = await env.DB.prepare('SELECT * FROM ads ORDER BY id DESC').all();
  return json({ ads: results });
}
async function adminUpdateAd(request, env, id) {
  const b = await request.json();
  const ad = await env.DB.prepare('SELECT * FROM ads WHERE id = ?').bind(id).first();
  if (!ad) return json({ error: 'Ad not found.' }, 404);

  let website = ad.website_url;
  if (b.websiteUrl !== undefined) {
    website = b.websiteUrl && b.websiteUrl.trim() ? b.websiteUrl.trim() : null;
    if (website && !/^https?:\/\//i.test(website)) website = 'https://' + website;
  }

  let image = ad.image_data;
  if (b.imageData !== undefined) {
    if (b.imageData === null) image = null; // admin explicitly removed the image
    else if (typeof b.imageData === 'string' && b.imageData.startsWith('data:image/')) image = b.imageData;
  }

  await env.DB.prepare(
    `UPDATE ads SET business_name=?, description=?, icon=?, phone=?, email=?, website_url=?, whatsapp=?, image_data=?, featured=? WHERE id=?`
  ).bind(
    b.businessName ?? ad.business_name,
    b.description ?? ad.description,
    b.icon ?? ad.icon,
    b.phone ?? ad.phone,
    b.email ?? ad.email,
    website,
    b.whatsapp !== undefined ? (b.whatsapp || null) : ad.whatsapp,
    image,
    b.featured !== undefined ? (b.featured ? 1 : 0) : ad.featured,
    id
  ).run();

  return json({ ok: true });
}
async function adminApproveAd(env, id) {
  const ad = await env.DB.prepare('SELECT duration_days FROM ads WHERE id = ?').bind(id).first();
  const days = Number(ad?.duration_days || 30); // falls back to 30 for any legacy ad predating ad plans
  const expiresMs = Date.now() + days * 24 * 3600 * 1000;
  await env.DB.prepare("UPDATE ads SET status = 'approved', starts_at = datetime('now'), expires_at = ? WHERE id = ?").bind(expiresMs, id).run();
  return json({ ok: true });
}
async function adminRejectAd(env, id) {
  const ad = await env.DB.prepare('SELECT * FROM ads WHERE id = ?').bind(id).first();
  if (!ad) return json({ error: 'Ad not found.' }, 404);

  // Only attempt a refund if a payment was actually captured for this ad.
  if (!ad.razorpay_payment_id) {
    await env.DB.prepare("UPDATE ads SET status = 'rejected' WHERE id = ?").bind(id).run();
    return json({ ok: true, refunded: false });
  }

  if (!env.RAZORPAY_KEY_ID || !env.RAZORPAY_KEY_SECRET) {
    await env.DB.prepare("UPDATE ads SET status = 'rejected', refund_status = 'failed' WHERE id = ?").bind(id).run();
    return json({ ok: true, refunded: false, warning: 'Razorpay keys are not set — could not process refund automatically. Refund this payment manually from the Razorpay dashboard.' });
  }

  try {
    const auth = btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`);
    const refundRes = await fetch(`https://api.razorpay.com/v1/payments/${ad.razorpay_payment_id}/refund`, {
      method: 'POST',
      headers: { 'Authorization': `Basic ${auth}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ amount: ad.amount })
    });
    const refund = await refundRes.json();

    if (refund.id) {
      await env.DB.prepare("UPDATE ads SET status = 'rejected', refund_status = 'refunded', razorpay_refund_id = ? WHERE id = ?")
        .bind(refund.id, id).run();
      return json({ ok: true, refunded: true });
    } else {
      await env.DB.prepare("UPDATE ads SET status = 'rejected', refund_status = 'failed' WHERE id = ?").bind(id).run();
      return json({ ok: true, refunded: false, warning: 'Refund failed: ' + (refund.error?.description || JSON.stringify(refund)) });
    }
  } catch (e) {
    await env.DB.prepare("UPDATE ads SET status = 'rejected', refund_status = 'failed' WHERE id = ?").bind(id).run();
    return json({ ok: true, refunded: false, warning: 'Refund error: ' + String(e) });
  }
}
async function adminDeleteAd(env, id) {
  await env.DB.prepare('DELETE FROM ads WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

/* ============================== ADMIN: SITE SETTINGS ============================== */
async function adminSaveSettings(request, env) {
  const body = await request.json();
  for (const [key, value] of Object.entries(body)) {
    await env.DB.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind(key, value).run();
  }
  return json({ ok: true });
}

/* ============================== ADMIN: AD PLANS ============================== */
async function adminListAdPlans(request, env) {
  const { results } = await env.DB.prepare('SELECT * FROM ad_plans ORDER BY placement, price_rupees').all();
  return json({ plans: results });
}
async function adminSaveAdPlan(request, env) {
  const b = await request.json();
  if (!b.name || !b.placement || !b.durationDays || !b.priceRupees) {
    return json({ error: 'Name, placement, duration and price are all required.' }, 400);
  }
  if (b.id) {
    await env.DB.prepare('UPDATE ad_plans SET name=?, placement=?, duration_days=?, price_rupees=?, active=? WHERE id=?')
      .bind(b.name, b.placement, b.durationDays, b.priceRupees, b.active ? 1 : 0, b.id).run();
  } else {
    await env.DB.prepare('INSERT INTO ad_plans (name, placement, duration_days, price_rupees, active) VALUES (?, ?, ?, ?, ?)')
      .bind(b.name, b.placement, b.durationDays, b.priceRupees, b.active === false ? 0 : 1).run();
  }
  return json({ ok: true });
}
async function adminDeleteAdPlan(env, id) {
  await env.DB.prepare('DELETE FROM ad_plans WHERE id = ?').bind(id).run();
  return json({ ok: true });
}
