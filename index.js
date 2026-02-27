'use strict';

const express = require('express');
const crypto = require('crypto');
const Stripe = require('stripe');
const { Firestore } = require('@google-cloud/firestore');

const app = express();

// -------------------- Config --------------------
const PORT = process.env.PORT || 8080;

// Change this every commit so /status proves you’re on the latest revision
const BUILD_STAMP = '2026-02-27-02';

// Stripe env vars
const STRIPE_SECRET = process.env.STRIPE_SECRET;                   // sk_test_... or sk_live_...
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;   // whsec_...

if (!STRIPE_SECRET) console.warn('[WARN] Missing env var STRIPE_SECRET');
if (!STRIPE_WEBHOOK_SECRET) console.warn('[WARN] Missing env var STRIPE_WEBHOOK_SECRET');

// Only create Stripe client if secret exists (prevents crashes during deploy)
const stripe = STRIPE_SECRET ? Stripe(STRIPE_SECRET) : null;

// Firestore (Cloud Run uses Service Account automatically via ADC)
const firestore = new Firestore();

// PayPal env vars
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID || '';
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET || '';
const PAYPAL_WEBHOOK_ID = process.env.PAYPAL_WEBHOOK_ID || ''; // from PayPal app webhook details
const PAYPAL_MODE = (process.env.PAYPAL_MODE || 'sandbox').toLowerCase(); // sandbox | live

const PAYPAL_BASE =
  PAYPAL_MODE === 'live'
    ? 'https://api-m.paypal.com'
    : 'https://api-m.sandbox.paypal.com';

// In sandbox, PayPal simulator payloads can be “mocky” — allow unverified in sandbox if you want
const PAYPAL_ALLOW_UNVERIFIED = (process.env.PAYPAL_ALLOW_UNVERIFIED || (PAYPAL_MODE === 'sandbox' ? 'true' : 'false'))
  .toLowerCase() === 'true';

if (!PAYPAL_CLIENT_ID) console.warn('[WARN] Missing env var PAYPAL_CLIENT_ID');
if (!PAYPAL_CLIENT_SECRET) console.warn('[WARN] Missing env var PAYPAL_CLIENT_SECRET');
if (!PAYPAL_WEBHOOK_ID) console.warn('[WARN] Missing env var PAYPAL_WEBHOOK_ID');

// BSP product defaults (optional, but keeps things consistent)
const BSP_PRODUCT = process.env.BSP_PRODUCT || 'BrandStampPro';
const BSP_DEFAULT_SEATS = Number(process.env.BSP_DEFAULT_SEATS || 2);
const BSP_DEFAULT_TIER = process.env.BSP_DEFAULT_TIER || 'standard';
const BSP_DEFAULT_ENTITLEMENT = process.env.BSP_DEFAULT_ENTITLEMENT || '1.x'; // set to 2.x only if you truly intend that

// CORS (for WP Smart Buttons calling Cloud Run from the browser)
const CORS_ALLOW_ORIGINS = (process.env.CORS_ALLOW_ORIGINS || '*')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

// -------------------- Middleware --------------------
// IMPORTANT: Stripe webhook needs RAW body. If we parse JSON globally first, Stripe signature verify will fail.
// Solution: apply JSON parsing to everything EXCEPT the Stripe webhook route.
const jsonParser = express.json({ limit: '256kb' });
app.use((req, res, next) => {
  if (req.originalUrl === '/webhook/stripe') return next();
  return jsonParser(req, res, next);
});

// -------------------- Helpers --------------------
function nowIso() {
  return new Date().toISOString();
}

function normalizeEmail(v) {
  const s = String(v || '').trim().toLowerCase();
  return s || null;
}

function makeLicenseKey() {
  const a = crypto.randomBytes(4).toString('hex').toUpperCase();
  const b = crypto.randomBytes(4).toString('hex').toUpperCase();
  return `BSP-${a}-${b}`;
}

function makePurchaseRef() {
  const tail = crypto.randomBytes(3).toString('hex').toUpperCase();
  return `BSP-${Date.now()}-${tail}`;
}

function emailHash(email) {
  if (!email) return null;
  return crypto.createHash('sha256').update(email.toLowerCase().trim()).digest('hex');
}

function corsAllow(res, origin) {
  // Basic allowlist; '*' means allow all.
  const allowAll = CORS_ALLOW_ORIGINS.includes('*');
  const ok = allowAll || (origin && CORS_ALLOW_ORIGINS.includes(origin));
  if (!ok) return false;

  res.setHeader('Access-Control-Allow-Origin', allowAll ? '*' : origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  return true;
}

// Preflight handler for CORS
app.options('*', (req, res) => {
  const origin = req.headers.origin;
  corsAllow(res, origin);
  return res.sendStatus(204);
});

async function paypalGetAccessToken() {
  const creds = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString('base64');

  const res = await fetch(`${PAYPAL_BASE}/v1/oauth2/token`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${creds}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'grant_type=client_credentials',
  });

  if (!res.ok) {
    const txt = await res.text().catch(() => '');
    throw new Error(`PayPal token error ${res.status}: ${txt}`);
  }

  const json = await res.json();
  return json.access_token;
}

async function paypalVerifyWebhookSignature(reqHeaders, rawEventBody) {
  // PayPal sends these headers (names are case-insensitive; Node lowercases them)
  const transmissionId = reqHeaders['paypal-transmission-id'];
  const transmissionTime = reqHeaders['paypal-transmission-time'];
  const transmissionSig = reqHeaders['paypal-transmission-sig'];
  const certUrl = reqHeaders['paypal-cert-url'];
  const authAlgo = reqHeaders['paypal-auth-algo'];

  // If any are missing, verification can’t happen (common in some simulators)
  if (!transmissionId || !transmissionTime || !transmissionSig || !certUrl || !authAlgo) {
    return { verified: false, reason: 'missing_paypal_headers' };
  }

  if (!PAYPAL_WEBHOOK_ID || !PAYPAL_CLIENT_ID || !PAYPAL_CLIENT_SECRET) {
    return { verified: false, reason: 'missing_paypal_env' };
  }

  const accessToken = await paypalGetAccessToken();

  const payload = {
    auth_algo: authAlgo,
    cert_url: certUrl,
    transmission_id: transmissionId,
    transmission_sig: transmissionSig,
    transmission_time: transmissionTime,
    webhook_id: PAYPAL_WEBHOOK_ID,
    webhook_event: rawEventBody, // object, not string
  };

  const res = await fetch(`${PAYPAL_BASE}/v1/notifications/verify-webhook-signature`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const txt = await res.text().catch(() => '');
    return { verified: false, reason: `verify_api_error_${res.status}`, detail: txt };
  }

  const json = await res.json();
  // json.verification_status === "SUCCESS"
  return { verified: json.verification_status === 'SUCCESS', detail: json };
}

// -------------------- Routes --------------------
app.get('/', (req, res) => {
  res.type('text/plain').send('bsp-licensing-webhook ok');
});

app.get('/status', (req, res) => {
  res.json({
    ok: true,
    service: 'bsp-licensing-webhook',
    build: BUILD_STAMP,
    ts: nowIso(),
    paypalMode: PAYPAL_MODE,
    allowUnverifiedPaypal: PAYPAL_ALLOW_UNVERIFIED,
    corsAllowOrigins: CORS_ALLOW_ORIGINS,
  });
});

/**
 * License verification endpoint (BSP Activate / Verify)
 * Expects: { key, machineId }
 * Returns: { status: valid|invalid|max_devices|error, message }
 */
app.post('/verify', async (req, res) => {
  try {
    const key = String(req.body?.key || '').trim();
    const machineId = String(req.body?.machineId || '').trim();

    if (!key || !machineId) {
      return res.status(400).json({ status: 'invalid', message: 'Missing key or machineId.' });
    }

    const ref = firestore.collection('licenses').doc(key);
    const snap = await ref.get();

    if (!snap.exists) {
      return res.json({ status: 'invalid', message: 'Key not found.' });
    }

    const lic = snap.data() || {};
    if ((lic.status || 'active') !== 'active') {
      return res.json({ status: 'invalid', message: 'License is disabled.' });
    }

    const maxDevices = Number(lic.maxDevices || 2);
    const devices = Array.isArray(lic.devices) ? lic.devices : [];
    const now = nowIso();

    // already activated on this machine?
    const idx = devices.findIndex(d => d && d.id === machineId);
    if (idx >= 0) {
      devices[idx].lastSeen = now;
      await ref.set({ devices, updatedAt: now }, { merge: true });
      return res.json({ status: 'valid', message: 'License verified.' });
    }

    // new machine
    if (devices.length >= maxDevices) {
      return res.json({ status: 'max_devices', message: `Device limit reached (${maxDevices}).` });
    }

    devices.push({ id: machineId, firstSeen: now, lastSeen: now });
    await ref.set({ devices, maxDevices, updatedAt: now }, { merge: true });

    return res.json({ status: 'valid', message: 'License verified.' });
  } catch (err) {
    console.error('🔥 verify error:', err);
    return res.status(500).json({ status: 'error', message: 'Server error.' });
  }
});

/**
 * PayPal Smart Buttons: Create Order (server-side)
 * Expects: { email, amount? }
 * Returns: { ok, orderId, purchaseRef }
 */
app.post('/paypal/create-order', async (req, res) => {
  try {
    const origin = req.headers.origin;
    corsAllow(res, origin);

    const email = normalizeEmail(req.body?.email);
    const amountValue = String(req.body?.amount || '30.00'); // TODO: compute from SKU/pricing if needed
    const currency = 'USD';

    if (!email) return res.status(400).json({ ok: false, error: 'missing_email' });

    const purchaseRef = makePurchaseRef();

    // Write pending purchase first (critical bridge that fixes email:null in webhook)
    await firestore.collection('paypal_purchases').doc(purchaseRef).set({
      purchaseRef,
      email,
      product: BSP_PRODUCT,
      license_seats: BSP_DEFAULT_SEATS,
      license_tier: BSP_DEFAULT_TIER,
      version_entitlement: BSP_DEFAULT_ENTITLEMENT,
      status: 'pending',
      amount: Number(amountValue),
      currency,
      createdAt: nowIso(),
      updatedAt: nowIso(),
      paypalMode: PAYPAL_MODE,
    });

    const accessToken = await paypalGetAccessToken();

    const orderPayload = {
      intent: 'CAPTURE',
      purchase_units: [{
        amount: { currency_code: currency, value: amountValue },
        invoice_id: purchaseRef, // <-- BRIDGE (comes back on capture webhook)
        custom_id: purchaseRef,  // <-- redundant but useful
      }],
    };

    const resp = await fetch(`${PAYPAL_BASE}/v2/checkout/orders`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(orderPayload),
    });

    if (!resp.ok) {
      const txt = await resp.text().catch(() => '');
      console.error('🔥 PayPal create order failed:', resp.status, txt);

      await firestore.collection('paypal_purchases').doc(purchaseRef).set({
        status: 'failed',
        error: `paypal_create_order_failed_${resp.status}`,
        updatedAt: nowIso(),
      }, { merge: true });

      return res.status(500).json({ ok: false, error: 'paypal_create_order_failed', detail: txt });
    }

    const order = await resp.json();

    await firestore.collection('paypal_purchases').doc(purchaseRef).set({
      orderId: order?.id || null,
      updatedAt: nowIso(),
    }, { merge: true });

    return res.json({ ok: true, orderId: order.id, purchaseRef });
  } catch (err) {
    console.error('🔥 /paypal/create-order error:', err);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

/**
 * PayPal Smart Buttons: Capture Order (server-side)
 * Expects: { orderId }
 * Returns: { ok, result }
 *
 * NOTE: You can show success to the buyer after capture,
 * but you should still mint/license via webhook as the source of truth.
 */
app.post('/paypal/capture-order', async (req, res) => {
  try {
    const origin = req.headers.origin;
    corsAllow(res, origin);

    const orderId = String(req.body?.orderId || '').trim();
    if (!orderId) return res.status(400).json({ ok: false, error: 'missing_orderId' });

    const accessToken = await paypalGetAccessToken();

    const resp = await fetch(`${PAYPAL_BASE}/v2/checkout/orders/${encodeURIComponent(orderId)}/capture`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
    });

    const json = await resp.json().catch(() => ({}));

    if (!resp.ok) {
      console.error('🔥 PayPal capture failed:', resp.status, json);
      return res.status(500).json({ ok: false, error: 'paypal_capture_failed', detail: json });
    }

    return res.json({ ok: true, result: json });
  } catch (err) {
    console.error('🔥 /paypal/capture-order error:', err);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.post('/stripe/create-checkout-session', async (req, res) => {
  try {
    const origin = req.headers.origin;
    // If you have the corsAllow helper in your updated file, call it here:
    // corsAllow(res, origin);

    if (!stripe) return res.status(500).json({ ok: false, error: 'stripe_not_configured' });

    const email = String(req.body?.email || '').trim().toLowerCase();
    if (!email) return res.status(400).json({ ok: false, error: 'missing_email' });

    const priceId = process.env.STRIPE_PRICE_ID;
    if (!priceId) return res.status(500).json({ ok: false, error: 'missing_STRIPE_PRICE_ID' });

    const siteUrl = process.env.SITE_URL || 'https://betterhomephotos.net';
    const successUrl = `${siteUrl}/bsp-thank-you/?provider=stripe&session_id={CHECKOUT_SESSION_ID}`;
    const cancelUrl  = `${siteUrl}/lightroom-classic-branding-plugin/?cancelled=1`;

    const session = await stripe.checkout.sessions.create({
      mode: 'payment',
      customer_email: email,
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: successUrl,
      cancel_url: cancelUrl,
      metadata: {
        license_email: email,
        license_seats: '2',
        license_tier: 'standard',
        product: 'BrandStampPro',
        version_entitlement: '1.x', // change only if you truly intend 2.x
      },
    });

    return res.json({ ok: true, url: session.url });
  } catch (err) {
    console.error('🔥 /stripe/create-checkout-session error:', err);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// ==================== STRIPE WEBHOOK ====================
// Stripe requires the RAW body for signature verification.
app.post('/webhook/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    if (!stripe) {
      console.error('[ERROR] Stripe not initialized. Missing STRIPE_SECRET.');
      return res.status(500).send('Server misconfigured');
    }
    if (!STRIPE_WEBHOOK_SECRET) {
      console.error('[ERROR] Missing STRIPE_WEBHOOK_SECRET.');
      return res.status(500).send('Server misconfigured');
    }

    const sig = req.headers['stripe-signature'];
    if (!sig) {
      console.error('[ERROR] Missing stripe-signature header.');
      return res.status(400).send('Missing stripe-signature');
    }

    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
      console.error('⚠️ Stripe signature verify failed:', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;

      const email =
        session.customer_details?.email ||
        session.customer_email ||
        null;

      const metadata = session.metadata || {};

      // Dedupe by Stripe event id
      const eventRef = firestore.collection('stripe_events').doc(event.id);

      await firestore.runTransaction(async (tx) => {
        const existing = await tx.get(eventRef);
        if (existing.exists) return;

        const licenseKey = makeLicenseKey();

        const licenseDoc = {
          licenseKey,
          email,
          emailHash: email ? emailHash(email) : null,
          stripe: {
            provider: 'stripe',
            eventId: event.id,
            sessionId: session.id,
            paymentStatus: session.payment_status,
            mode: session.mode,
            amountTotal: session.amount_total,
            currency: session.currency,
            livemode: !!session.livemode,
          },
          metadata,
          status: 'active',
          maxDevices: BSP_DEFAULT_SEATS,
          createdAt: nowIso(),
          updatedAt: nowIso(),
          expiresAt: null,
        };

        tx.set(eventRef, {
          processedAt: nowIso(),
          type: event.type,
          sessionId: session.id,
          email,
          licenseKey,
        });

        tx.set(firestore.collection('licenses').doc(licenseKey), licenseDoc, { merge: true });
      });

      console.log('✅ Stripe checkout.session.completed processed', {
        eventId: event.id,
        sessionId: session.id,
        emailPresent: !!email,
      });
    } else {
      console.log('ℹ️ Stripe event received:', event.type);
    }

    return res.sendStatus(200);
  } catch (err) {
    console.error('🔥 Stripe webhook handler error:', err);
    return res.status(500).send('Server error');
  }
});

// ==================== PAYPAL WEBHOOK ====================
app.post('/webhook/paypal', async (req, res) => {
  try {
    const event = req.body || {};
    const eventId = event.id || null;
    const eventType = event.event_type || null;
    const resourceType = event.resource_type || null;
    const createTime = event.create_time || null;
    const resource = event.resource || {};

    if (!eventId || !eventType) {
      console.error('[ERROR] PayPal webhook missing id/event_type');
      return res.status(400).json({ ok: false, error: 'invalid_paypal_payload' });
    }

    // Verify signature if we can (recommended for live)
    let verified = false;
    let verifyInfo = null;

    const canVerify =
      PAYPAL_WEBHOOK_ID &&
      PAYPAL_CLIENT_ID &&
      PAYPAL_CLIENT_SECRET &&
      req.headers['paypal-transmission-id'];

    if (canVerify) {
      const v = await paypalVerifyWebhookSignature(req.headers, event);
      verified = !!v.verified;
      verifyInfo = v;

      if (!verified && !PAYPAL_ALLOW_UNVERIFIED) {
        console.error('⚠️ PayPal signature verify failed', v);
        return res.status(400).json({ ok: false, error: 'paypal_signature_verify_failed', detail: v.reason || null });
      }
    } else {
      if (!PAYPAL_ALLOW_UNVERIFIED) {
        console.error('⚠️ PayPal verification unavailable and PAYPAL_ALLOW_UNVERIFIED=false');
        return res.status(400).json({ ok: false, error: 'paypal_verification_unavailable' });
      }
    }

    // Trust only V2 capture completion
    const shouldMint = eventType === 'PAYMENT.CAPTURE.COMPLETED';

    // Pull amount/currency in a tolerant way
    let amount = null;
    let currency = null;

    if (resource?.amount?.value && resource?.amount?.currency_code) {
      amount = Number(resource.amount.value);
      currency = resource.amount.currency_code;
    } else if (resource?.amount?.total && resource?.amount?.currency) {
      amount = Number(resource.amount.total);
      currency = resource.amount.currency;
    }

    const captureId = resource?.id || null;
    const orderId =
      resource?.supplementary_data?.related_ids?.order_id ||
      resource?.parent_payment ||
      null;

    const purchaseRef =
      resource?.invoice_id ||
      resource?.custom_id ||
      null;

    // CAPTURE DEDUPE: PayPal may resend the same capture with a new eventId
    if (captureId) {
      const capRef = firestore.collection('paypal_captures').doc(captureId);
      const capSnap = await capRef.get();
      if (capSnap.exists) {
        console.log('ℹ️ PayPal capture deduped', { captureId, eventId, eventType });
        return res.status(200).json({ ok: true, deduped: true });
      }
    }

    // Hydrate email from our pending purchase doc (reliable)
    let email = null;

    if (purchaseRef) {
      const pSnap = await firestore.collection('paypal_purchases').doc(purchaseRef).get();
      if (pSnap.exists) {
        email = pSnap.data()?.email || null;
      }
    }

    // Fallback (often absent)
    email = email || resource?.payer?.email_address || null;

    // Dedupe by PayPal event id too
    const eventRef = firestore.collection('paypal_events').doc(eventId);

    await firestore.runTransaction(async (tx) => {
      const existing = await tx.get(eventRef);
      if (existing.exists) return;

      let licenseKey = null;

      if (shouldMint) {
        licenseKey = makeLicenseKey();

        const licenseDoc = {
          licenseKey,
          email,
          emailHash: email ? emailHash(email) : null,
          paypal: {
            provider: 'paypal',
            eventId,
            eventType,
            resourceType,
            createTime,
            captureId,
            orderId,
            purchaseRef,
            amount,
            currency,
            verified: !!verified,
          },
          metadata: {},
          status: 'active',
          maxDevices: BSP_DEFAULT_SEATS,
          createdAt: nowIso(),
          updatedAt: nowIso(),
          expiresAt: null,
        };

        tx.set(firestore.collection('licenses').doc(licenseKey), licenseDoc, { merge: true });

        if (purchaseRef) {
          tx.set(firestore.collection('paypal_purchases').doc(purchaseRef), {
            status: 'paid',
            captureId,
            orderId,
            updatedAt: nowIso(),
          }, { merge: true });
        }

        if (captureId) {
          tx.set(firestore.collection('paypal_captures').doc(captureId), {
            captureId,
            eventId,
            eventType,
            purchaseRef: purchaseRef || null,
            processedAt: nowIso(),
          }, { merge: true });
        }
      }

      tx.set(eventRef, {
        processedAt: nowIso(),
        verified: !!verified,
        verifyInfo: verifyInfo ? (verifyInfo.reason || verifyInfo.detail || null) : null,
        eventId,
        eventType,
        resourceType,
        createTime,
        captureId,
        orderId,
        purchaseRef: purchaseRef || null,
        amount,
        currency,
        email,
        licenseKey: licenseKey || null,
      });
    });

    console.log('✅ PayPal event processed', {
      eventId,
      eventType,
      verified,
      minted: shouldMint,
      captureId,
      purchaseRef,
      hasEmail: !!email,
    });

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('🔥 PayPal webhook handler error:', err);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// For any accidental hits to unknown paths
app.use((req, res) => res.status(404).json({ ok: false, error: 'Not found' }));

// -------------------- Start --------------------
app.listen(PORT, () => {
  console.log(`bsp-licensing-webhook listening on ${PORT} (build ${BUILD_STAMP})`);
});
















