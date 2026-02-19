'use strict';

const express = require('express');
const crypto = require('crypto');
const Stripe = require('stripe');
const { Firestore } = require('@google-cloud/firestore');

const app = express();

// -------------------- Config --------------------
const PORT = process.env.PORT || 8080;

// Change this every commit so /status proves you’re on the latest revision
const BUILD_STAMP = '2026-02-19-02';

// Stripe env vars
const STRIPE_SECRET = process.env.STRIPE_SECRET;                 // sk_test_... or sk_live_...
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET; // whsec_...

if (!STRIPE_SECRET) console.warn('[WARN] Missing env var STRIPE_SECRET');
if (!STRIPE_WEBHOOK_SECRET) console.warn('[WARN] Missing env var STRIPE_WEBHOOK_SECRET');

// Only create Stripe client if secret exists (prevents crashes during deploy)
const stripe = STRIPE_SECRET ? Stripe(STRIPE_SECRET) : null;

// Firestore (Cloud Run uses Service Account automatically via ADC)
const firestore = new Firestore();

// -------------------- Helpers --------------------
function makeLicenseKey() {
  const a = crypto.randomBytes(4).toString('hex').toUpperCase();
  const b = crypto.randomBytes(4).toString('hex').toUpperCase();
  return `BSP-${a}-${b}`;
}

function nowIso() {
  return new Date().toISOString();
}

// Minimal email hashing so you can correlate without exposing email
function sha256Hex(s) {
  return crypto.createHash('sha256').update(String(s || ''), 'utf8').digest('hex');
}

function normalizeLicenseKey(k) {
  return String(k || '').trim().toUpperCase();
}

// Accept only keys like BSP-XXXXXXXX-XXXXXXXX (hex blocks)
function isValidLicenseKey(k) {
  return /^BSP-[0-9A-F]{8}-[0-9A-F]{8}$/.test(k);
}

// Read license doc, return safe payload
async function lookupLicense(licenseKey) {
  const key = normalizeLicenseKey(licenseKey);
  if (!isValidLicenseKey(key)) {
    return { ok: false, error: 'Invalid license key format' };
  }

  const snap = await firestore.collection('licenses').doc(key).get();
  if (!snap.exists) {
    return { ok: false, error: 'License not found' };
  }

  const doc = snap.data() || {};
  const status = doc.status || 'unknown';
  const createdAt = doc.createdAt || null;
  const updatedAt = doc.updatedAt || null;

  // Never return raw email from the API
  const emailHash = doc.email ? sha256Hex(doc.email) : null;

  // Optional: allow future expiration field
  const expiresAt = doc.expiresAt || null;

  return {
    ok: true,
    licenseKey: key,
    status,
    createdAt,
    updatedAt,
    expiresAt,
    emailHash,
  };
}

// -------------------- Routes --------------------

// (Optional) Small CORS helper so you can test from browsers later without pain
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Stripe-Signature');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.get('/', (req, res) => {
  res.type('text/plain').send('bsp-licensing-webhook ok');
});

app.get('/status', (req, res) => {
  res.json({
    ok: true,
    service: 'bsp-licensing-webhook',
    build: BUILD_STAMP,
    ts: nowIso(),
  });
});

// ✅ License lookup by URL (what the plugin can call)
app.get('/license/:key', async (req, res) => {
  try {
    const out = await lookupLicense(req.params.key);
    return res.status(out.ok ? 200 : 404).json(out);
  } catch (err) {
    console.error('🔥 /license/:key error:', err);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// ✅ License verify by JSON body (also plugin-friendly)
app.post('/license/verify', express.json(), async (req, res) => {
  try {
    const licenseKey = req.body && req.body.licenseKey;
    const out = await lookupLicense(licenseKey);
    return res.status(out.ok ? 200 : 404).json(out);
  } catch (err) {
    console.error('🔥 /license/verify error:', err);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// IMPORTANT:
// - Stripe requires the RAW body for signature verification.
// - Do NOT use express.json() on this route.
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

    // We care about one-time purchase completion
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;

      const email =
        session.customer_details?.email ||
        session.customer_email ||
        null;

      const metadata = session.metadata || {};

      // ---- Idempotency / De-dupe ----
      // Stripe can resend the same event. We store event.id so we never double-issue.
      const eventRef = firestore.collection('stripe_events').doc(event.id);

      await firestore.runTransaction(async (tx) => {
        const existing = await tx.get(eventRef);
        if (existing.exists) return;

        const licenseKey = makeLicenseKey();

        const licenseDoc = {
          licenseKey,
          email,
          stripe: {
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
          createdAt: nowIso(),
          updatedAt: nowIso(),
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

      console.log('✅ checkout.session.completed processed', {
        eventId: event.id,
        sessionId: session.id,
        email,
      });
    } else {
      console.log('ℹ️ event received:', event.type);
    }

    return res.sendStatus(200);
  } catch (err) {
    console.error('🔥 webhook handler error:', err);
    // 500 triggers Stripe retry — helpful during setup
    return res.status(500).send('Server error');
  }
});

// For any accidental hits to unknown paths
app.use((req, res) => res.status(404).json({ ok: false, error: 'Not found' }));

// -------------------- Start --------------------
app.listen(PORT, () => {
  console.log(`bsp-licensing-webhook listening on ${PORT} (build ${BUILD_STAMP})`);
});










