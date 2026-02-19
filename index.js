'use strict';

const express = require('express');
const crypto = require('crypto');
const Stripe = require('stripe');
const { Firestore } = require('@google-cloud/firestore');

const app = express();

// -------------------- Config --------------------
const PORT = process.env.PORT || 8080;

// bump this each commit if you want
const BUILD_STAMP = '2026-02-19-02';

// Stripe env vars
const STRIPE_SECRET = process.env.STRIPE_SECRET;                   // sk_test_... or sk_live_...
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;   // whsec_...

if (!STRIPE_SECRET) console.warn('[WARN] Missing env var STRIPE_SECRET');
if (!STRIPE_WEBHOOK_SECRET) console.warn('[WARN] Missing env var STRIPE_WEBHOOK_SECRET');

const stripe = STRIPE_SECRET ? Stripe(STRIPE_SECRET) : null;

// Firestore (Cloud Run uses service account automatically via ADC)
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
  });
});

// -------------------- STRIPE WEBHOOK --------------------
// IMPORTANT:
// Stripe requires RAW body for signature verification.
// Do NOT use express.json() on this route.
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
    if (!sig) return res.status(400).send('Missing stripe-signature');

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

      // idempotency by Stripe event.id
      const eventRef = firestore.collection('stripe_events').doc(event.id);

      await firestore.runTransaction(async (tx) => {
        const existing = await tx.get(eventRef);
        if (existing.exists) return;

        const licenseKey = makeLicenseKey();

        const licenseDoc = {
          licenseKey,
          email,
          provider: 'stripe',
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
        email,
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

// -------------------- PAYPAL WEBHOOK --------------------
// PayPal sends JSON. Simulator events do NOT include everything needed for full verification.
// For now: accept JSON and mint license based on event.id (WH-...).
app.post('/webhook/paypal', express.json({ type: '*/*' }), async (req, res) => {
  try {
    const body = req.body || {};
    const eventType = body.event_type || null;
    const eventId = body.id || null;

    if (!eventId || !eventType) {
      return res.status(400).json({ ok: false, error: 'Missing PayPal event id/type' });
    }

    // These are "paid" events (mint license)
    const PAID_EVENTS = new Set([
      'PAYMENT.CAPTURE.COMPLETED',
      'PAYMENT.SALE.COMPLETED',
    ]);

    const resource = body.resource || {};

    // CAPTURE: amount.value + currency_code
    // SALE: amount.total + currency
    const amountStr =
      resource.amount?.value ??
      resource.amount?.total ??
      null;

    const currency =
      resource.amount?.currency_code ??
      resource.amount?.currency ??
      null;

    const amount = amountStr != null ? Number(amountStr) : null;

    // Store every PayPal event for audit/debug
    const eventRef = firestore.collection('paypal_events').doc(eventId);

    if (!PAID_EVENTS.has(eventType)) {
      await eventRef.set({ receivedAt: nowIso(), eventType, raw: body }, { merge: true });
      return res.status(200).json({ ok: true, ignored: true, eventType });
    }

    // Idempotency: one license per PayPal event id
    await firestore.runTransaction(async (tx) => {
      const existing = await tx.get(eventRef);
      if (existing.exists) return;

      const licenseKey = makeLicenseKey();

      const licenseDoc = {
        licenseKey,
        email: null,          // PayPal webhooks often don't include buyer email (especially simulator)
        provider: 'paypal',
        paypal: {
          eventId,
          eventType,
          resourceType: body.resource_type || null,
          summary: body.summary || null,
          amount,
          currency,
          captureId: resource.id || null,
          createTime: resource.create_time || body.create_time || null,
        },
        status: 'active',
        createdAt: nowIso(),
        updatedAt: nowIso(),
        expiresAt: null,
      };

      tx.set(eventRef, {
        processedAt: nowIso(),
        eventType,
        amount,
        currency,
        licenseKey,
      });

      tx.set(firestore.collection('licenses').doc(licenseKey), licenseDoc, { merge: true });
    });

    console.log('✅ PayPal paid event processed', { eventId, eventType, amount, currency });
    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('🔥 PayPal webhook handler error:', err);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// Helpful: JSON parser for any future non-webhook JSON endpoints (placed AFTER Stripe raw route)
app.use(express.json());

// Catch-all 404 LAST
app.use((req, res) => res.status(404).json({ ok: false, error: 'Not found' }));

// -------------------- Start --------------------
app.listen(PORT, () => {
  console.log(`bsp-licensing-webhook listening on ${PORT} (build ${BUILD_STAMP})`);
});














