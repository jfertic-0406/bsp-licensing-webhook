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
const STRIPE_SECRET = process.env.STRIPE_SECRET;                   // sk_test_... or sk_live_...
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;   // whsec_...

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

function sha256Hex(s) {
  return crypto.createHash('sha256').update(String(s || ''), 'utf8').digest('hex');
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

/**
 * ================== STRIPE WEBHOOK ==================
 * IMPORTANT:
 * - Stripe requires RAW body for signature verification
 * - Do NOT use express.json() on this route
 */
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

      // Idempotency: store Stripe event id so resends don't create new licenses
      const eventRef = firestore.collection('stripe_events').doc(event.id);

      await firestore.runTransaction(async (tx) => {
        const existing = await tx.get(eventRef);
        if (existing.exists) return;

        const licenseKey = makeLicenseKey();
        const emailHash = email ? sha256Hex(email.trim().toLowerCase()) : null;

        const licenseDoc = {
          licenseKey,
          provider: 'stripe',
          email,
          emailHash,
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
          emailHash,
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

// JSON parser for everything AFTER the Stripe raw route
app.use(express.json());

/**
 * ================== PAYPAL WEBHOOK ==================
 * For the PayPal Webhooks Simulator, we accept JSON and write to Firestore.
 * (Later we can add PayPal signature verification; the Simulator events are mock anyway.)
 */
app.post('/webhook/paypal', async (req, res) => {
  try {
    const body = req.body || {};
    const eventId = body.id || null;
    const eventType = body.event_type || null;
    const resourceType = body.resource_type || null;
    const createTime = body.create_time || null;
    const summary = body.summary || null;
    const resource = body.resource || {};

    if (!eventId || !eventType) {
      console.error('[PayPal] Missing event id/type');
      return res.status(400).json({ ok: false, error: 'Missing event id/type' });
    }

    // Try to extract useful purchase identifiers
    const captureId = resource.id || null;
    const orderId =
      resource?.supplementary_data?.related_ids?.order_id ||
      null;

    const amountValue = resource?.amount?.value || null;
    const currencyCode = resource?.amount?.currency_code || null;

    const payerEmail =
      resource?.payer?.email_address ||
      resource?.payer?.email ||
      null;

    const email = payerEmail || null;
    const emailHash = email ? sha256Hex(email.trim().toLowerCase()) : null;

    // Idempotency: PayPal event id de-dupe
    const ppEventRef = firestore.collection('paypal_events').doc(eventId);

    await firestore.runTransaction(async (tx) => {
      const existing = await tx.get(ppEventRef);
      if (existing.exists) return;

      const licenseKey = makeLicenseKey();

      const licenseDoc = {
        licenseKey,
        provider: 'paypal',
        email,
        emailHash,
        paypal: {
          eventId,
          eventType,
          resourceType,
          createTime,
          summary,
          captureId,
          orderId,
          amount: amountValue ? Number(amountValue) : null,
          currency: currencyCode,
        },
        status: 'active',
        createdAt: nowIso(),
        updatedAt: nowIso(),
        expiresAt: null,
      };

      tx.set(ppEventRef, {
        processedAt: nowIso(),
        eventType,
        resourceType,
        captureId,
        orderId,
        email,
        emailHash,
        licenseKey,
      });

      tx.set(firestore.collection('licenses').doc(licenseKey), licenseDoc, { merge: true });
    });

    console.log('✅ PayPal event processed', { eventId, eventType, email, captureId, orderId });

    return res.sendStatus(200);
  } catch (err) {
    console.error('🔥 PayPal webhook handler error:', err);
    return res.status(500).send('Server error');
  }
});

// For any accidental hits to unknown paths
app.use((req, res) => res.status(404).json({ ok: false, error: 'Not found' }));

// -------------------- Start --------------------
app.listen(PORT, () => {
  console.log(`bsp-licensing-webhook listening on ${PORT} (build ${BUILD_STAMP})`);
});












