'use strict';

const express = require('express');
const crypto = require('crypto');
const Stripe = require('stripe');
const { Firestore } = require('@google-cloud/firestore');

const app = express();

// -------------------- Config --------------------
const PORT = process.env.PORT || 8080;

// Stripe env vars
const STRIPE_SECRET = process.env.STRIPE_SECRET;               // sk_test_... or sk_live_...
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

// -------------------- Routes --------------------
app.get('/', (req, res) => {
  res.type('text/plain').send('bsp-licensing-webhook ok');
});

app.get('/status', async (req, res) => {
  res.json({ ok: true, service: 'bsp-licensing-webhook', ts: nowIso() });
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
      // Use Stripe event id as the primary dedupe key
      // so resends don't generate more licenses.
      const eventRef = firestore.collection('stripe_events').doc(event.id);

      // Also store license in licenses collection; licenseKey is human friendly.
      await firestore.runTransaction(async (tx) => {
        const existing = await tx.get(eventRef);
        if (existing.exists) {
          // Already processed this event
          return;
        }

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
            livemode: session.livemode,
          },
          metadata,
          status: 'active',
          createdAt: nowIso(),
          updatedAt: nowIso(),
        };

        // Record event processed
        tx.set(eventRef, {
          processedAt: nowIso(),
          type: event.type,
          sessionId: session.id,
          email,
          licenseKey,
        });

        // Write license
        const licenseRef = firestore.collection('licenses').doc(licenseKey);
        tx.set(licenseRef, licenseDoc, { merge: true });
      });

      console.log('✅ checkout.session.completed processed', {
        eventId: event.id,
        sessionId: session.id,
        email,
      });
    } else {
      // Optional during setup
      console.log('ℹ️ event received:', event.type);
    }

    return res.sendStatus(200);
  } catch (err) {
    console.error('🔥 webhook handler error:', err);
    // 500 triggers Stripe retry — helpful during setup
    return res.status(500).send('Server error');
  }
});

// Helpful: JSON parser for non-webhook routes (AFTER webhook route)
app.use(express.json());

// For any accidental hits to unknown paths
app.use((req, res) => res.status(404).json({ ok: false, error: 'Not found' }));

// -------------------- Start --------------------
app.listen(PORT, () => {
  console.log(`bsp-licensing-webhook listening on ${PORT}`);
});






