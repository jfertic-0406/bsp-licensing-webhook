'use strict';

const express = require('express');
const crypto = require('crypto');
const Stripe = require('stripe');

const app = express();

// -------------------- Config --------------------
const PORT = process.env.PORT || 8080;

// Stripe
const STRIPE_SECRET = process.env.STRIPE_SECRET; // sk_test_... or sk_live_...
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET; // whsec_...

if (!STRIPE_SECRET) console.warn('Missing env var STRIPE_SECRET');
if (!STRIPE_WEBHOOK_SECRET) console.warn('Missing env var STRIPE_WEBHOOK_SECRET');

const stripe = Stripe(STRIPE_SECRET);

// Firestore (uses Cloud Run service account via ADC)
const admin = require('firebase-admin');

if (!admin.apps.length) {
  admin.initializeApp(); // Cloud Run will use the service account automatically
}

const firestore = admin.firestore();


// -------------------- Helpers --------------------
function makeLicenseKey() {
  // human-friendly-ish key
  // Example: BSP-9F3A7C2D-4B1E6A0C
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
  res.json({ ok: true, service: 'bsp-licensing-webhook', ts: nowIso() });
});

// IMPORTANT: Stripe webhook must use RAW body, not JSON parser
app.post('/webhook/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];

  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,                 // raw Buffer
      sig,
      STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('⚠️  Stripe signature verify failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    // We care about one-time purchase completion
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;

      // Try to get an email
      const email =
        session.customer_details?.email ||
        session.customer_email ||
        null;

      // If you used metadata in Checkout Link / session creation, it will be here:
      const metadata = session.metadata || {};

      // Make a license document
      const licenseKey = makeLicenseKey();

      const doc = {
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

      // Write to Firestore:
      // Collection: licenses
      // Document ID: licenseKey (easy lookups)
      await firestore.collection('licenses').doc(licenseKey).set(doc, { merge: true });

      console.log('✅ checkout.session.completed -> Firestore write OK', {
        email,
        licenseKey,
        sessionId: session.id,
      });
    } else {
      // Optional: log other events while you’re wiring things up
      console.log('ℹ️ event received:', event.type);
    }

    return res.sendStatus(200);
  } catch (err) {
    console.error('🔥 webhook handler error:', err);
    // Return 500 so Stripe retries (helps you catch issues during setup)
    return res.status(500).send('Server error');
  }
});

// For any accidental hits to unknown paths
app.use((req, res) => res.status(404).json({ ok: false, error: 'Not found' }));

// -------------------- Start --------------------
app.listen(PORT, () => {
  console.log(`bsp-licensing-webhook listening on ${PORT}`);
});




