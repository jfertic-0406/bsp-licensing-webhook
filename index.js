'use strict';

const express = require('express');
const Stripe = require('stripe');
const admin = require('firebase-admin');

const app = express();

// ---- Required env vars (set in Cloud Run) ----
// STRIPE_SECRET_KEY          = sk_test_...
// STRIPE_WEBHOOK_SECRET      = whsec_...
// (optional) FIRESTORE_COLLECTION = "licenses"
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

const COLLECTION = process.env.FIRESTORE_COLLECTION || 'licenses';

// Firestore Admin SDK uses Cloud Run’s service account automatically (no JSON key file)
if (!admin.apps.length) {
  admin.initializeApp();
}
const db = admin.firestore();

// Stripe needs RAW body for signature verification on this route only
app.post('/webhook/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err) {
    console.error('⚠️ Stripe signature verify failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;

      // Grab customer email (Stripe sometimes stores it in customer_details)
      const email =
        session.customer_details?.email ||
        session.customer_email ||
        null;

      // What you store is up to you — this is a solid minimal license record
      const docId = session.id; // stable + unique
      await db.collection(COLLECTION).doc(docId).set(
        {
          sessionId: session.id,
          email,
          amount_total: session.amount_total || null,
          currency: session.currency || null,
          payment_status: session.payment_status || null,
          mode: session.mode || null,
          created: admin.firestore.FieldValue.serverTimestamp(),
          livemode: !!event.livemode
        },
        { merge: true }
      );

      console.log('✅ Stored license record for:', email, 'session:', session.id);
    }

    return res.sendStatus(200);
  } catch (err) {
    console.error('🔥 Webhook handler error:', err);
    // Tell Stripe “we got it” ONLY if you want to avoid retries.
    // For now, return 500 so you notice failures during testing.
    return res.sendStatus(500);
  }
});

// For non-webhook routes, use normal JSON parsing
app.use(express.json());

app.get('/status', (req, res) => {
  res.json({ ok: true, service: 'bsp-licensing-webhook' });
});

// Cloud Run port binding
const port = process.env.PORT || 8080;
app.listen(port, '0.0.0.0', () => {
  console.log(`bsp-licensing-webhook listening on ${port}`);
});


