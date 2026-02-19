// index.js
'use strict';

const express = require('express');
const app = express();

// IMPORTANT: Stripe webhooks require RAW body for signature verification.
// Do NOT put express.json() before the webhook route.

app.get('/status', (req, res) => {
  res.json({ ok: true, service: 'bsp-licensing-webhook' });
});

// Load Stripe using your SECRET key from Cloud Run env var
const stripe = require('stripe')(process.env.STRIPE_SECRET);

// Accept webhook on multiple paths so you never break the working endpoint.
// Keep '/' LAST if you also want the base URL to accept Stripe POSTs.
const webhookPaths = ['/webhook/stripe', '/stripe', '/'];

app.post(
  webhookPaths,
  express.raw({ type: 'application/json' }),
  (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body, // raw buffer
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error('⚠️ Stripe signature verify failed:', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    console.log('✅ Stripe webhook verified:', event.type, 'eventId:', event.id);

    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      console.log('🎉 checkout.session.completed', {
        id: session.id,
        email: session.customer_details?.email || session.customer_email || null,
        client_reference_id: session.client_reference_id || null,
        mode: session.mode || null,
      });
      // Next step later: write license record to Firestore + email license
    }

    return res.sendStatus(200);
  }
);

// Everything else can be normal JSON AFTER the webhook route
app.use(express.json());

const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`bsp-licensing-webhook listening on ${port}`));
