"use strict";

const express = require("express");
const Stripe = require("stripe");

const app = express();

// Health checks
app.get("/", (req, res) => res.status(200).send("bsp-licensing-webhook ok"));
app.get("/status", (req, res) =>
  res.status(200).json({ ok: true, service: "bsp-licensing-webhook" })
);

// Stripe webhook: POST to "/" (base URL)
// IMPORTANT: must use raw body for signature verification
app.post("/", express.raw({ type: "application/json" }), (req, res) => {
  const STRIPE_SECRET = process.env.STRIPE_SECRET || "";
  const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";

  if (!STRIPE_SECRET || !STRIPE_WEBHOOK_SECRET) {
    console.error("Missing STRIPE_SECRET or STRIPE_WEBHOOK_SECRET");
    return res.status(500).send("Stripe not configured");
  }

  const stripe = new Stripe(STRIPE_SECRET);

  const sig = req.headers["stripe-signature"];
  if (!sig) return res.status(400).send("Missing Stripe-Signature header");

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error("⚠️ Webhook signature verify failed:", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  console.log("✅ Stripe webhook verified:", event.type, "eventId:", event.id);

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const buyerEmail =
      session.customer_email ||
      (session.customer_details && session.customer_details.email) ||
      null;

    console.log("🧾 checkout.session.completed:", {
      id: session.id,
      email: buyerEmail,
      client_reference_id: session.client_reference_id || null,
      mode: session.mode || null,
    });

    // TODO later: issue license + store + email
  }

  return res.sendStatus(200);
});

// Cloud Run uses PORT env var
const PORT = parseInt(process.env.PORT || "8080", 10);
app.listen(PORT, () => console.log("bsp-licensing-webhook listening on", PORT));
