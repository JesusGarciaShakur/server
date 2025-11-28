const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const express = require("express");
const router = express.Router();
const validateToken = require("../middlewares/validate-token");

router.post("/create-payment-intent", validateToken, async (req, res) => {
  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount: req.body.amount * 100,
      currency: "usd",
      description: "Proyecto Groovix",
    });

    return res.status(200).json({ clientSecret: paymentIntent.client_secret });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});


module.exports = router;