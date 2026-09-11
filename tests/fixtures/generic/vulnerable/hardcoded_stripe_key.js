// Fixture vulnérable : clé Stripe Secret hardcodée
const stripe = require('stripe');

const STRIPE_KEY = "sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZab";

const client = stripe(STRIPE_KEY);
const charge = client.charges.create({ amount: 1000, currency: 'eur' });
