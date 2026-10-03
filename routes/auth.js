const crypto = require('crypto');
const express = require('express');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const { requireAuth, guestOnly } = require('../middleware/auth');

const router = express.Router();

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) =>
    res.status(429).render('error', { message: 'Too many attempts. Please try again in 15 minutes.' }),
});

const passwordRule = (field) =>
  body(field)
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
    .matches(/[A-Z]/).withMessage('Password needs an uppercase letter')
    .matches(/[a-z]/).withMessage('Password needs a lowercase letter')
    .matches(/[0-9]/).withMessage('Password needs a number');

const confirmRule = body('confirm')
  .custom((v, { req }) => v === req.body.password)
  .withMessage('Passwords do not match');

const errorList = (req) => validationResult(req).array().map((e) => e.msg);

// Regenerate the session on login to prevent session fixation
const startSession = (req, user, cb) => {
  req.session.regenerate((err) => {
    if (err) return cb(err);
    req.session.user = { id: user._id.toString(), name: user.name, email: user.email };
    req.session.save(cb);
  });
};

router.get('/', (req, res) => res.render('home'));

// ---------- Sign up ----------
router.get('/register', guestOnly, (req, res) => res.render('register'));

router.post(
  '/register',
  guestOnly,
  authLimiter,
  [
    body('name').trim().isLength({ min: 2, max: 50 }).withMessage('Name must be 2-50 characters'),
    body('email').trim().toLowerCase().isEmail().withMessage('Enter a valid email address'),
    passwordRule('password'),
    confirmRule,
  ],
  async (req, res, next) => {
    try {
      const errors = errorList(req);
      const values = { name: req.body.name, email: req.body.email };
      if (errors.length) return res.status(400).render('register', { errors, values });

      if (await User.findOne({ email: req.body.email })) {
        return res.status(400).render('register', { errors: ['An account with this email already exists'], values });
      }
      const user = await User.create({ name: req.body.name, email: req.body.email, password: req.body.password });
      startSession(req, user, (err) => {
        if (err) return next(err);
        req.session.flash = { type: 'success', message: 'Account created. Welcome!' };
        res.redirect('/dashboard');
      });
    } catch (err) {
      next(err);
    }
  }
);

// ---------- Login ----------
router.get('/login', guestOnly, (req, res) => res.render('login'));

router.post(
  '/login',
  guestOnly,
  authLimiter,
  [body('email').trim().toLowerCase().isEmail().withMessage('Enter a valid email address'),
   body('password').notEmpty().withMessage('Password is required')],
  async (req, res, next) => {
    try {
      const errors = errorList(req);
      const values = { email: req.body.email };
      if (errors.length) return res.status(400).render('login', { errors, values });

      const user = await User.findOne({ email: req.body.email });
      // Same message for unknown email / wrong password (prevents user enumeration)
      if (!user || !(await user.comparePassword(req.body.password))) {
        return res.status(401).render('login', { errors: ['Invalid email or password'], values });
      }
      startSession(req, user, (err) => {
        if (err) return next(err);
        req.session.flash = { type: 'success', message: 'Logged in successfully.' };
        res.redirect('/dashboard');
      });
    } catch (err) {
      next(err);
    }
  }
);

// ---------- Logout (POST so it can't be triggered by a link/image) ----------
router.post('/logout', (req, res, next) => {
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie('sid');
    res.redirect('/login');
  });
});

// ---------- Protected route ----------
router.get('/dashboard', requireAuth, (req, res) => res.render('dashboard'));

// ---------- Forgot password ----------
router.get('/forgot-password', guestOnly, (req, res) => res.render('forgot'));

async function sendResetEmail(to, link) {
  if (!process.env.SMTP_HOST) {
    console.log(`[DEV] Password reset link for ${to}: ${link}`);
    return;
  }
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
  await transporter.sendMail({
    from: process.env.MAIL_FROM,
    to,
    subject: 'Reset your password',
    text: `Use this link to reset your password (valid for 15 minutes):\n\n${link}\n\nIf you did not request this, ignore this email.`,
  });
}

router.post(
  '/forgot-password',
  guestOnly,
  authLimiter,
  [body('email').trim().toLowerCase().isEmail().withMessage('Enter a valid email address')],
  async (req, res, next) => {
    try {
      const errors = errorList(req);
      if (errors.length) return res.status(400).render('forgot', { errors, values: { email: req.body.email } });

      const user = await User.findOne({ email: req.body.email });
      const flash = { type: 'success', message: 'If that email is registered, a reset link has been sent.' };

      if (user) {
        const token = crypto.randomBytes(32).toString('hex');
        // Only the hash is stored – a DB leak does not expose usable tokens
        user.resetTokenHash = crypto.createHash('sha256').update(token).digest('hex');
        user.resetTokenExpires = Date.now() + 15 * 60 * 1000;
        await user.save();

        const link = `${process.env.BASE_URL}/reset-password/${token}`;
        await sendResetEmail(user.email, link);
        if (process.env.DEMO_SHOW_RESET_LINK === 'true') {
          flash.message = 'Demo mode: use this link to reset your password (valid 15 minutes).';
          flash.link = link;
        }
      }
      req.session.flash = flash;
      res.redirect('/forgot-password');
    } catch (err) {
      next(err);
    }
  }
);

// ---------- Reset password ----------
const findByToken = (token) =>
  User.findOne({
    resetTokenHash: crypto.createHash('sha256').update(token).digest('hex'),
    resetTokenExpires: { $gt: Date.now() },
  });

router.get('/reset-password/:token', guestOnly, async (req, res, next) => {
  try {
    const user = await findByToken(req.params.token);
    if (!user) return res.status(400).render('error', { message: 'Reset link is invalid or has expired.' });
    res.render('reset', { token: req.params.token });
  } catch (err) {
    next(err);
  }
});

router.post('/reset-password/:token', guestOnly, authLimiter, [passwordRule('password'), confirmRule], async (req, res, next) => {
  try {
    const user = await findByToken(req.params.token);
    if (!user) return res.status(400).render('error', { message: 'Reset link is invalid or has expired.' });

    const errors = errorList(req);
    if (errors.length) return res.status(400).render('reset', { errors, token: req.params.token });

    user.password = req.body.password;
    user.resetTokenHash = undefined; // single use
    user.resetTokenExpires = undefined;
    await user.save();

    req.session.flash = { type: 'success', message: 'Password updated. Please log in.' };
    res.redirect('/login');
  } catch (err) {
    next(err);
  }
});

module.exports = router;
