// Protected routes: only logged-in users
exports.requireAuth = (req, res, next) => {
  if (req.session.user) return next();
  req.session.flash = { type: 'error', message: 'Please log in to view that page.' };
  res.redirect('/login');
};

// Guest-only routes (login/register) – logged-in users go to dashboard
exports.guestOnly = (req, res, next) => {
  if (req.session.user) return res.redirect('/dashboard');
  next();
};
