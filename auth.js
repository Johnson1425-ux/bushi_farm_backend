const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET || 'milktrack-secret-change-me';

function verifyToken(req, res, next) {
  const header = req.headers['authorization'];
  const token  = header && header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

module.exports = { verifyToken, requireAdmin, SECRET };
