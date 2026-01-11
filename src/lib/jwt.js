import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import 'dotenv/config'; // Assure-toi que dotenv est bien là

/**
 * Fonction pour générer du "padding" aléatoire.
 * On génère environ 450 octets pour garantir un token > 1024 caractères.
 */
const generatePadding = () => crypto.randomBytes(450).toString('hex');

/**
 * Génère un Access Token (Court terme)
 * Utilise ACCESS_TOKEN_SECRET
 */
export const generateAccessToken = (user) => {
  const payload = {
    sub: user.id,
    email: user.email,
    // On ajoute du "padding" pour atteindre les 1024 caractères demandés
    padding: "x".repeat(1000) 
  };
  return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
};

/**
 * Génère un Refresh Token (Long terme)
 * Utilise REFRESH_TOKEN_SECRET
 */
export const generateRefreshToken = (user) => {
  const payload = {
    sub: user.id,
    _session_data: generatePadding()
  };

  return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
};

/**
 * Vérification des tokens
 */
export const verifyAccessToken = (token) => jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
export const verifyRefreshToken = (token) => jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);