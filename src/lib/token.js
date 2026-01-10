import crypto from 'crypto';

// 512 bytes = 1024 caractères hexadécimaux
export const generateLongToken = () => {
  return crypto.randomBytes(512).toString('hex');
};