import { verifyAccessToken } from '#lib/jwt';
import { UnauthorizedException } from '#lib/exceptions';

export const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    throw new UnauthorizedException("Token manquant");
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = verifyAccessToken(token);
    req.user = decoded; // On attache l'id (sub) et l'email à la requête
    next();
  } catch (error) {
    throw new UnauthorizedException("Token invalide ou expiré");
  }
};