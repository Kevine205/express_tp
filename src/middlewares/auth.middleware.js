import { verifyAccessToken } from '#lib/jwt';
import { UnauthorizedException } from '#lib/exceptions';
import prisma from "#lib/prisma"; 

export const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    throw new UnauthorizedException("Token manquant");
  }

  const token = authHeader.split(' ')[1];

  try {
    const isBlacklisted = await prisma.blacklistedAccessToken.findUnique({
      where: { token }
    });

    if (isBlacklisted) {
      throw new UnauthorizedException("Ce token a été révoqué (déconnexion)");
    }

    const decoded = verifyAccessToken(token);
    req.user = decoded;
    req.currentToken = token; // Utile pour la déconnexion
    next();
  } catch (error) {
    throw new UnauthorizedException(error.message || "Token invalide");
  }
};