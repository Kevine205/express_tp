import { authenticator } from 'otplib';
import QRCode from 'qrcode';
import prisma from "#lib/prisma";
import { UnauthorizedException, NotFoundException } from "#lib/exceptions";

export class SecurityService {
  
  /**
   * Générer le secret et le QR Code
   */
  static async generate2FA(userId) {
    // Vérification : l'utilisateur existe-t-il ?
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new NotFoundException("Utilisateur non trouvé");

    const secret = authenticator.generateSecret();
    
    // Sauvegarde du secret (non encore activé)
    await prisma.user.update({
      where: { id: userId },
      data: { twoFactorSecret: secret }
    });

    // Utilisation d'un nom d'app explicite pour l'appli mobile (Google Auth)
    const otpauth = authenticator.keyuri(user.email, 'Alade-Secure-API', secret);
    const qrCodeUrl = await QRCode.toDataURL(otpauth);

    return { secret, qrCodeUrl };
  }

  /**
   * Confirmer et activer le 2FA
   */
  static async activate2FA(userId, code) {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    
    // Sécurité : Vérifier si un secret a bien été généré auparavant
    if (!user || !user.twoFactorSecret) {
      throw new UnauthorizedException("Veuillez d'abord initialiser le 2FA (setup)");
    }

    // Vérification du code fourni par l'utilisateur
    const isValid = authenticator.check(code, user.twoFactorSecret);
    if (!isValid) throw new UnauthorizedException("Code 2FA invalide ou expiré");

    // Activation définitive
    await prisma.user.update({
      where: { id: userId },
      data: { twoFactorEnabledAt: new Date() }
    });
  }

  /**
   * Révoquer les sessions (Refresh Tokens)
   * @param {number} userId 
   * @param {string} currentToken - Le token à NE PAS révoquer (pour rester connecté sur l'appareil actuel)
   */
  static async revokeSessions(userId, currentToken = null) {
    await prisma.refreshToken.updateMany({
      where: {
        userId: userId,
        revokedAt: null, // On ne cible que celles qui sont encore actives
        // Si on fournit un token, on l'exclut de la révocation
        NOT: currentToken ? { token: currentToken } : undefined
      },
      data: { 
        revokedAt: new Date() 
      }
    });
  }

  /**
   * [AJOUT D3] Mettre un Access Token en Blacklist
   * Utile pour la déconnexion immédiate
   */
  static async blacklistToken(token, expiresAt) {
    await prisma.blacklistedAccessToken.create({
      data: {
        token,
        expiresAt: new Date(expiresAt * 1000) // Conversion timestamp Unix vers Date JS
      }
    });
  }
}