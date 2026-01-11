import prisma from "#lib/prisma";
import { hashPassword, verifyPassword } from "#lib/password";
import { ConflictException, UnauthorizedException, NotFoundException } from "#lib/exceptions";
import { generateAccessToken, generateRefreshToken } from '#lib/jwt'; 
import { generateLongToken } from "../lib/token.js";
import { authenticator } from 'otplib'; // À installer : npm install otplib
import jwt from 'jsonwebtoken';

export class UserService {
  /**
   * Inscription d'un nouvel utilisateur (D1/D2)
   */
  static async register(data) {
    const { email, password, name } = data;

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      throw new ConflictException("Email déjà utilisé");
    }

    const hashedPassword = await hashPassword(password);

    return prisma.user.create({
      data: { 
        email, 
        password: hashedPassword, 
        name 
      },
    });
  }

  /**
   * Connexion avec gestion 2FA (Mise à jour D3)
   */
  static async login(email, password, ip = "unknown", userAgent = "unknown") {
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user || !(await verifyPassword(user.password, password))) {
      if (user) {
        await prisma.loginHistory.create({
          data: { userId: user.id, ip, userAgent, success: false }
        });
      }
      throw new UnauthorizedException("Identifiants invalides");
    }

    // --- INTERCEPTION 2FA (D3) ---
    if (user.twoFactorEnabledAt && user.twoFactorSecret) {
      return {
        requires2FA: true,
        userId: user.id,
        message: "Authentification à deux facteurs requise."
      };
    }

    // Si pas de 2FA, on génère les tokens normalement (D1)
    return this.finalizeLogin(user, ip, userAgent);
  }

  /**
   * Finalisation de la connexion (Génération tokens + Session)
   * Centralisé pour être utilisé par login classique et login 2FA
   */
  static async finalizeLogin(user, ip, userAgent) {
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await prisma.$transaction([
      prisma.refreshToken.create({
        data: {
          token: refreshToken,
          userId: user.id,
          expiresAt: expiresAt
        }
      }),
      prisma.loginHistory.create({
        data: {
          userId: user.id,
          ip,
          userAgent,
          success: true
        }
      })
    ]);

    return {
      user: { id: user.id, email: user.email, name: user.name },
      accessToken,
      refreshToken
    };
  }

  /**
   * Vérification du code 2FA pour finaliser la connexion (D3)
   */
  static async verify2FAAndLogin(userId, totpCode, ip, userAgent) {
    const user = await prisma.user.findUnique({ where: { id: userId } });
    
    if (!user || !user.twoFactorSecret) {
      throw new UnauthorizedException("2FA non configuré");
    }

    const isValid = authenticator.check(totpCode, user.twoFactorSecret);
    if (!isValid) {
      throw new UnauthorizedException("Code 2FA invalide");
    }

    return this.finalizeLogin(user, ip, userAgent);
  }

  /**
   * Déconnexion avec Blacklist de l'Access Token (Mise à jour D3)
   */
  static async logout(refreshToken, accessToken) {
    // 1. Invalider le Refresh Token (D1)
    await prisma.refreshToken.updateMany({
      where: { token: refreshToken },
      data: { revokedAt: new Date() }
    });

    // 2. Blacklister l'Access Token (D3)
    if (accessToken) {
      const decoded = jwt.decode(accessToken);
      if (decoded && decoded.exp) {
        await prisma.blacklistedAccessToken.create({
          data: {
            token: accessToken,
            expiresAt: new Date(decoded.exp * 1000)
          }
        });
      }
    }
  }

  /**
   * Réinitialisation du mot de passe + Révocation sessions (Mise à jour D3)
   */
  static async resetPassword(token, newPassword) {
    const tokenRecord = await prisma.passwordResetToken.findUnique({
      where: { token },
      include: { user: true }
    });

    if (!tokenRecord || tokenRecord.expiresAt < new Date()) {
      throw new UnauthorizedException("Lien invalide ou expiré");
    }

    const hashedPassword = await hashPassword(newPassword);

    await prisma.$transaction([
      // Changer le mot de passe
      prisma.user.update({
        where: { id: tokenRecord.userId },
        data: { password: hashedPassword }
      }),
      // Supprimer le token de reset
      prisma.passwordResetToken.delete({
        where: { id: tokenRecord.id }
      }),
      // RÉVOCATION DE TOUTES LES SESSIONS (D3) : Sécurité accrue après changement de MDP
      prisma.refreshToken.updateMany({
        where: { userId: tokenRecord.userId, revokedAt: null },
        data: { revokedAt: new Date() }
      })
    ]);
  }

  // ... (Garder findAll, findById, createPasswordResetToken, verifyEmail inchangés) ...
  
  static async findAll() {
    return prisma.user.findMany({
      select: { id: true, email: true, name: true, createdAt: true }
    });
  }

  static async findById(id) {
    const user = await prisma.user.findUnique({ where: { id: parseInt(id) } });
    if (!user) throw new NotFoundException("Utilisateur non trouvé");
    return user;
  }

  static async createPasswordResetToken(email) {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return null;
    const token = generateLongToken(); 
    const expiresAt = new Date(Date.now() + 3600000); 
    await prisma.passwordResetToken.create({ data: { token, userId: user.id, expiresAt } });
    return token;
  }

  static async verifyEmail(token) {
    const tokenRecord = await prisma.verificationToken.findUnique({ where: { token } });
    if (!tokenRecord || tokenRecord.expiresAt < new Date()) throw new UnauthorizedException("Token invalide");
    await prisma.$transaction([
      prisma.user.update({ where: { id: tokenRecord.userId }, data: { emailVerifiedAt: new Date() } }),
      prisma.verificationToken.delete({ where: { id: tokenRecord.id } })
    ]);
  }
}