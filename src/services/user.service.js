import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const otplib = require('otplib');

// Plus besoin de chercher .authenticator, on utilise l'objet otplib directement
console.log('✅ Utilisation des fonctions directes de otplib');
import prisma from "#lib/prisma";
import { hashPassword, verifyPassword } from "#lib/password";
import { ConflictException, UnauthorizedException, NotFoundException } from "#lib/exceptions";
import { generateAccessToken, generateRefreshToken } from '#lib/jwt'; 
import { generateLongToken } from "../lib/token.js";
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
  // On s'assure que l'ID existe et est un nombre
  const numericId = parseInt(id);
  if (isNaN(numericId)) {
    throw new Error("ID utilisateur invalide ou manquant");
  }

  const user = await prisma.user.findUnique({ where: { id: numericId } });
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
  /**
   * [D3] - Générer un secret 2FA et l'URL du QR Code
   */
  static async generate2FA(userId) {
    const id = parseInt(userId);
    const user = await prisma.user.findUnique({ where: { id } });
    
    if (!user) throw new NotFoundException("Utilisateur non trouvé");

    // 1. Génération du secret
    const secret = authenticator.generateSecret();
    
    // 2. DEBUG : On vérifie que rien n'est undefined
    console.log('DEBUG 2FA:', {
      email: user.email,
      issuer: "MonAppExpress",
      secret: secret ? "Généré ✅" : "VIDE ❌"
    });

    // 3. Génération de l'URL (Utilisation de la méthode la plus compatible)
    // On utilise keyuri si dispo, sinon generateURI
    const keyuriFn = authenticator.keyuri || authenticator.generateURI;
    
    if (typeof keyuriFn !== 'function') {
        throw new Error("Impossible de trouver la fonction de génération d'URL dans otplib");
    }

    const otpauthUrl = keyuriFn(
      user.email,
      "MonAppExpress",
      secret
    );

    // 4. Update DB
    await prisma.user.update({
      where: { id },
      data: { twoFactorSecret: secret }
    });

    return { secret, qrCodeUrl: otpauthUrl };
  }

  /**
   * [D3] - Activer officiellement le 2FA après vérification d'un premier code
   */
  static async activate2FA(userId, totpCode) {
    const user = await this.findById(userId);

    if (!user.twoFactorSecret) {
      throw new Error("Le secret 2FA n'a pas été généré.");
    }

    // Vérifier si le code fourni par l'utilisateur est correct
    const isValid = authenticator.check(totpCode, user.twoFactorSecret);

    if (!isValid) {
      throw new UnauthorizedException("Code de confirmation 2FA invalide");
    }

    // Activer officiellement le 2FA
    await prisma.user.update({
      where: { id: userId },
      data: { twoFactorEnabledAt: new Date() }
    });
  }
}