import prisma from "#lib/prisma";
import { hashPassword, verifyPassword } from "#lib/password";
import { ConflictException, UnauthorizedException, NotFoundException } from "#lib/exceptions";
import { generateAccessToken, generateRefreshToken } from '#lib/jwt'; 
import { generateLongToken } from "../lib/token.js";


export class UserService {
  /**
   * Inscription d'un nouvel utilisateur
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
   * Connexion avec génération de tokens et historique
   */
  static async login(email, password, ip = "unknown", userAgent = "unknown") {
    const user = await prisma.user.findUnique({ where: { email } });

    // 1. Vérification des identifiants
    if (!user || !(await verifyPassword(user.password, password))) {
      // On log l'échec dans l'historique si l'utilisateur existe
      if (user) {
        await prisma.loginHistory.create({
          data: { userId: user.id, ip, userAgent, success: false }
        });
      }
      throw new UnauthorizedException("Identifiants invalides");
    }

    // 2. Génération des tokens (JWT avec padding > 1024 octets)
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    // 3. Calcul de l'expiration du Refresh Token (7 jours)
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    // 4. Transaction : Création de la session + Historique de succès
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
   * Déconnexion (Révocation du Refresh Token)
   */
  static async logout(refreshToken) {
    const tokenRecord = await prisma.refreshToken.findUnique({
      where: { token: refreshToken }
    });

    if (!tokenRecord) return; // Déjà déconnecté ou token inexistant

    await prisma.refreshToken.update({
      where: { token: refreshToken },
      data: { revokedAt: new Date() }
    });
  }

  /**
   * Liste tous les utilisateurs
   */
  static async findAll() {
    return prisma.user.findMany({
      select: { id: true, email: true, name: true, createdAt: true }
    });
  }

  /**
   * Trouver un utilisateur par son ID
   */
  static async findById(id) {
    const user = await prisma.user.findUnique({ 
      where: { id: parseInt(id) } 
    });

    if (!user) {
      throw new NotFoundException("Utilisateur non trouvé");
    }

    return user;
  }

  /**
   * Générer un token pour mot de passe oublié 
   */
  static async createPasswordResetToken(email) {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return null;

  
    const token = generateLongToken(); 
    const expiresAt = new Date(Date.now() + 3600000); 

    await prisma.passwordResetToken.create({
      data: { token, userId: user.id, expiresAt }
    });

    return token;
  }

  /**
   * Vérification de l'adresse email 
   */
  static async verifyEmail(token) {
    const tokenRecord = await prisma.verificationToken.findUnique({
      where: { token }
    });

    if (!tokenRecord || tokenRecord.expiresAt < new Date()) {
      throw new UnauthorizedException("Token invalide ou expiré");
    }

    await prisma.$transaction([
      prisma.user.update({
        where: { id: tokenRecord.userId },
        data: { emailVerifiedAt: new Date() }
      }),
      prisma.verificationToken.delete({
        where: { id: tokenRecord.id } 
      })
    ]);
  }

  /**
   * Réinitialisation finale du mot de passe 
   */
  static async resetPassword(token, newPassword) {
    const tokenRecord = await prisma.passwordResetToken.findUnique({
      where: { token }
    });

    if (!tokenRecord || tokenRecord.expiresAt < new Date()) {
      throw new UnauthorizedException("Lien invalide ou expiré");
    }

    const hashedPassword = await hashPassword(newPassword);

    await prisma.$transaction([
      prisma.user.update({
        where: { id: tokenRecord.userId },
        data: { password: hashedPassword }
      }),
      prisma.passwordResetToken.delete({
        where: { id: tokenRecord.id }
      })
    ]);
  }
}