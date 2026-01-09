import prisma from "#lib/prisma";

export class SessionService {
  /**
   * Liste des sessions actives pour un utilisateur
   */
  static async getActiveSessions(userId) {
    return prisma.refreshToken.findMany({
      where: {
        userId: parseInt(userId),
        revokedAt: null,
        expiresAt: { gt: new Date() }
      },
      select: {
        id: true,
        expiresAt: true,
        createdAt: true
      }
    });
  }
}