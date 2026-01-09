import { SessionService } from "#services/session.service";

export class SessionController {
  /**
   * Récupérer les sessions actives de l'utilisateur connecté
   */
  static async getActiveSessions(req, res) {
    const userId = req.user.sub; // Depuis le token via authMiddleware
    const sessions = await SessionService.getActiveSessions(userId);
    res.json({
      success: true,
      sessions,
    });
  }
}
