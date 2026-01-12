import { UserService } from "#services/user.service";
import { UserDto } from "#dto/user.dto";
import { validateData } from "#lib/validate";
import { registerSchema, loginSchema } from "#schemas/user.schema";
import * as emailService from "#services/email.service";

export class UserController {
  static async register(req, res) {
    const validatedData = validateData(registerSchema, req.body);
    const user = await UserService.register(validatedData);
    res.status(201).json({
      success: true,
      message: "Utilisateur créé avec succès",
      user: UserDto.transform(user),
    });
  }

  static async login(req, res) {
    const validatedData = validateData(loginSchema, req.body);
    const { email, password } = validatedData;
    const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const userAgent = req.get('user-agent');

    const result = await UserService.login(email, password, ip, userAgent);

    // GESTION DU FLUX 2FA (D3)
    if (result.requires2FA) {
      return res.json({
        success: true,
        requires2FA: true,
        userId: result.userId,
        message: result.message
      });
    }

    // FLUX NORMAL (D1)
    res.json({
      success: true,
      user: UserDto.transform(result.user),
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
    });
  }

  // NOUVELLE MÉTHODE : Vérification 2FA (D3)
  static async verify2FA(req, res) {
    const { userId, totpCode } = req.body;
    const ip = req.ip || req.get('x-forwarded-for') || req.socket.remoteAddress;
    const userAgent = req.get('user-agent');

    const result = await UserService.verify2FAAndLogin(userId, totpCode, ip, userAgent);

    res.json({
      success: true,
      user: UserDto.transform(result.user),
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
    });
  }

  static async logout(req, res) {
    const { refreshToken } = req.body;
    // Récupérer le Bearer token pour la blacklist (D3)
    const authHeader = req.headers.authorization;
    const accessToken = authHeader ? authHeader.split(' ')[1] : null;

    if (!refreshToken) {
      return res.status(400).json({ success: false, message: "Token requis" });
    }

    await UserService.logout(refreshToken, accessToken);

    res.json({
      success: true,
      message: "Déconnexion réussie (session révoquée et token blacklisté).",
    });
  }

  // --- Garder le reste (forgotPassword, resetPassword, etc.) ---
  static async forgotPassword(req, res) {
    const { email } = req.body;
    const token = await UserService.createPasswordResetToken(email);
    if (token) await emailService.sendResetEmail(email, token);
    res.json({ success: true, message: "Si ce compte existe, un e-mail de récupération a été envoyé." });
  }

  static async resetPassword(req, res) {
    const { token, newPassword } = req.body;
    await UserService.resetPassword(token, newPassword);
    res.json({ success: true, message: "Mot de passe réinitialisé avec succès." });
  }

  static async verifyEmail(req, res) {
    const { token } = req.query;
    await UserService.verifyEmail(token);
    res.json({ success: true, message: "Votre e-mail a été vérifié avec succès !" });
  }

  static async getAll(req, res) {
    const users = await UserService.findAll();
    res.json({ success: true, users: UserDto.transform(users) });
  }

  static async getById(req, res) {
    const user = await UserService.findById(req.params.id);
    res.json({ success: true, user: UserDto.transform(user) });
  }

  /**
   * [D3] - Génération du secret 2FA et du QR Code (Setup)
   */
  static async setup2FA(req, res) {
    // On vérifie 'id' OU 'sub' car les middlewares JWT utilisent souvent 'sub'
    const userId = req.user?.id || req.user?.sub;

    if (!userId) {
      return res.status(401).json({ 
        success: false, 
        message: "Session utilisateur invalide (ID manquant)" 
      });
    }

    const { secret, qrCodeUrl } = await UserService.generate2FA(userId);
    
    res.json({
      success: true,
      secret,
      qrCodeUrl
    });
  }

  /**
   * [D3] - Activer le 2FA après vérification du code
   */
  static async activate2FA(req, res) {
    const userId = req.user?.id || req.user?.sub;
    const { totpCode } = req.body;

    if (!userId) {
      return res.status(401).json({ 
        success: false, 
        message: "Session utilisateur invalide (ID manquant)" 
      });
    }

    await UserService.activate2FA(userId, totpCode);

    res.json({
      success: true,
      message: "2FA activé avec succès"
    });
  }
}