import { UserService } from "#services/user.service";
import { UserDto } from "#dto/user.dto";
import { validateData } from "#lib/validate";
import { registerSchema, loginSchema } from "#schemas/user.schema";
import * as emailService from "#services/email.service"; 

export class UserController {
  /**
   * Inscription
   */
  static async register(req, res) {
    // 1. Validation des entrées
    const validatedData = validateData(registerSchema, req.body);
    
    // 2. Appel au service
    const user = await UserService.register(validatedData);

    // 3. Réponse (On ne génère généralement pas de token ici, 
    // l'utilisateur devra se connecter, ou on peut le faire si on veut une auto-connexion)
    res.status(201).json({
      success: true,
      message: "Utilisateur créé avec succès",
      user: UserDto.transform(user),
    });
  }

  /**
   * Connexion
   */
  static async login(req, res) {
    // 1. Validation des entrées
    const validatedData = validateData(loginSchema, req.body);
    const { email, password } = validatedData;

    // 2. Récupération des infos de contexte pour l'historique
    const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const userAgent = req.get('user-agent');

    // 3. Appel au service (qui génère tokens + sessions + historique)
    const { user, accessToken, refreshToken } = await UserService.login(
      email, 
      password, 
      ip, 
      userAgent
    );

    // 4. Réponse avec les deux tokens
    res.json({
      success: true,
      user: UserDto.transform(user),
      accessToken,
      refreshToken,
    });
  }

  /**
   * Récupérer tous les utilisateurs (Route protégée par admin normalement)
   */
  static async getAll(req, res) {
    const users = await UserService.findAll();
    res.json({
      success: true,
      users: UserDto.transform(users),
    });
  }

  /**
   * Récupérer un utilisateur par ID
   */
  static async getById(req, res) {
    const user = await UserService.findById(req.params.id);
    res.json({
      success: true,
      user: UserDto.transform(user),
    });
  }
  
  /**
   * Mot de passe oublié
   */
  static async forgotPassword(req, res) {
    const { email } = req.body;

    // 1. Appel au service pour créer le token en base
    const token = await UserService.createPasswordResetToken(email);


    // Le token est dans le mail, PAS dans la réponse JSON
    if (token) {
      await emailService.sendResetEmail(email, token);
    }

    // Réponse neutre pour la sécurité (ne pas confirmer si l'email existe)
    res.json({
      success: true,
      message: "Si ce compte existe, un e-mail de récupération a été envoyé.",
    });
  }

  /**
   * Vérification de l'email
   */
  static async verifyEmail(req, res) {
  
    const { token } = req.query;

    if (!token) {
      return res.status(400).json({ success: false, message: "Token manquant" });
    }

    // Appel au service pour valider
    await UserService.verifyEmail(token);

    res.json({
      success: true,
      message: "Votre e-mail a été vérifié avec succès !",
    });
  }

  /**
   * Déconnexion 
   * Invalide le Refresh Token en base de données
   */
  static async logout(req, res) {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ success: false, message: "Token requis" });
    }

  
    await UserService.logout(refreshToken);

    res.json({
      success: true,
      message: "Déconnexion réussie et session invalidée.",
    });
  }


  /**
   * Réinitialisation effective du mot de passe
   */
  static async resetPassword(req, res) {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ success: false, message: "Données manquantes" });
    }

    await UserService.resetPassword(token, newPassword);

    res.json({
      success: true,
      message: "Mot de passe réinitialisé avec succès.",
    });
  }
}