import { UserService } from "#services/user.service";
import { UserDto } from "#dto/user.dto";
import { validateData } from "#lib/validate";
import { registerSchema, loginSchema } from "#schemas/user.schema";

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

    // 2. Récupération des infos de contexte pour l'historique (Lead Architect)
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
}