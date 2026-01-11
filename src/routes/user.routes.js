import express from 'express';
import { UserController } from '../controllers/user.controller.js';
import { authMiddleware } from '../middlewares/auth.middleware.js'; // Import du middleware

const router = express.Router();

// --- ROUTES PUBLIQUES ---
router.post('/register', UserController.register);
router.post('/login', UserController.login);
router.post('/forgot-password', UserController.forgotPassword);
router.get('/verify-email', UserController.verifyEmail);
router.post('/reset-password', UserController.resetPassword);

// [DÉVELOPPEUR 3] - Route de connexion étape 2 (après mot de passe)
router.post('/verify-2fa', UserController.verify2FA); 

// --- ROUTES PROTÉGÉES (Nécessitent un Access Token valide) ---

// [DÉVELOPPEUR 3] - Configuration de la sécurité
router.post('/2fa/setup', authMiddleware, UserController.setup2FA);    // Générer le QR Code
router.post('/2fa/activate', authMiddleware, UserController.confirm2FA); // Activer le 2FA

// La déconnexion doit être protégée pour pouvoir blacklister le token actuel
router.post('/logout', authMiddleware, UserController.logout);

export default router;