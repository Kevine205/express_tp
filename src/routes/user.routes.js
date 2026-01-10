import express from 'express';
import { UserController } from '../controllers/user.controller.js';

const router = express.Router();

router.post('/register', UserController.register);
router.post('/login', UserController.login);
router.post('/forgot-password', UserController.forgotPassword);
router.get('/verify-email', UserController.verifyEmail);


router.post('/reset-password', UserController.resetPassword); 
router.post('/logout', UserController.logout);

export default router;