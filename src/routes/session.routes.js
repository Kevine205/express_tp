import { Router } from "express";
import { SessionController } from "#controllers/session.controller";
import { asyncHandler } from "#lib/async-handler";
import { authMiddleware } from "#middlewares/auth.middleware";

const router = Router();

// Liste des sessions actives (protégée)
router.get("/", authMiddleware, asyncHandler(SessionController.getActiveSessions));

export default router;
