import { z } from "zod";

// [DÉVELOPPEUR 1 & 2]
export const registerSchema = z.object({
  email: z.string().email("Email invalide"),
  password: z.string().min(8, "Minimum 8 caractères"),
  name: z.string().min(2).optional(),
});

export const loginSchema = z.object({
  email: z.string().email("Email invalide"),
  password: z.string().min(1, "Mot de passe requis"),
});

// [DÉVELOPPEUR 3] - Validation pour confirmer l'activation du 2FA
export const activate2FASchema = z.object({
  code: z.string()
    .length(6, "Le code doit contenir exactement 6 chiffres")
    .regex(/^\d+$/, "Le code doit uniquement contenir des chiffres"),
});

// [DÉVELOPPEUR 3] - Validation pour la vérification lors du Login
export const verify2FASchema = z.object({
  userId: z.number().int().positive("ID utilisateur invalide"),
  code: z.string()
    .length(6, "Le code doit contenir exactement 6 chiffres")
    .regex(/^\d+$/, "Le code doit uniquement contenir des chiffres"),
});