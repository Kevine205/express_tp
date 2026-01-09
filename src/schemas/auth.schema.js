const { z } = require('zod');

// Schéma pour l'inscription
const registerSchema = z.object({
  body: z.object({
    email: z.string().email("Format d'email invalide"),
    password: z.string().min(8, "Le mot de passe doit faire au moins 8 caractères"),
    name: z.string().min(2, "Le nom est trop court").optional(),
  }),
});

// Schéma pour la connexion
const loginSchema = z.object({
  body: z.object({
    email: z.string().email("Format d'email invalide"),
    password: z.string().min(1, "Le mot de passe est requis"),
  }),
});

module.exports = { registerSchema, loginSchema };