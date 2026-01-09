import 'dotenv/config';
import { PrismaClient } from '@prisma/client';

// 1. On définit l'URL en dur si le .env ne répond pas
const DB_URL = process.env.DATABASE_URL || "file:./prisma/dev.db";

// 2. FORCE : On injecte directement dans process.env pour le moteur Rust de Prisma
process.env.DATABASE_URL = DB_URL;

// 3. Initialisation du PrismaClient avec moteur binaire forcé
const prisma = new PrismaClient({
  __internal: {
    engine: 'binary'
  }
});

console.log(`✅ Prisma injecté avec succès sur : ${DB_URL}`);

export { prisma };
export default prisma;