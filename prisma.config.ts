import { defineConfig } from '@prisma/config'; // Vérifie bien l'import ici

export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrations: {
    directory: 'prisma/migrations',
  },
  datasource: {
    // On met une valeur de secours si le .env n'est pas encore lu
    url: process.env.DATABASE_URL || 'file:./dev.db',
  },
});