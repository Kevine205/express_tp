import { defineConfig } from '@prisma/config'; // Vérifie bien l'import ici

export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrations: {
    directory: 'prisma/migrations',
  },
  datasource: {
    url: process.env.DATABASE_URL || 'file:./dev.db',
  },
});