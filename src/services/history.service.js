import { prisma } from '../lib/prisma.js';

export const logConnection = async (userId, ip, userAgent, success) => {
  await prisma.loginHistory.create({
    data: { userId, ip, userAgent, success }
  });
};