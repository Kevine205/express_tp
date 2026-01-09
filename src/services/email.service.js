import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT),
  secure: false, 
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

export const sendResetEmail = async (email, token) => {
  const link = `http://localhost:3000/auth/reset-password?token=${token}`;
  
  await transporter.sendMail({
    from: '"Test Sécurité" <no-reply@test.com>',
    to: email,
    subject: "Réinitialisation de mot de passe",
    html: `<p>Reset : <a href="${link}">${link}</a></p>`
  });
};