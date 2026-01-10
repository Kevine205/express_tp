import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT),
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});


export const sendResetEmail = async (email, token) => {
  const url = `http://localhost:3000/auth/reset-password?token=${token}`;
  
  const info = await transporter.sendMail({
    from: '"Sécurité TP" <admin@tp-auth.com>',
    to: email,
    subject: "Réinitialisation de mot de passe",
    html: `<p>Utilisez ce lien pour changer votre mot de passe (Token 1024 chars) :</p>
           <a href="${url}">${url}</a>`,
  });

  console.log("✉️ Email de reset envoyé ! Preview : %s", nodemailer.getTestMessageUrl(info));
};