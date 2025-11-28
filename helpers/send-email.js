const nodemailer = require("nodemailer");

const sendEmail = async ({ email, subject, text, html }) => {
  try {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      host: "smtp.gmail.com",
      port: 587,
      secure: false,
      auth: {
        user: process.env.NODEMAILER_EMAIL,
        pass: process.env.NODEMAILER_PASSWORD,
      },
    });

    const mailOptions = {
      from: `SheyEvents <${process.env.NODEMAILER_EMAIL}>`,
      to: email,
      subject,
      text,
      html,
    };

    await transporter.sendMail(mailOptions);
    console.log("Correo electrónico enviado correctamente");
  } catch (error) {
    console.error("Error al enviar correo electrónico: ", error);
    return error;
  }
};

module.exports = sendEmail;