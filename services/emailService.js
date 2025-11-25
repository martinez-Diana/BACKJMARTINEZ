import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

// Configurar el transporter de Nodemailer con mejor manejo de errores
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  tls: {
    rejectUnauthorized: false // Permite certificados autofirmados
  }
});

// Verificar la configuración al iniciar
transporter.verify((error, success) => {
  if (error) {
    console.error("❌ Error en la configuración de email:", error);
  } else {
    console.log("✅ Servidor de email listo para enviar mensajes");
  }
});

// Función para generar código de 6 dígitos
export const generateVerificationCode = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Función para enviar código de verificación
export const sendVerificationEmail = async (email, code) => {
  // Validar que las credenciales estén configuradas
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.error("❌ ERROR: Variables EMAIL_USER o EMAIL_PASS no configuradas");
    return false;
  }

  const mailOptions = {
    from: `"Juguetería Martínez" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "🔐 Código de verificación - Juguetería Martínez",
    html: `
      <div style="font-family: 'Poppins', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #fef5fb; border-radius: 10px;">
        <div style="background: linear-gradient(135deg, #ec4899 0%, #db2777 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0; font-size: 24px;">🎁 JUGUETERÍA MARTÍNEZ</h1>
          <p style="color: #fcd34d; margin: 10px 0 0 0; font-size: 14px;">Sistema de Gestión Integral</p>
        </div>
        
        <div style="background: white; padding: 40px; border-radius: 0 0 10px 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
          <h2 style="color: #333; margin-top: 0;">¡Hola! 👋</h2>
          <p style="color: #666; font-size: 15px; line-height: 1.6;">
            Has solicitado iniciar sesión en tu cuenta de <strong>Juguetería Martínez</strong>.
          </p>
          
          <div style="background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 30px 0; text-align: center;">
            <p style="color: #666; margin: 0 0 10px 0; font-size: 14px;">Tu código de verificación es:</p>
            <div style="font-size: 36px; font-weight: bold; color: #ec4899; letter-spacing: 8px; margin: 10px 0;">
              ${code}
            </div>
            <p style="color: #999; margin: 10px 0 0 0; font-size: 12px;">
              ⏰ Este código expirará en <strong>10 minutos</strong>
            </p>
          </div>
          
          <div style="background: #fef2f2; border-left: 4px solid #ef4444; padding: 15px; border-radius: 4px; margin-top: 20px;">
            <p style="color: #991b1b; margin: 0; font-size: 13px;">
              ⚠️ <strong>Importante:</strong> Si no solicitaste este código, ignora este correo y tu cuenta permanecerá segura.
            </p>
          </div>
          
          <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; text-align: center;">
            <p style="color: #999; font-size: 12px; margin: 0;">
              © 2025 Juguetería y Novedades Martínez<br>
              Sistema de Gestión Integral
            </p>
          </div>
        </div>
      </div>
    `,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log(`✅ Código de verificación enviado a: ${email}`);
    console.log(`📧 Message ID: ${info.messageId}`);
    return true;
  } catch (error) {
    console.error("❌ Error detallado al enviar correo:");
    console.error("Código de error:", error.code);
    console.error("Mensaje:", error.message);
    console.error("Stack:", error.stack);
    return false;
  }
};

// Función para enviar enlace de recuperación de contraseña
export const sendPasswordResetEmail = async (email, token) => {
  // Validar que las credenciales estén configuradas
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.error("❌ ERROR: Variables EMAIL_USER o EMAIL_PASS no configuradas");
    return false;
  }

  const resetLink = `${process.env.FRONTEND_URL || 'http://localhost:5173'}/reset-password?token=${token}`;
  
  const mailOptions = {
    from: `"Juguetería Martínez" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "🔐 Recuperación de contraseña - Juguetería Martínez",
    html: `
      <div style="font-family: 'Poppins', Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #fef5fb; border-radius: 10px;">
        <div style="background: linear-gradient(135deg, #ec4899 0%, #db2777 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0; font-size: 24px;">🎁 JUGUETERÍA MARTÍNEZ</h1>
          <p style="color: #fcd34d; margin: 10px 0 0 0; font-size: 14px;">Sistema de Gestión Integral</p>
        </div>
        
        <div style="background: white; padding: 40px; border-radius: 0 0 10px 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
          <h2 style="color: #333; margin-top: 0;">Recuperación de Contraseña 🔒</h2>
          <p style="color: #666; font-size: 15px; line-height: 1.6;">
            Has solicitado restablecer tu contraseña de <strong>Juguetería Martínez</strong>.
          </p>
          
          <p style="color: #666; font-size: 15px; line-height: 1.6;">
            Haz clic en el siguiente botón para crear una nueva contraseña:
          </p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetLink}" style="display: inline-block; background: #ec4899; color: white; padding: 14px 30px; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 15px; box-shadow: 0 3px 12px rgba(236, 72, 153, 0.25);">
              Restablecer Contraseña
            </a>
          </div>
          
          <p style="color: #999; font-size: 13px; text-align: center; margin: 20px 0;">
            O copia y pega este enlace en tu navegador:
          </p>
          <p style="color: #c084fc; font-size: 12px; word-break: break-all; text-align: center; background: #f9fafb; padding: 10px; border-radius: 4px;">
            ${resetLink}
          </p>
          
          <div style="background: #fef2f2; border-left: 4px solid #ef4444; padding: 15px; border-radius: 4px; margin-top: 20px;">
            <p style="color: #991b1b; margin: 0; font-size: 13px;">
              ⚠️ <strong>Importante:</strong> Este enlace expirará en <strong>1 hora</strong>. Si no solicitaste restablecer tu contraseña, ignora este correo y tu cuenta permanecerá segura.
            </p>
          </div>
          
          <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; text-align: center;">
            <p style="color: #999; font-size: 12px; margin: 0;">
              © 2025 Juguetería y Novedades Martínez<br>
              Sistema de Gestión Integral
            </p>
          </div>
        </div>
      </div>
    `,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log(`✅ Enlace de recuperación enviado a: ${email}`);
    console.log(`📧 Message ID: ${info.messageId}`);
    return true;
  } catch (error) {
    console.error("❌ Error detallado al enviar correo de recuperación:");
    console.error("Código de error:", error.code);
    console.error("Mensaje:", error.message);
    console.error("Stack:", error.stack);
    return false;
  }
};