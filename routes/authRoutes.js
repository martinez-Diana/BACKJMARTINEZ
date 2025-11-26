import express from "express";
import pool from "../config/db.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";
import { generateVerificationCode, sendVerificationEmail, sendPasswordResetEmail } from "../services/emailService.js";

const router = express.Router();

// ✅ Configurar Google OAuth Client
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ========================================
// 🔵 LOGIN CON GOOGLE
// ========================================
router.post("/auth/google", async (req, res) => {
  try {
    const { credential } = req.body;

    console.log("🔵 Intento de login con Google");

    if (!credential) {
      return res.status(400).json({ error: "Token de Google no proporcionado" });
    }

    // ✅ Verificar el token de Google usando 'client'
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const googleId = payload.sub;
    const email = payload.email;
    const firstName = payload.given_name;
    const lastName = payload.family_name;
    const profilePicture = payload.picture;

    console.log("✅ Token verificado:", { email, googleId });

    // Verificar si el usuario ya existe
    const [existingUsers] = await pool.query(
      "SELECT * FROM users WHERE google_id = ? OR email = ?",
      [googleId, email]
    );

    let user;

    if (existingUsers.length > 0) {
      // Usuario existente
      user = existingUsers[0];
      console.log("👤 Usuario existente:", user.email);
      
      if (!user.google_id) {
        await pool.query(
          "UPDATE users SET google_id = ?, profile_picture = ? WHERE id = ?",
          [googleId, profilePicture, user.id]
        );
        console.log("✅ Google ID actualizado");
      }
    } else {
      // Crear nuevo usuario
      console.log("🆕 Creando nuevo usuario...");
      
      const username = email.split("@")[0];
      const randomPassword = await bcrypt.hash(Math.random().toString(36), 10);

      const sql = `
        INSERT INTO users 
        (first_name, last_name, email, username, password, google_id, profile_picture, role_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `;

      const [result] = await pool.query(sql, [
        firstName,
        lastName || "",
        email,
        username,
        randomPassword,
        googleId,
        profilePicture,
        3 // role_id = 3 (Cliente)
      ]);

      const [newUser] = await pool.query("SELECT * FROM users WHERE id = ?", [result.insertId]);
      user = newUser[0];
      console.log("✅ Usuario creado:", user.email);
    }

    // Generar JWT token
    const token = jwt.sign(
      { 
        id: user.id, 
        username: user.username, 
        email: user.email,
        role_id: user.role_id 
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    console.log("✅ Login con Google exitoso");

    res.json({
      success: true,
      message: "Inicio de sesión con Google exitoso",
      token,
      user: {
        id: user.id,
        first_name: user.first_name,
        last_name: user.last_name,
        email: user.email,
        username: user.username,
        role_id: user.role_id,
        profile_picture: user.profile_picture || profilePicture
      }
    });

  } catch (error) {
    console.error("❌ Error en /auth/google:", error.message);
    res.status(500).json({ 
      error: "Error al autenticar con Google",
      details: error.message 
    });
  }
});

// ========================================
// 🔐 REGISTRO TRADICIONAL
// ========================================
router.post("/register", async (req, res) => {
  try {
    const {
      first_name,
      last_name,
      mother_lastname,
      email,
      phone,
      birthdate,
      username,
      password,
      role_id
    } = req.body;

    if (!first_name || !last_name || !email || !password || !username) {
      return res.status(400).json({ error: "Faltan campos obligatorios" });
    }

    const [existingEmail] = await pool.query(
      "SELECT id FROM users WHERE email = ?",
      [email]
    );

    if (existingEmail.length > 0) {
      return res.status(400).json({ error: "El correo electrónico ya está registrado" });
    }

    const [existingUsername] = await pool.query(
      "SELECT id FROM users WHERE username = ?",
      [username]
    );

    if (existingUsername.length > 0) {
      return res.status(400).json({ error: "El nombre de usuario ya está en uso" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = `
      INSERT INTO users 
      (first_name, last_name, mother_lastname, email, phone, birthdate, username, password, role_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    await pool.query(sql, [
      first_name,
      last_name,
      mother_lastname,
      email,
      phone,
      birthdate,
      username,
      hashedPassword,
      role_id
    ]);

    res.json({ success: true, message: "Usuario registrado correctamente" });

  } catch (error) {
    console.error("Error en /register:", error.message);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

// ========================================
// 🔑 LOGIN TRADICIONAL
// ========================================
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    console.log('📝 Intento de login:', { username });

    if (!username || !password) {
      return res.status(400).json({ 
        error: 'Usuario y contraseña son requeridos' 
      });
    }

    const query = `
      SELECT 
        id, 
        username, 
        email, 
        \`password\`,
        first_name,
        last_name,
        role_id,
        status
      FROM users 
      WHERE username = ? OR email = ? 
      LIMIT 1
    `;
    const [users] = await pool.query(query, [username, username]);

    if (users.length === 0) {
      console.log('❌ Usuario no encontrado:', username);
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }

    const user = users[0];
    
    console.log('🔍 Usuario encontrado:', {
      id: user.id,
      username: user.username,
      hasPassword: !!user.password
    });

    if (!user.password) {
      console.log('❌ Usuario sin contraseña en BD:', username);
      return res.status(500).json({ 
        error: 'Error de configuración. Contacta al administrador.' 
      });
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      console.log('❌ Contraseña incorrecta para:', username);
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    }

    const token = jwt.sign(
      { id: user.id, role_id: user.role_id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    console.log('✅ Login exitoso:', user.username);

    res.json({
      message: 'Login exitoso',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        role_id: user.role_id
      }
    });

  } catch (error) {
    console.error('❌ Error en /api/login:', error);
    res.status(500).json({ 
      error: 'Error en el servidor',
      details: error.message 
    });
  }
});

// ========================================
// 📧 SOLICITAR CÓDIGO POR EMAIL
// ========================================
router.post("/auth/email/request-code", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: "El correo electrónico es requerido" });
    }

    const [users] = await pool.query(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: "No existe una cuenta con este correo electrónico" });
    }

    const code = generateVerificationCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await pool.query(
      "DELETE FROM verification_codes WHERE email = ?",
      [email]
    );

    await pool.query(
      "INSERT INTO verification_codes (email, code, expires_at) VALUES (?, ?, ?)",
      [email, code, expiresAt]
    );

    const emailSent = await sendVerificationEmail(email, code);

    if (!emailSent) {
      return res.status(500).json({ error: "Error al enviar el correo electrónico" });
    }

    res.json({
      success: true,
      message: "Código de verificación enviado a tu correo electrónico"
    });

  } catch (error) {
    console.error("Error en /auth/email/request-code:", error.message);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

// ========================================
// ✅ VERIFICAR CÓDIGO
// ========================================
router.post("/auth/email/verify-code", async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ error: "Email y código son requeridos" });
    }

    const [codes] = await pool.query(
      "SELECT * FROM verification_codes WHERE email = ? AND code = ? AND used = FALSE",
      [email, code]
    );

    if (codes.length === 0) {
      return res.status(401).json({ error: "Código inválido o ya utilizado" });
    }

    const verificationCode = codes[0];

    if (new Date() > new Date(verificationCode.expires_at)) {
      return res.status(401).json({ error: "El código ha expirado. Solicita uno nuevo" });
    }

    await pool.query(
      "UPDATE verification_codes SET used = TRUE WHERE id = ?",
      [verificationCode.id]
    );

    const [users] = await pool.query(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    const user = users[0];

    const token = jwt.sign(
      { 
        id: user.id, 
        username: user.username, 
        email: user.email,
        role_id: user.role_id 
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      success: true,
      message: "Inicio de sesión exitoso",
      token,
      user: {
        id: user.id,
        first_name: user.first_name,
        last_name: user.last_name,
        email: user.email,
        username: user.username,
        role_id: user.role_id,
        profile_picture: user.profile_picture
      }
    });

  } catch (error) {
    console.error("Error en /auth/email/verify-code:", error.message);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

// ========================================
// 🔍 VERIFICAR TOKEN
// ========================================
router.get("/verify", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
      return res.status(401).json({ error: "Token no proporcionado" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const [users] = await pool.query("SELECT * FROM users WHERE id = ?", [decoded.id]);

    if (users.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const user = users[0];

    res.json({
      success: true,
      user: {
        id: user.id,
        first_name: user.first_name,
        last_name: user.last_name,
        email: user.email,
        username: user.username,
        role_id: user.role_id,
        profile_picture: user.profile_picture
      }
    });

  } catch (error) {
    console.error("Error en /verify:", error.message);
    res.status(401).json({ error: "Token inválido o expirado" });
  }
});

// ========================================
// 🔐 RECUPERACIÓN DE CONTRASEÑA
// ========================================
router.post("/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: "El correo electrónico es requerido" });
    }

    const [users] = await pool.query(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: "No existe una cuenta con este correo electrónico" });
    }

    const crypto = await import("crypto");
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);

    await pool.query(
      "DELETE FROM password_reset_tokens WHERE email = ?",
      [email]
    );

    await pool.query(
      "INSERT INTO password_reset_tokens (email, token, expires_at) VALUES (?, ?, ?)",
      [email, token, expiresAt]
    );

    const emailSent = await sendPasswordResetEmail(email, token);

    if (!emailSent) {
      return res.status(500).json({ error: "Error al enviar el correo electrónico" });
    }

    res.json({
      success: true,
      message: "Se ha enviado un enlace de recuperación a tu correo electrónico"
    });

  } catch (error) {
    console.error("Error en /auth/forgot-password:", error.message);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

// ========================================
// ✅ RESTABLECER CONTRASEÑA
// ========================================
router.post("/auth/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ error: "Token y nueva contraseña son requeridos" });
    }

    const [tokens] = await pool.query(
      "SELECT * FROM password_reset_tokens WHERE token = ? AND used = FALSE",
      [token]
    );

    if (tokens.length === 0) {
      return res.status(401).json({ error: "Token inválido o ya utilizado" });
    }

    const resetToken = tokens[0];

    if (new Date() > new Date(resetToken.expires_at)) {
      return res.status(401).json({ error: "El enlace ha expirado. Solicita uno nuevo" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await pool.query(
      "UPDATE users SET password = ? WHERE email = ?",
      [hashedPassword, resetToken.email]
    );

    await pool.query(
      "UPDATE password_reset_tokens SET used = TRUE WHERE id = ?",
      [resetToken.id]
    );

    res.json({
      success: true,
      message: "Contraseña actualizada correctamente"
    });

  } catch (error) {
    console.error("Error en /auth/reset-password:", error.message);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

export default router;