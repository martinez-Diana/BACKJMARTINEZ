import express from "express";
import pool from "../config/db.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";
import { 
  generateVerificationCode, 
  sendVerificationEmail, 
  sendPasswordResetEmail 
} from "../services/emailService.js";

const router = express.Router();

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

/* =========================================================
   🔵 LOGIN CON GOOGLE (ÚNICO Y LIMPIO)
========================================================= */
router.post("/auth/google", async (req, res) => {
  try {
    const { credential } = req.body;

    if (!credential) {
      return res.status(400).json({ error: "Token de Google no proporcionado" });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const googleId = payload.sub;
    const email = payload.email;
    const firstName = payload.given_name;
    const lastName = payload.family_name || "";
    const profilePicture = payload.picture;
    const username = email.split("@")[0];

    // Buscar usuario
    const [existing] = await pool.query(
      "SELECT * FROM users WHERE google_id = ? OR email = ?",
      [googleId, email]
    );

    let user;

    if (existing.length > 0) {
      user = existing[0];

      // Si existe pero no tiene google_id, lo actualizamos
      if (!user.google_id) {
        await pool.query(
          "UPDATE users SET google_id = ?, profile_picture = ? WHERE id = ?",
          [googleId, profilePicture, user.id]
        );
      }

    } else {
      // Crear nuevo usuario
      const randomPassword = await bcrypt.hash(Math.random().toString(36), 10);

      const [result] = await pool.query(
        `INSERT INTO users 
          (first_name, last_name, email, username, password, google_id, profile_picture, role_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, 3)
        `,
        [
          firstName,
          lastName,
          email,
          username,
          randomPassword,
          googleId,
          profilePicture
        ]
      );

      const [newUser] = await pool.query("SELECT * FROM users WHERE id = ?", [
        result.insertId
      ]);

      user = newUser[0];
    }

    // Generar token
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

    return res.json({
      success: true,
      message: "Login con Google exitoso",
      token,
      user: {
        id: user.id,
        first_name: user.first_name,
        last_name: user.last_name,
        username: user.username,
        email: user.email,
        role_id: user.role_id,
        profile_picture: user.profile_picture
      }
    });
  } catch (error) {
    console.error("Error en /auth/google:", error.message);
    return res.status(500).json({ error: "Error al autenticar con Google" });
  }
});

/* =========================================================
   🔐 REGISTRO
========================================================= */
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

    // Email existente
    const [emailExists] = await pool.query(
      "SELECT id FROM users WHERE email = ?",
      [email]
    );

    if (emailExists.length > 0)
      return res
        .status(400)
        .json({ error: "El correo ya está registrado" });

    // Username existente
    const [usernameExists] = await pool.query(
      "SELECT id FROM users WHERE username = ?",
      [username]
    );

    if (usernameExists.length > 0)
      return res
        .status(400)
        .json({ error: "El nombre de usuario ya está en uso" });

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      `
      INSERT INTO users 
      (first_name, last_name, mother_lastname, email, phone, birthdate, username, password, role_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
      [
        first_name,
        last_name,
        mother_lastname,
        email,
        phone,
        birthdate,
        username,
        hashedPassword,
        role_id
      ]
    );

    res.json({ success: true, message: "Usuario registrado correctamente" });
  } catch (error) {
    console.error("Error en /register:", error);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

/* =========================================================
   🔑 LOGIN TRADICIONAL
========================================================= */
router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password)
      return res
        .status(400)
        .json({ error: "Usuario y contraseña requeridos" });

    const query = `
      SELECT id, username, email, password, first_name, last_name, role_id
      FROM users
      WHERE username = ? OR email = ?
      LIMIT 1
    `;

    const [rows] = await pool.query(query, [username, username]);

    if (rows.length === 0)
      return res
        .status(401)
        .json({ error: "Usuario o contraseña incorrectos" });

    const user = rows[0];

    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return res
        .status(401)
        .json({ error: "Usuario o contraseña incorrectos" });

    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        email: user.email,
        role_id: user.role_id
      },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      message: "Login exitoso",
      token,
      user
    });
  } catch (error) {
    console.error("Error en /login:", error);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

/* =========================================================
   📧 VERIFICACIÓN POR EMAIL
========================================================= */
router.post("/auth/email/request-code", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email)
      return res.status(400).json({ error: "El email es requerido" });

    const [user] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email
    ]);

    if (user.length === 0)
      return res.status(404).json({ error: "Correo no encontrado" });

    const code = generateVerificationCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await pool.query("DELETE FROM verification_codes WHERE email = ?", [
      email
    ]);

    await pool.query(
      "INSERT INTO verification_codes (email, code, expires_at) VALUES (?, ?, ?)",
      [email, code, expiresAt]
    );

    await sendVerificationEmail(email, code);

    res.json({
      success: true,
      message: "Código enviado a tu correo"
    });
  } catch (error) {
    console.error("Error en /auth/email/request-code:", error);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

/* =========================================================
   🔍 VERIFICAR CÓDIGO
========================================================= */
router.post("/auth/email/verify-code", async (req, res) => {
  try {
    const { email, code } = req.body;

    const [codes] = await pool.query(
      "SELECT * FROM verification_codes WHERE email = ? AND code = ? AND used = FALSE",
      [email, code]
    );

    if (codes.length === 0)
      return res.status(401).json({ error: "Código inválido" });

    const verificationCode = codes[0];

    if (new Date() > new Date(verificationCode.expires_at))
      return res.status(401).json({ error: "Código expirado" });

    await pool.query(
      "UPDATE verification_codes SET used = TRUE WHERE id = ?",
      [verificationCode.id]
    );

    const [users] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email
    ]);

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
      token,
      user
    });
  } catch (error) {
    console.error("Error en /auth/email/verify-code:", error);
    res.status(500).json({ error: "Error en el servidor" });
  }
});

/* =========================================================
   🔐 RECUPERACIÓN DE CONTRASEÑA
========================================================= */
router.post("/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    const [users] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email
    ]);

    if (users.length === 0)
      return res.status(404).json({ error: "Correo no registrado" });

    const crypto = await import("crypto");
    const token = crypto.randomBytes(32).toString("hex");

    const expiresAt = new Date(Date.now() + 3600000);

    await pool.query(
      "DELETE FROM password_reset_tokens WHERE email = ?",
      [email]
    );

    await pool.query(
      "INSERT INTO password_reset_tokens (email, token, expires_at) VALUES (?, ?, ?)",
      [email, token, expiresAt]
    );

    await sendPasswordResetEmail(email, token);

    res.json({
      success: true,
      message: "Correo enviado para restablecer contraseña"
    });
  } catch (error) {
    console.error("Error en /auth/forgot-password:", error);
    res.status(500).json({ error: "Error en servidor" });
  }
});

/* =========================================================
   🔄 RESTABLECER CONTRASEÑA
========================================================= */
router.post("/auth/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    const [tokens] = await pool.query(
      "SELECT * FROM password_reset_tokens WHERE token = ? AND used = FALSE",
      [token]
    );

    if (tokens.length === 0)
      return res.status(400).json({ error: "Token inválido" });

    const resetToken = tokens[0];

    if (new Date() > new Date(resetToken.expires_at))
      return res.status(400).json({ error: "Token expirado" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await pool.query("UPDATE users SET password = ? WHERE email = ?", [
      hashedPassword,
      resetToken.email
    ]);

    await pool.query(
      "UPDATE password_reset_tokens SET used = TRUE WHERE id = ?",
      [resetToken.id]
    );

    res.json({
      success: true,
      message: "Contraseña actualizada"
    });
  } catch (error) {
    console.error("Error en /auth/reset-password:", error);
    res.status(500).json({ error: "Error en servidor" });
  }
});

export default router;
