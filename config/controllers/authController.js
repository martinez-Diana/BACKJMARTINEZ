import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import pool from "../db.js";
// Si quieres usar Twilio real, descomenta la siguiente línea:
// import twilio from "twilio";

dotenv.config();

// ⚙️ Configura Twilio (si lo usarás realmente)
// const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);

// 📦 Almacenamiento temporal de códigos SMS
const codes = new Map();

// 🔐 Generar token JWT
const generateToken = (user) => {
  return jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
};

// ✅ REGISTRO
export const registerUser = async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    if (!name || !email || !phone || !password)
      return res.status(400).json({ message: "Todos los campos son obligatorios" });

    const strongPassword = /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+={}\[\]:;"'<>,.?/~`-]).{8,}$/;
    if (!strongPassword.test(password)) {
      return res.status(400).json({
        message:
          "La contraseña debe tener al menos 8 caracteres, una mayúscula, un número y un símbolo",
      });
    }

    const [existing] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);
    if (existing.length > 0)
      return res.status(400).json({ message: "El correo ya está registrado" });

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)",
      [name, email, phone, hashedPassword]
    );

    res.json({ message: "Usuario registrado correctamente" });
  } catch (error) {
    console.error("Error en registro:", error);
    res.status(500).json({ message: "Error en el servidor" });
  }
};

// ✅ LOGIN (1° paso)
export const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ msg: "Correo y contraseña requeridos" });

    const [rows] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);
    if (rows.length === 0)
      return res.status(404).json({ msg: "Usuario no encontrado" });

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ msg: "Contraseña incorrecta" });

    // Generar código aleatorio de 6 dígitos
    const code = Math.floor(100000 + Math.random() * 900000);
    codes.set(email, code);

    // ⚙️ OPCIÓN 1: Enviar código con Twilio real
    /*
    await client.messages.create({
      body: `Tu código de verificación es: ${code}`,
      from: process.env.TWILIO_PHONE,
      to: user.phone,
    });
    */

    // ⚙️ OPCIÓN 2: Simular envío de SMS (para pruebas sin Twilio)
    console.log(`📱 Código SMS simulado para ${email}: ${code}`);

    res.json({ msg: "Código SMS enviado correctamente (simulado para pruebas)" });
  } catch (error) {
    console.error("Error en login:", error);
    res.status(500).json({ msg: "Error en el servidor" });
  }
};

// ✅ VERIFICAR CÓDIGO (2° paso)
export const verifyCode = async (req, res) => {
  try {
    const { email, code } = req.body;

    const savedCode = codes.get(email);
    if (!savedCode || savedCode != code)
      return res.status(400).json({ msg: "Código incorrecto o expirado" });

    const [rows] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);
    if (rows.length === 0)
      return res.status(404).json({ msg: "Usuario no encontrado" });

    const user = rows[0];
    const token = generateToken(user);

    // Eliminar el código ya usado
    codes.delete(email);

    res.json({ msg: "Código verificado correctamente", token });
  } catch (error) {
    console.error("Error en verificación:", error);
    res.status(500).json({ msg: "Error en el servidor" });
  }
};
