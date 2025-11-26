import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import authRoutes from "./routes/authRoutes.js";
import pool from "./config/db.js";

dotenv.config();

const app = express();

/* ==========================================
   🔍 DEBUG: VARIABLES GOOGLE
========================================== */
console.log("🔍 GOOGLE CLIENT ID:", process.env.GOOGLE_CLIENT_ID || "❌ NO DEFINIDO");

/* ==========================================
   🔍 VERIFICAR VARIABLES CRÍTICAS
========================================== */
const requiredEnvVars = [
  "DB_HOST",
  "DB_USER",
  "DB_PASSWORD",
  "DB_NAME",
  "JWT_SECRET",
  "GOOGLE_CLIENT_ID"
];

const missingVars = requiredEnvVars.filter(v => !process.env[v]);
if (missingVars.length > 0) {
  console.error("❌ FALTAN VARIABLES DE ENTORNO:");
  console.table(missingVars);
  process.exit(1);
}

console.log("✅ Variables esenciales OK");

/* ==========================================
   🔌 BASE DE DATOS
========================================== */
try {
  const connection = await pool.getConnection();
  console.log("✅ Conexión a BD exitosa");
  connection.release();
} catch (err) {
  console.error("❌ Error al conectar con BD:", err.message);
  process.exit(1);
}

/* ==========================================
   🛡️ CORS — Muy importante para GOOGLE LOGIN
========================================== */
const allowedOrigins = [
  "http://localhost:5173",
  "https://frontjmartinez-production.up.railway.app"
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);

      console.warn("❌ CORS bloqueó:", origin);
      return callback(new Error("No permitido por CORS"));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

app.use(express.json());

/* ==========================================
   🛣️ RUTAS
========================================== */
app.use("/api", authRoutes);

app.get("/", (req, res) => {
  res.json({
    message: "API de Juguetería Martínez",
    googleClientId: process.env.GOOGLE_CLIENT_ID,
    status: "OK"
  });
});

/* ==========================================
   🚀 SERVIDOR
========================================== */
const PORT = process.env.PORT || 4000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Servidor en puerto ${PORT}`);
});

export default app;
