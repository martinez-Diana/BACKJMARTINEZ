import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import authRoutes from "./routes/authRoutes.js";
import googleAuthRoutes from "./routes/authGoogle.js";
import pool from "./config/db.js";

dotenv.config();

const app = express();

// ==========================================
// 🔍 VERIFICAR VARIABLES DE ENTORNO CRÍTICAS
// ==========================================
console.log("🔍 Verificando variables de entorno...");

const requiredEnvVars = [
  "DB_HOST",
  "DB_USER",
  "DB_PASSWORD",
  "DB_NAME",
  "JWT_SECRET",
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET"
];

const missingVars = requiredEnvVars.filter(v => !process.env[v]);

if (missingVars.length > 0) {
  console.error("❌ FALTAN VARIABLES DE ENTORNO CRÍTICAS:");
  missingVars.forEach(v => console.error("   - " + v));
  process.exit(1);
}

console.log("✅ Variables de entorno verificadas");

// Opcionales de email
if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
  console.warn("⚠️ EMAIL_USER o EMAIL_PASS no configuradas (funciones de email deshabilitadas)");
}

// ==========================================
// 🗄️ VERIFICAR CONEXIÓN A BASE DE DATOS
// ==========================================
console.log("🔌 Intentando conectar a la base de datos...");

try {
  const connection = await pool.getConnection();
  console.log("✅ Conexión exitosa a MySQL");
  console.log("📊 Base de datos:", process.env.DB_NAME);
  console.log("🔍 Variables de DB:", {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    database: process.env.DB_NAME,
    hasPassword: !!process.env.DB_PASSWORD
  });
  connection.release();
} catch (error) {
  console.error("❌ Error al conectar a MySQL:", error.message);
  console.error("   Host:", process.env.DB_HOST);
  console.error("   User:", process.env.DB_USER);
  console.error("   DB:", process.env.DB_NAME);
  process.exit(1);
}

// ==========================================
// 🛡️ MIDDLEWARES
// ==========================================

const allowedOrigins = [
  "http://localhost:5173",
  "https://frontjmartinez-production.up.railway.app"
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);

      console.warn("⚠️ Origen bloqueado por CORS:", origin);
      callback(new Error("No permitido por CORS"));
    },
    credentials: true,
  })
);

app.use(express.json());

// ==========================================
// 🛣️ RUTAS
// ==========================================
app.use("/api", authRoutes);
app.use("/", googleAuthRoutes); // 👈 Google Login

// Health Check
app.get("/", (req, res) => {
  res.json({
    status: "OK",
    message: "🎁 API de Juguetería Martínez",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
  });
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      status: "healthy",
      database: "connected",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    res.status(503).json({
      status: "unhealthy",
      database: "disconnected",
      error: error.message,
    });
  }
});

// ==========================================
// 🚀 INICIAR SERVIDOR
// ==========================================
const PORT = process.env.PORT || 4000;

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`\n✨ ========================================`);
  console.log(`   🚀 Servidor iniciado exitosamente`);
  console.log(`   📍 Puerto: ${PORT}`);
  console.log(`   🌐 Entorno: ${process.env.NODE_ENV}`);
  console.log(`   🔗 Frontend: ${process.env.FRONTEND_URL || "http://localhost:5173"}`);
  console.log(`   ⏰ ${new Date().toLocaleString("es-MX")}`);
  console.log(`========================================\n`);
});

// ==========================================
// ⚠️ MANEJO DE ERRORES
// ==========================================
process.on("uncaughtException", (error) => {
  console.error("\n❌ Excepción no capturada:", error);
  process.exit(1);
});

process.on("unhandledRejection", (reason) => {
  console.error("\n❌ Promise rechazada no manejada:", reason);
  process.exit(1);
});

process.on("SIGTERM", () => {
  console.log("\n⚠️ SIGTERM recibido. Cerrando servidor...");
  server.close(() => {
    console.log("✅ Servidor cerrado");
    pool.end();
    process.exit(0);
  });
});

export default app;
