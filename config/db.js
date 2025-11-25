import mysql from "mysql2/promise";
import dotenv from "dotenv";

dotenv.config();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0,
  connectTimeout: 20000 // 20 segundos para conexiones lentas
});

async function testDB() {
  try {
    console.log("🔌 Intentando conectar a la base de datos...");
    console.log(`   Host: ${process.env.DB_HOST}`);
    console.log(`   User: ${process.env.DB_USER}`);
    console.log(`   Database: ${process.env.DB_NAME}`);
    
    const connection = await pool.getConnection();
    console.log("✅ Conexión exitosa a la base de datos MySQL");
    
    // Verificar que podemos hacer queries
    const [rows] = await connection.query('SELECT 1 as test');
    console.log("✅ Query de prueba exitosa");
    
    connection.release();
  } catch (error) {
    console.error("❌ Error al conectar a la base de datos:");
    console.error("   Mensaje:", error.message);
    console.error("   Código:", error.code);
    console.error("   Host:", process.env.DB_HOST);
    
    if (error.code === 'ECONNREFUSED') {
      console.error("   → El servidor MySQL rechazó la conexión");
    } else if (error.code === 'ER_ACCESS_DENIED_ERROR') {
      console.error("   → Credenciales incorrectas (usuario/contraseña)");
    } else if (error.code === 'ETIMEDOUT') {
      console.error("   → Timeout: El servidor no responde");
    }
  }
}

// Ejecutar test al iniciar
testDB();

export default pool;