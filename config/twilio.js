// backend/src/config/twilio.js
import twilio from "twilio";
import dotenv from "dotenv";

dotenv.config();

// Se inicializa el cliente de Twilio con las credenciales del .env
const client = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

/**
 * Envía un SMS con Twilio
 * @param {string} to - Número de teléfono del destinatario (formato internacional, ej. +521XXXXXXXXXX)
 * @param {string} message - Texto del mensaje a enviar
 */
export const sendSMS = async (to, message) => {
  try {
    const response = await client.messages.create({
      body: message,
      from: process.env.TWILIO_PHONE_NUMBER, // Tu número de Twilio
      to, // Número del usuario
    });

    console.log("✅ SMS enviado correctamente:", response.sid);
    return response;
  } catch (error) {
    console.error("❌ Error al enviar SMS:", error);
    throw error;
  }
};
