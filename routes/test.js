import express from "express";
import pool from "../config/db.js";

const router = express.Router();

router.get("/testdb", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT 1 + 1 AS result");
    res.json({ ok: true, result: rows[0].result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
