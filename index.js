require("dotenv").config();
const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const serverless = require("serverless-http");

const app = express();

// ✅ Middlewares
app.use(cors({ origin: "*" }));
app.use(express.json());

// ✅ Servir arquivos estáticos
app.use("/assets", express.static(path.join(__dirname, "assets")));

// ✅ Rotas HTML
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "alunos.html"));
});
app.get("/docentes.html", (req, res) => {
  res.sendFile(path.join(__dirname, "docentes.html"));
});
app.get("/favicon.ico", (req, res) => {
  res.sendFile(path.join(__dirname, "assets", "img", "favicon.ico"));
});

// ✅ Conexão MySQL (Railway)
const pool = mysql.createPool({
  host: process.env.MYSQLHOST || process.env.DB_HOST,
  user: process.env.MYSQLUSER || process.env.DB_USER,
  password: process.env.MYSQLPASSWORD || process.env.DB_PASSWORD,
  database: process.env.MYSQLDATABASE || process.env.DB_NAME,
  port: process.env.MYSQLPORT || 3306,
  ssl: { rejectUnauthorized: true }, // Railway geralmente exige SSL
  waitForConnections: true,
  connectionLimit: 10,
});

const JWT_SECRET = process.env.JWT_SECRET || "pokecreche_secret";

// ✅ Funções auxiliares
function onlyDigits(str = "") {
  return (str || "").toString().replace(/\D+/g, "");
}

// ✅ Middleware JWT
function authenticateJWT(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ success: false, message: "Token ausente" });
  }
  const token = auth.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(401).json({ success: false, message: "Token inválido" });
    req.user = payload;
    next();
  });
}

// ✅ Rotas de API
app.post("/register/aluno", async (req, res) => {
  const { nome, cpf, matricula } = req.body || {};
  if (!nome || !cpf || !matricula)
    return res.status(400).json({ message: "Campos obrigatórios faltando" });

  const cpfClean = onlyDigits(cpf);
  const matriculaStr = String(matricula).trim();

  const conn = await pool.getConnection();
  try {
    const [existing] = await conn.query(
      "SELECT id FROM alunos WHERE matricula = ? OR cpf = ? LIMIT 1",
      [matriculaStr, cpfClean]
    );
    if (existing.length > 0) {
      return res.status(409).json({ message: "Aluno já cadastrado" });
    }
    const [result] = await conn.query(
      "INSERT INTO alunos (nome, cpf, matricula) VALUES (?, ?, ?)",
      [nome, cpfClean, matriculaStr]
    );
    return res.status(201).json({ message: "Aluno cadastrado", id: result.insertId });
  } finally {
    conn.release();
  }
});

app.post("/register/docente", async (req, res) => {
  const { nome, identificador, senha } = req.body || {};
  if (!nome || !identificador || !senha)
    return res.status(400).json({ message: "Campos obrigatórios faltando" });

  const hashed = await bcrypt.hash(senha, 10);
  const conn = await pool.getConnection();
  try {
    const [result] = await conn.query(
      "INSERT INTO docentes (nome, identificador, senha) VALUES (?, ?, ?)",
      [nome, identificador, hashed]
    );
    return res.status(201).json({ message: "Docente cadastrado", id: result.insertId });
  } finally {
    conn.release();
  }
});

// ✅ Login aluno
app.post("/login/aluno", async (req, res) => {
  const { matricula, cpf } = req.body || {};
  if (!matricula || !cpf)
    return res.status(400).json({ success: false, message: "Matrícula e CPF são obrigatórios" });

  const matriculaStr = String(matricula).trim();
  const cpfClean = onlyDigits(cpf);

  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.query(
      "SELECT * FROM alunos WHERE matricula = ? AND cpf = ?",
      [matriculaStr, cpfClean]
    );
    if (rows.length > 0) {
      const aluno = rows[0];
      const token = jwt.sign(
        { id: aluno.id, type: "aluno", matricula: aluno.matricula },
        JWT_SECRET,
        { expiresIn: "8h" }
      );
      return res.json({ success: true, message: "Login realizado", token, user: aluno });
    }
    return res.status(401).json({ success: false, message: "Matrícula ou CPF inválidos" });
  } finally {
    conn.release();
  }
});

// ✅ Login docente
app.post("/login/docente", async (req, res) => {
  const { identificador, senha } = req.body || {};
  if (!identificador || !senha)
    return res.status(400).json({ success: false, message: "Identificador e senha são obrigatórios" });

  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.query("SELECT * FROM docentes WHERE identificador = ?", [identificador]);
    if (rows.length === 0)
      return res.status(401).json({ success: false, message: "Identificador ou senha inválidos" });

    const docente = rows[0];
    const senhaValida = await bcrypt.compare(senha, docente.senha);
    if (!senhaValida)
      return res.status(401).json({ success: false, message: "Identificador ou senha inválidos" });

    const token = jwt.sign(
      { id: docente.id, identificador: docente.identificador, type: "docente" },
      JWT_SECRET,
      { expiresIn: "8h" }
    );
    return res.json({ success: true, message: "Login realizado", token, user: docente });
  } finally {
    conn.release();
  }
});

// ✅ Eventos
app.get("/api/events", async (req, res) => {
  const year = parseInt(req.query.year, 10);
  const month = parseInt(req.query.month, 10);
  const teacherId = req.query.teacher_id || null;

  if (!year || !month || month < 1 || month > 12)
    return res.status(400).json({ success: false, message: "Parâmetros year e month são obrigatórios" });

  const first = `${year}-${String(month).padStart(2, "0")}-01`;
  const lastDate = new Date(year, month, 0).getDate();
  const last = `${year}-${String(month).padStart(2, "0")}-${String(lastDate).padStart(2, "0")}`;

  let sql = `SELECT id, teacher_id, DATE_FORMAT(date, '%Y-%m-%d') AS date, title, color FROM calendario_events WHERE date BETWEEN ? AND ?`;
  const params = [first, last];
  if (teacherId) {
    sql += " AND teacher_id = ?";
    params.push(teacherId);
  }

  const conn = await pool.getConnection();
  try {
    const [results] = await conn.query(sql, params);
    return res.json({ success: true, events: results });
  } finally {
    conn.release();
  }
});

app.post("/api/events", authenticateJWT, async (req, res) => {
  const teacherId = req.user && req.user.id ? req.user.id : null;
  const { date, title, color } = req.body || {};
  if (!date || !title || !color)
    return res.status(400).json({ success: false, message: "date, title e color são obrigatórios" });

  const conn = await pool.getConnection();
  try {
    const [result] = await conn.query(
      "INSERT INTO calendario_events (teacher_id, date, title, color) VALUES (?, ?, ?, ?)",
      [teacherId, date, title, color]
    );
    return res.status(201).json({ success: true, message: "Evento criado", id: result.insertId });
  } finally {
    conn.release();
  }
});

// ✅ Exportar para Vercel
module.exports = app;
module.exports.handler = serverless(app);