// server.js
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(express.json());

app.use(cors({
  origin: '*'
}));

// JWT secret (troque para uma variável de ambiente em produção)
const JWT_SECRET = process.env.JWT_SECRET || 'troque_esta_chave_em_producao';

// Conexão MySQL
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'q1w2e3',
  database: 'PokeCreche'
});

db.connect((err) => {
  if (err) {
    console.error('Erro ao conectar ao MySQL:', err.message);
  } else {
    console.log('Conectado ao MySQL');
  }
});

// Criação de tabelas existentes + tabela de eventos
const createAlunos = `
CREATE TABLE IF NOT EXISTS alunos (
  id INT AUTO_INCREMENT PRIMARY KEY,
  nome VARCHAR(255) NOT NULL,
  cpf VARCHAR(20) NOT NULL UNIQUE,
  matricula VARCHAR(50) NOT NULL
);`;

const createDocentes = `
CREATE TABLE IF NOT EXISTS docentes (
  id INT AUTO_INCREMENT PRIMARY KEY,
  nome VARCHAR(255) NOT NULL,
  identificador VARCHAR(100) NOT NULL UNIQUE,
  senha VARCHAR(255) NOT NULL
);`;

// tabela de eventos do calendário
const createEvents = `
CREATE TABLE IF NOT EXISTS calendario_events (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  teacher_id BIGINT UNSIGNED NULL,
  date DATE NOT NULL,
  title VARCHAR(255) NOT NULL,
  color ENUM('green','red','none') NOT NULL DEFAULT 'none',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY ux_teacher_date (teacher_id, date)
);`;

db.query(createAlunos, (err) => {
  if (err) console.error('Erro ao criar/verificar tabela alunos:', err.message);
  else {
    console.log('Tabela alunos verificada/criada');
    db.query(createDocentes, (err2) => {
      if (err2) console.error('Erro ao criar/verificar tabela docentes:', err2.message);
      else {
        console.log('Tabela docentes verificada/criada');
        db.query(createEvents, (err3) => {
          if (err3) console.error('Erro ao criar/verificar tabela calendario_events:', err3.message);
          else console.log('Tabela calendario_events verificada/criada');
        });
      }
    });
  }
});

// Middleware para autenticar token JWT (docente)
function authenticateJWT(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Token ausente' });
  }
  const token = auth.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(401).json({ success: false, message: 'Token inválido' });
    // payload deve conter id e identificador
    req.user = payload;
    next();
  });
}

// Rotas básicas existentes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'alunos.html'));
});

app.post('/register/aluno', (req, res) => {
  const { nome, cpf, matricula } = req.body || {};
  if (!nome || !cpf || !matricula) {
    return res.status(400).json({ message: 'Campos nome, cpf e matricula são obrigatórios' });
  }

  const sql = 'INSERT INTO alunos (nome, cpf, matricula) VALUES (?, ?, ?)';
  db.query(sql, [nome, cpf, matricula], (err, result) => {
    if (err) {
      console.error('Erro ao inserir aluno:', err);
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ message: 'Aluno já cadastrado', error: err.message });
      }
      return res.status(500).json({ message: 'Erro ao cadastrar aluno', error: err.message });
    }
    return res.status(201).json({ message: 'Aluno cadastrado', id: result.insertId });
  });
});

app.post('/register/docente', async (req, res) => {
  const { nome, identificador, senha } = req.body || {};
  if (!nome || !identificador || !senha) {
    return res.status(400).json({ message: 'Campos nome, identificador e senha são obrigatórios' });
  }

  try {
    const hashed = await bcrypt.hash(senha, 10);
    const sql = 'INSERT INTO docentes (nome, identificador, senha) VALUES (?, ?, ?)';
    db.query(sql, [nome, identificador, hashed], (err, result) => {
      if (err) {
        console.error('Erro ao inserir docente:', err);
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(409).json({ message: 'Identificador já existe', error: err.message });
        }
        return res.status(500).json({ message: 'Erro ao cadastrar docente', error: err.message });
      }
      return res.status(201).json({ message: 'Docente cadastrado', id: result.insertId });
    });
  } catch (e) {
    console.error('Erro ao hashear senha:', e);
    return res.status(500).json({ message: 'Erro interno', error: e.message });
  }
});

// Login aluno (mantive igual)
app.post('/login/aluno', (req, res) => {
  const { matricula, cpf } = req.body || {};

  if (!matricula || !cpf) {
    return res.status(400).json({
      success: false,
      message: 'Matrícula e CPF são obrigatórios'
    });
  }

  const sql = 'SELECT * FROM alunos WHERE matricula = ? AND cpf = ?';
  db.query(sql, [matricula, cpf], (err, result) => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: 'Erro no servidor'
      });
    }

    if (result.length > 0) {
      const aluno = result[0];
      const token = 'token_' + aluno.id; // token simples de aluno (se quiser JWT, podemos alterar)

      res.json({
        success: true,
        message: 'Login realizado com sucesso',
        token,
        user: {
          id: aluno.id,
          nome: aluno.nome,
          matricula: aluno.matricula,
          cpf: aluno.cpf
        }
      });
    } else {
      res.status(401).json({
        success: false,
        message: 'Matrícula ou CPF inválidos'
      });
    }
  });
});

// Login docente - agora retorna JWT
app.post('/login/docente', async (req, res) => {
  const { identificador, senha } = req.body || {};

  if (!identificador || !senha) {
    return res.status(400).json({
      success: false,
      message: 'Identificador e senha são obrigatórios'
    });
  }

  const sql = 'SELECT * FROM docentes WHERE identificador = ?';
  db.query(sql, [identificador], async (err, result) => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: 'Erro no servidor'
      });
    }

    if (result.length > 0) {
      const docente = result[0];
      const senhaValida = await bcrypt.compare(senha, docente.senha);

      if (senhaValida) {
        // Gera JWT com id e identificador (duração 8h)
        const token = jwt.sign({ id: docente.id, identificador: docente.identificador }, JWT_SECRET, { expiresIn: '8h' });

        res.json({
          success: true,
          message: 'Login realizado com sucesso',
          token,
          user: {
            id: docente.id,
            nome: docente.nome,
            identificador: docente.identificador
          }
        });
      } else {
        res.status(401).json({
          success: false,
          message: 'Identificador ou senha inválidos'
        });
      }
    } else {
      res.status(401).json({
        success: false,
        message: 'Identificador ou senha inválidos'
      });
    }
  });
}

// --- Endpoints de eventos do calendário ---
// LISTAR eventos por mês (disponível para todos - alunos chamam sem token)
app.get('/api/events', (req, res) => {
  const year = parseInt(req.query.year, 10);
  const month = parseInt(req.query.month, 10); // 1-12
  const teacherId = req.query.teacher_id || null; // opcional

  if (!year || !month || month < 1 || month > 12) {
    return res.status(400).json({ success: false, message: 'Parâmetros year e month (1-12) são obrigatórios' });
  }

  const first = `${year}-${String(month).padStart(2, '0')}-01`;
  const lastDate = new Date(year, month, 0).getDate();
  const last = `${year}-${String(month).padStart(2, '0')}-${String(lastDate).padStart(2, '0')}`;

  let sql = `SELECT id, teacher_id, DATE_FORMAT(date, '%Y-%m-%d') AS date, title, color FROM calendario_events WHERE date BETWEEN ? AND ?`;
  const params = [first, last];
  if (teacherId) {
    sql += ' AND teacher_id = ?';
    params.push(teacherId);
  }

  db.query(sql, params, (err, results) => {
    if (err) {
      console.error('Erro ao buscar eventos:', err);
      return res.status(500).json({ success: false, message: 'Erro no servidor', error: err.message });
    }
    return res.json({ success: true, events: results });
  });
});

// CRIAR evento (apenas docente autenticado)
app.post('/api/events', authenticateJWT, (req, res) => {
  // payload: { date: 'YYYY-MM-DD', title, color: 'green'|'red'|'none' }
  const teacherId = req.user && req.user.id ? req.user.id : null;
  const { date, title, color } = req.body || {};

  if (!date || !title || !color) {
    return res.status(400).json({ success: false, message: 'date, title e color são obrigatórios' });
  }

  const sql = `INSERT INTO calendario_events (teacher_id, date, title, color) VALUES (?, ?, ?, ?)`;
  db.query(sql, [teacherId, date, title, color], (err, result) => {
    if (err) {
      // se duplicado, atualizamos a entrada existente
      if (err.code === 'ER_DUP_ENTRY') {
        const up = `UPDATE calendario_events SET title = ?, color = ?, teacher_id = ? WHERE date = ?`;
        db.query(up, [title, color, teacherId, date], (err2, result2) => {
          if (err2) {
            console.error('Erro ao resolver duplicado:', err2);
            return res.status(500).json({ success: false, message: 'Erro interno', error: err2.message });
          }
          return res.json({ success: true, message: 'Evento atualizado (duplicado)', id: result2.insertId || null });
        });
      } else {
        console.error('Erro ao inserir evento:', err);
        return res.status(500).json({ success: false, message: 'Erro ao inserir evento', error: err.message });
      }
      return;
    }
    return res.status(201).json({ success: true, message: 'Evento criado', id: result.insertId });
  });
});

// ATUALIZAR evento (apenas docente autenticado) - alterar título/cor (e opcionalmente data)
app.put('/api/events/:id', authenticateJWT, (req, res) => {
  const teacherId = req.user && req.user.id ? req.user.id : null;
  const id = parseInt(req.params.id, 10);
  const { date, title, color } = req.body || {};

  if (!id || !date || !title || !color) {
    return res.status(400).json({ success: false, message: 'id, date, title e color são obrigatórios' });
  }

  const sql = `UPDATE calendario_events SET date = ?, title = ?, color = ?, teacher_id = ? WHERE id = ?`;
  db.query(sql, [date, title, color, teacherId, id], (err, result) => {
    if (err) {
      console.error('Erro ao atualizar evento:', err);
      return res.status(500).json({ success: false, message: 'Erro ao atualizar evento', error: err.message });
    }
    return res.json({ success: true, message: 'Evento atualizado', affectedRows: result.affectedRows });
  });
});

// REMOVER evento (apenas docente autenticado)
app.delete('/api/events/:id', authenticateJWT, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ success: false, message: 'ID inválido' });

  const sql = `DELETE FROM calendario_events WHERE id = ?`;
  db.query(sql, [id], (err, result) => {
    if (err) {
      console.error('Erro ao deletar evento:', err);
      return res.status(500).json({ success: false, message: 'Erro ao deletar', error: err.message });
    }
    return res.json({ success: true, message: 'Evento removido', affectedRows: result.affectedRows });
  });
});

// Serve arquivos estáticos
app.use(express.static(path.join(__dirname)));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});