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

db.query(createAlunos, (err) => {
  if (err) console.error('Erro ao criar/verificar tabela alunos:', err.message);
  else {
    console.log('Tabela alunos verificada/criada');
    db.query(createDocentes, (err2) => {
      if (err2) console.error('Erro ao criar/verificar tabela docentes:', err2.message);
      else console.log('Tabela docentes verificada/criada');
    });
  }
});

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
      const token = 'token_' + aluno.id;

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
        const token = 'token_' + docente.id;

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
});

app.use(express.static(path.join(__dirname)));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});