const express = require("express");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  console.error("ERRO: DATABASE_URL não configurada.");
  process.exit(1);
}

if (!process.env.SESSION_SECRET) {
  console.error("ERRO: SESSION_SECRET não configurada.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("railway.internal")
    ? false
    : { rejectUnauthorized: false }
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  store: new PgSession({
    pool,
    tableName: "user_sessions",
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 12
  }
}));

function dinheiro(valor) {
  return Number(valor || 0).toLocaleString("pt-BR", {
    style: "currency",
    currency: "BRL"
  });
}

function pagina(titulo, conteudo) {
  return `
  <!DOCTYPE html>
  <html lang="pt-BR">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${titulo} - TROOPA DO GALO</title>
    <style>
      * { box-sizing:border-box; }
      body {
        margin:0;
        font-family:Arial,sans-serif;
        background:#ffdf00;
        color:#171717;
      }
      header {
        background:#171717;
        color:#ffdf00;
        padding:22px;
        text-align:center;
        font-weight:bold;
        font-size:23px;
      }
      main {
        max-width:1000px;
        margin:25px auto;
        padding:15px;
      }
      .card {
        background:white;
        border-radius:14px;
        padding:20px;
        margin-bottom:16px;
        box-shadow:0 3px 12px #0002;
      }
      input,select,button {
        width:100%;
        padding:13px;
        margin:7px 0;
        border:1px solid #ccc;
        border-radius:8px;
        font-size:15px;
      }
      button,.btn {
        background:#171717;
        color:#ffdf00;
        border:0;
        font-weight:bold;
        cursor:pointer;
        text-decoration:none;
        display:inline-block;
        text-align:center;
        padding:13px;
        border-radius:8px;
      }
      a { color:#171717; }
      table {
        width:100%;
        border-collapse:collapse;
        background:white;
      }
      td,th {
        padding:10px;
        border-bottom:1px solid #ddd;
        text-align:left;
      }
      .valor { font-size:25px;font-weight:bold; }
      .erro { color:#b00020; }
      .menu { display:flex;gap:8px;flex-wrap:wrap;margin-bottom:15px; }
      .menu a { background:#171717;color:#ffdf00;padding:12px;border-radius:8px;text-decoration:none; }
      @media(max-width:600px) {
        table { font-size:12px; }
        td,th { padding:7px; }
      }
    </style>
  </head>
  <body>
    <header>🐓 TROOPA DO GALO</header>
    <main>${conteudo}</main>
  </body>
  </html>`;
}

function protegido(req,res,next) {
  if (!req.session.usuario) return res.redirect("/login");
  next();
}

function admin(req,res,next) {
  if (!req.session.usuario || req.session.usuario.role !== "admin") {
    return res.status(403).send("Acesso não autorizado.");
  }
  next();
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      extension TEXT UNIQUE,
      role TEXT NOT NULL DEFAULT 'employee',
      job TEXT NOT NULL DEFAULT 'Atendente',
      pix TEXT,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS production (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      amount NUMERIC(12,2) NOT NULL,
      employee_rate NUMERIC(5,2) NOT NULL,
      employee_commission NUMERIC(12,2) NOT NULL,
      company_commission NUMERIC(12,2) NOT NULL,
      result TEXT NOT NULL,
      production_date DATE NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS withdrawals (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      amount NUMERIC(12,2) NOT NULL,
      pix TEXT,
      status TEXT DEFAULT 'requested',
      created_at TIMESTAMP DEFAULT NOW(),
      paid_at TIMESTAMP
    );
  `);

  if (process.env.ADMIN_USER && process.env.ADMIN_PASSWORD) {
    const existente = await pool.query(
      "SELECT id FROM users WHERE username=$1",
      [process.env.ADMIN_USER]
    );

    if (!existente.rowCount) {
      const senha = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
      await pool.query(
        `INSERT INTO users(name,username,password,role,job)
         VALUES($1,$2,$3,'admin','Administrador')`,
        ["Administrador", process.env.ADMIN_USER, senha]
      );
      console.log("Administrador inicial criado.");
    }
  }

  console.log("Banco de dados conectado e tabelas verificadas.");
}

app.get("/", (req,res) => {
  if (!req.session.usuario) return res.redirect("/login");
  res.redirect("/painel");
});

app.get("/health", async (req,res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status:"ok", database:"connected" });
  } catch (e) {
    res.status(500).json({ status:"error", message:"Banco indisponível" });
  }
});

app.get("/login", (req,res) => {
  res.send(pagina("Entrar", `
    <div class="card">
      <h2>Entrar no sistema</h2>
      <form method="POST" action="/login">
        <input name="username" placeholder="Usuário" required>
        <input name="password" type="password" placeholder="Senha" required>
        <button>ENTRAR</button>
      </form>
    </div>
  `));
});

app.post("/login", async (req,res) => {
  try {
    const { username,password } = req.body;
    const resultado = await pool.query(
      "SELECT * FROM users WHERE username=$1 AND active=TRUE",
      [username]
    );

    if (!resultado.rowCount) {
      return res.send(pagina("Erro", `<div class="card erro">Usuário ou senha incorretos. <a href="/login">Voltar</a></div>`));
    }

    const usuario = resultado.rows[0];
    const correto = await bcrypt.compare(password,usuario.password);

    if (!correto) {
      return res.send(pagina("Erro", `<div class="card erro">Usuário ou senha incorretos. <a href="/login">Voltar</a></div>`));
    }

    req.session.regenerate(err => {
      if (err) return res.status(500).send("Erro ao iniciar sessão.");
      req.session.usuario = {
        id:usuario.id,
        name:usuario.name,
        role:usuario.role
      };
      req.session.save(err => {
        if (err) return res.status(500).send("Erro ao salvar sessão.");
        res.redirect("/painel");
      });
    });
  } catch(e) {
    console.error(e);
    res.status(500).send("Erro no login.");
  }
});

app.get("/sair",(req,res) => {
  req.session.destroy(() => res.redirect("/login"));
});

app.get("/painel",protegido,async (req,res) => {
  try {
    const u = req.session.usuario;

    if (u.role === "admin") {
      const funcionarios = await pool.query(
        "SELECT COUNT(*) AS total FROM users WHERE role='employee' AND active=TRUE"
      );
      const producao = await pool.query(
        "SELECT COALESCE(SUM(amount),0) AS total FROM production"
      );
      const comissoes = await pool.query(
        "SELECT COALESCE(SUM(employee_commission),0) AS total FROM production"
      );
      const saques = await pool.query(
        "SELECT COUNT(*) AS total FROM withdrawals WHERE status='requested'"
      );

      return res.send(pagina("Painel ADM", `
        <div class="card">
          <h2>Olá, ${u.name}</h2>
          <p>Painel administrativo</p>
          <div class="menu">
            <a href="/admin/funcionarios">Funcionários</a>
            <a href="/admin/producao">Produção</a>
            <a href="/admin/saques">Saques</a>
            <a href="/sair">Sair</a>
          </div>
        </div>
        <div class="card"><h3>Funcionários ativos</h3><div class="valor">${funcionarios.rows[0].total}</div></div>
        <div class="card"><h3>Produção total</h3><div class="valor">${dinheiro(producao.rows[0].total)}</div></div>
        <div class="card"><h3>Comissões dos funcionários</h3><div class="valor">${dinheiro(comissoes.rows[0].total)}</div></div>
        <div class="card"><h3>Saques aguardando pagamento</h3><div class="valor">${saques.rows[0].total}</div></div>
      `));
    }

    const saldo = await pool.query(`
      SELECT
        COALESCE((SELECT SUM(employee_commission) FROM production WHERE user_id=$1),0)
        -
        COALESCE((SELECT SUM(amount) FROM withdrawals WHERE user_id=$1 AND status IN ('requested','paid')),0)
        AS disponivel
    `,[u.id]);

    const semanal = await pool.query(`
      SELECT COALESCE(SUM(employee_commission),0) AS total
      FROM production
      WHERE user_id=$1
      AND production_date >= date_trunc('week', CURRENT_DATE)::date
      AND production_date <= CURRENT_DATE
    `,[u.id]);

    const historico = await pool.query(
      `SELECT * FROM production WHERE user_id=$1 ORDER BY production_date DESC,id DESC LIMIT 30`,
      [u.id]
    );

    const saldoDisponivel = Number(saldo.rows[0].disponivel);

    res.send(pagina("Meu painel", `
      <div class="card">
        <h2>Olá, ${u.name}</h2>
        <div class="menu">
          <a href="/saque">Solicitar saque</a>
          <a href="/sair">Sair</a>
        </div>
      </div>
      <div class="card"><h3>Saldo disponível</h3><div class="valor">${dinheiro(saldoDisponivel)}</div></div>
      <div class="card"><h3>Comissão desta semana</h3><div class="valor">${dinheiro(semanal.rows[0].total)}</div></div>
      <div class="card">
        <h3>Minha produção</h3>
        <table><tr><th>Data</th><th>Valor</th><th>Comissão</th></tr>
        ${historico.rows.map(p=>`<tr><td>${new Date(p.production_date).toLocaleDateString("pt-BR")}</td><td>${dinheiro(p.amount)}</td><td>${dinheiro(p.employee_commission)}</td></tr>`).join("")}
        </table>
      </div>
    `));
  } catch(e) {
    console.error(e);
    res.status(500).send("Erro ao carregar painel.");
  }
});

app.get("/admin/funcionarios",admin,async (req,res) => {
  const lista = await pool.query(
    "SELECT id,name,username,extension,job,pix,active FROM users WHERE role='employee' ORDER BY name"
  );

  res.send(pagina("Funcionários", `
    <div class="card">
      <a href="/painel">← Voltar</a>
      <h2>Cadastrar funcionário</h2>
      <form method="POST" action="/admin/funcionarios">
        <input name="name" placeholder="Nome completo" required>
        <input name="username" placeholder="Usuário de acesso" required>
        <input name="password" type="password" placeholder="Senha inicial" required minlength="8">
        <input name="extension" placeholder="Ramal exclusivo" required>
        <select name="job">
          <option>Atendente</option>
          <option>Tripeiro</option>
        </select>
        <input name="pix" placeholder="Chave PIX">
        <button>CADASTRAR</button>
      </form>
    </div>
    <div class="card">
      <h2>Funcionários cadastrados</h2>
      <table>
        <tr><th>Nome</th><th>Ramal</th><th>Função</th><th>Usuário</th><th>Status</th></tr>
        ${lista.rows.map(f=>`<tr><td>${f.name}</td><td>${f.extension}</td><td>${f.job}</td><td>${f.username}</td><td>${f.active?"Ativo":"Inativo"}</td></tr>`).join("")}
      </table>
    </div>
  `));
});

app.post("/admin/funcionarios",admin,async (req,res) => {
  try {
    const {name,username,password,extension,job,pix} = req.body;

    if (!name || !username || !password || !extension) {
      return res.status(400).send("Preencha os campos obrigatórios.");
    }

    if (!["Atendente","Tripeiro"].includes(job)) {
      return res.status(400).send("Função inválida.");
    }

    const hash = await bcrypt.hash(password,12);

    await pool.query(
      `INSERT INTO users(name,username,password,extension,job,pix,role)
       VALUES($1,$2,$3,$4,$5,$6,'employee')`,
      [name,username,hash,extension,job,pix || null]
    );

    res.redirect("/admin/funcionarios");
  } catch(e) {
    console.error(e);
    res.status(400).send("Não foi possível cadastrar. Verifique se usuário e ramal já existem.");
  }
});

app.get("/admin/producao",admin,async (req,res) => {
  const funcionarios = await pool.query(
    "SELECT id,name,job,extension FROM users WHERE role='employee' AND active=TRUE ORDER BY name"
  );

  const historico = await pool.query(`
    SELECT p.*,u.name
    FROM production p
    JOIN users u ON u.id=p.user_id
    ORDER BY p.production_date DESC,p.id DESC
    LIMIT 50
  `);

  res.send(pagina("Produção", `
    <div class="card">
      <a href="/painel">← Voltar</a>
      <h2>Lançar produção</h2>
      <form method="POST" action="/admin/producao">
        <select name="user_id" required>
          <option value="">Selecione funcionário</option>
          ${funcionarios.rows.map(f=>`<option value="${f.id}">${f.name} - Ramal ${f.extension} - ${f.job}</option>`).join("")}
        </select>
        <input type="date" name="production_date" required>
        <input type="number" name="amount" step="0.01" min="0.01" placeholder="Valor da produção em R$" required>
        <select name="result" required>
          <option value="first">Primeira linha concluída</option>
          <option value="both">Primeira e segunda linhas concluídas</option>
          <option value="tripeiro">Produção de tripeiro</option>
        </select>
        <button>REGISTRAR PRODUÇÃO</button>
      </form>
    </div>
    <div class="card">
      <h2>Últimos lançamentos</h2>
      <table>
        <tr><th>Funcionário</th><th>Data</th><th>Produção</th><th>Comissão</th><th>Empresa</th></tr>
        ${historico.rows.map(p=>`<tr><td>${p.name}</td><td>${new Date(p.production_date).toLocaleDateString("pt-BR")}</td><td>${dinheiro(p.amount)}</td><td>${dinheiro(p.employee_commission)}</td><td>${dinheiro(p.company_commission)}</td></tr>`).join("")}
      </table>
    </div>
  `));
});

app.post("/admin/producao",admin,async (req,res) => {
  const {user_id,amount,production_date,result} = req.body;
  const valor = Number(amount);

  if (!Number.isFinite(valor) || valor <= 0) {
    return res.status(400).send("Valor de produção inválido.");
  }

  if (!/^\d{4}-\d{2}-\d{2}$/.test(production_date || "")) {
    return res.status(400).send("Data inválida.");
  }

  const funcionario = await pool.query(
    "SELECT id,job FROM users WHERE id=$1 AND role='employee' AND active=TRUE",
    [user_id]
  );

  if (!funcionario.rowCount) return res.status(400).send("Funcionário não encontrado.");

  const job = funcionario.rows[0].job;

  let taxa;

  if (job === "Tripeiro") {
    taxa = 30;
  } else if (job === "Atendente" && result === "first") {
    taxa = 25;
  } else if (job === "Atendente" && result === "both") {
    taxa = 50;
  } else {
    return res.status(400).send("Resultado incompatível com a função.");
  }

  const comissao = valor * taxa / 100;
  const empresa = valor * 0.50;

  await pool.query(
    `INSERT INTO production(user_id,amount,employee_rate,employee_commission,company_commission,result,production_date)
     VALUES($1,$2,$3,$4,$5,$6,$7)`,
    [user_id,valor,taxa,comissao,empresa,result,production_date]
  );

  res.redirect("/admin/producao");
});

app.get("/saque",protegido,async (req,res) => {
  if (req.session.usuario.role === "admin") return res.redirect("/painel");

  const u = req.session.usuario;

  const saldo = await pool.query(`
    SELECT
      COALESCE((SELECT SUM(employee_commission) FROM production WHERE user_id=$1),0)
      -
      COALESCE((SELECT SUM(amount) FROM withdrawals WHERE user_id=$1 AND status IN ('requested','paid')),0)
      AS disponivel
  `,[u.id]);

  res.send(pagina("Solicitar saque", `
    <div class="card">
      <a href="/painel">← Voltar</a>
      <h2>Solicitar saque PIX</h2>
      <p>Saldo disponível: <strong>${dinheiro(saldo.rows[0].disponivel)}</strong></p>
      <form method="POST" action="/saque">
        <input type="number" name="amount" step="0.01" min="0.01" max="${Math.max(0,Number(saldo.rows[0].disponivel))}" placeholder="Valor do saque" required>
        <button>SOLICITAR SAQUE</button>
      </form>
      <p>O pagamento será realizado manualmente pelo administrador.</p>
    </div>
  `));
});

app.post("/saque",protegido,async (req,res) => {
  try {
    const u = req.session.usuario;
    const valor = Number(req.body.amount);

    if (!Number.isFinite(valor) || valor <= 0) {
      return res.status(400).send("Valor inválido.");
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const saldo = await client.query(`
        SELECT
          COALESCE((SELECT SUM(employee_commission) FROM production WHERE user_id=$1),0)
          -
          COALESCE((SELECT SUM(amount) FROM withdrawals WHERE user_id=$1 AND status IN ('requested','paid')),0)
          AS disponivel
      `,[u.id]);

      if (valor > Number(saldo.rows[0].disponivel)) {
        throw new Error("Saldo insuficiente.");
      }

      const funcionario = await client.query(
        "SELECT pix FROM users WHERE id=$1",
        [u.id]
      );

      if (!funcionario.rows[0].pix) {
        throw new Error("Cadastre sua chave PIX com o administrador antes de solicitar saque.");
      }

      await client.query(
        "INSERT INTO withdrawals(user_id,amount,pix) VALUES($1,$2,$3)",
        [u.id,valor,funcionario.rows[0].pix]
      );

      await client.query("COMMIT");
      res.redirect("/painel");
    } catch(e) {
      await client.query("ROLLBACK");
      res.status(400).send(e.message);
    } finally {
      client.release();
    }
  } catch(e) {
    console.error(e);
    res.status(500).send("Erro ao solicitar saque.");
  }
});

app.get("/admin/saques",admin,async (req,res) => {
  const lista = await pool.query(`
    SELECT w.*,u.name,u.extension
    FROM withdrawals w
    JOIN users u ON u.id=w.user_id
    ORDER BY w.created_at DESC
  `);

  res.send(pagina("Saques", `
    <div class="card">
      <a href="/painel">← Voltar</a>
      <h2>Pedidos de saque</h2>
      <table>
        <tr><th>Funcionário</th><th>Valor</th><th>PIX</th><th>Status</th><th>Ação</th></tr>
        ${lista.rows.map(w=>`<tr>
          <td>${w.name} (${w.extension})</td>
          <td>${dinheiro(w.amount)}</td>
          <td>${w.pix || "-"}</td>
          <td>${w.status}</td>
          <td>${w.status==="requested"?`<form method="POST" action="/admin/saque/${w.id}/pago"><button>MARCAR PAGO</button></form>`:"Concluído"}</td>
        </tr>`).join("")}
      </table>
    </div>
  `));
});

app.post("/admin/saque/:id/pago",admin,async (req,res) => {
  await pool.query(
    "UPDATE withdrawals SET status='paid',paid_at=NOW() WHERE id=$1 AND status='requested'",
    [req.params.id]
  );
  res.redirect("/admin/saques");
});

app.use((req,res) => {
  res.status(404).send(pagina("Página não encontrada",`
    <div class="card">
      <h2>Página não encontrada</h2>
      <a href="/">Voltar ao início</a>
    </div>
  `));
});

initDb()
  .then(() => {
    app.listen(PORT,"0.0.0.0",() => {
      console.log(`TROOPA DO GALO rodando na porta ${PORT}`);
    });
  })
  .catch(err => {
    console.error("Falha ao iniciar banco de dados:",err);
    process.exit(1);
  });
