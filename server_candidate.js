require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const User = require("./models/user");
const Facility = require("./models/facility");
const Consultation = require("./models/consultation");
const OutbreakAlert = require("./models/outbreakAlert");
const ChatMessage = require("./models/chatMessage");

mongoose.set("bufferCommands", false);
const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
const MONGO_URI = process.env.MONGO_URI;
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

if (!JWT_SECRET) throw new Error("JWT_SECRET is required.");
if (!MONGO_URI) throw new Error("MONGO_URI is required.");

let databaseReady = false;

const GENERATED_DIR = path.join(__dirname, "generated");
const RECEITAS_DIR = path.join(GENERATED_DIR, "receitas");
const REGISTROS_DIR = path.join(GENERATED_DIR, "registros");
fs.mkdirSync(RECEITAS_DIR, { recursive: true });
fs.mkdirSync(REGISTROS_DIR, { recursive: true });

const EMAIL_CODE_TTL_MINUTES = 15;
const VERIFICATION_MODE = process.env.VERIFICATION_MODE || "app_code"; // app_code or email
const EMAIL_CODE_MAX_ATTEMPTS = 5;

const TERMS_TEXT = {
  versao: "2026-03-07",
  titulo: "Termos de Utilizacao e Politica de Privacidade",
  resumo: [
    "A plataforma Health Connected trata dados de saude e identificacao para prestacao de cuidados.",
    "Dados sensiveis so sao expostos a profissionais quando o paciente concede consentimento para aquela consulta.",
    "Gestores podem aceder dados operacionais para governanca, auditoria e seguranca, com dever de confidencialidade.",
    "Dados de localizacao podem ser usados para monitoria epidemiologica e alertas de surtos.",
    "Profissionais devem ter carteira validada para acesso completo as ferramentas clinicas.",
    "Receitas e registros medicos podem ser gerados em PDF e enviados ao paciente.",
    "Ao rejeitar os termos, o acesso a plataforma fica bloqueado ate nova adesao formal."
  ]
};

const DEFAULT_FACILITIES = [
  { nome: "Hospital Central de Luanda", tipo: "hospital", endereco: "Luanda", lat: -8.839, lng: 13.2894, especialidades: ["Pediatria", "Cardiologia", "Clinica Geral"] },
  { nome: "Clinica Esperanca", tipo: "hospital", endereco: "Benfica, Luanda", lat: -8.92, lng: 13.19, especialidades: ["Pediatria", "Dentista"] },
  { nome: "Farmacia Popular Luanda", tipo: "farmacia", endereco: "Mutamba, Luanda", lat: -8.815, lng: 13.23, especialidades: [] }
];

const HEALTH_DICTIONARY = [
  { tema: "Hipertensao", descricao: "Pressao arterial alta pode aumentar risco cardiovascular. Reduza sal, controle peso e acompanhe periodicamente.", tags: ["hipertensao", "pressao", "pressao alta", "cardiologia"] },
  { tema: "Diabetes", descricao: "Diabetes exige controle de glicemia, alimentacao equilibrada, atividade fisica e seguimento medico regular.", tags: ["diabetes", "glicose", "acucar"] },
  { tema: "Febre", descricao: "Febre persistente por mais de 48 horas ou associada a falta de ar, dor intensa ou desidratacao exige avaliacao medica.", tags: ["febre", "temperatura", "calafrio"] },
  { tema: "Saude infantil", descricao: "Criancas devem manter vacinacao em dia, hidratacao adequada e observacao de sinais de alerta como letargia e febre alta.", tags: ["pediatria", "crianca", "infantil", "vacina"] },
  { tema: "Saude mental", descricao: "Ansiedade e estresse podem ser reduzidos com rotina, sono regular e apoio profissional quando necessario.", tags: ["ansiedade", "estresse", "psicologia", "saude mental"] }
];

app.disable("x-powered-by");
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  next();
});
app.use(cors({ origin: CORS_ORIGIN === "*" ? true : CORS_ORIGIN.split(",") }));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname)));

app.use((req, res, next) => {
  const needsDb = (req.path.startsWith("/auth") || req.path.startsWith("/api")) && req.path !== "/auth/terms";
  if (needsDb && !databaseReady) {
    return res.status(503).json({
      ok: false,
      error: "Base de dados indisponivel no momento.",
      hint: "Verifique conexao com MongoDB Atlas (DNS/IP whitelist) e tente novamente."
    });
  }
  return next();
});

function hashCode(code) {
  return crypto.createHash("sha256").update(String(code)).digest("hex");
}

function generateEmailCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function parseDayKey(date = new Date()) {
  return date.toISOString().slice(0, 10);
}

function buildSessionPayload(user) {
  return {
    id: user._id.toString(),
    nome: user.nome,
    email: user.email,
    role: user.role || "paciente",
    especialidade: user.especialidade || "",
    emailVerificado: Boolean(user.emailVerificado),
    termosStatus: user.termosStatus || "pendente",
    onboardingCompleto: Boolean(user.onboardingCompleto),
    profissionalStatus: user.profissionalStatus || "nao_aplicavel"
  };
}

async function sendEmail({ to, subject, html, attachments }) {
  let nodemailer;
  try {
    nodemailer = require("nodemailer");
  } catch (_err) {
    console.log(`nodemailer missing. Email to ${to}: ${subject}`);
    return;
  }

  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  const from = process.env.EMAIL_FROM || user || "noreply@health-connected.local";

  if (!host || !user || !pass) {
    console.log(`SMTP not configured. Email to ${to}: ${subject}`);
    return;
  }

  const transporter = nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: { user, pass }
  });

  await transporter.sendMail({ from, to, subject, html, attachments: attachments || [] });
}

async function sendVerificationEmail(to, code) {
  if (VERIFICATION_MODE !== "email") {
    console.log(`Verification code for ${to}: ${code}`);
    return;
  }
  await sendEmail({
    to,
    subject: "Codigo de verificacao - Health Connected",
    html: `<p>Seu codigo de verificacao e: <b>${code}</b></p><p>Valido por ${EMAIL_CODE_TTL_MINUTES} minutos.</p>`
  });
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ ok: false, error: "Token nao fornecido" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.auth = decoded;
    req.userId = decoded.id;
    return next();
  } catch (_err) {
    return res.status(401).json({ ok: false, error: "Token invalido" });
  }
}

function requireRoles(...roles) {
  return (req, res, next) => {
    if (!req.auth || !roles.includes(req.auth.role)) {
      return res.status(403).json({ ok: false, error: "Acesso negado" });
    }
    return next();
  };
}

async function requireAppAccess(req, res, next) {
  try {
    const user = await User.findById(req.userId).select("emailVerificado termosStatus onboardingCompleto role profissionalStatus");
    if (!user) return res.status(404).json({ ok: false, error: "Usuario nao encontrado" });
    if (!user.emailVerificado) return res.status(403).json({ ok: false, error: "Email nao verificado", code: "email_nao_verificado" });
    if (user.termosStatus !== "aceite") return res.status(403).json({ ok: false, error: "Termos ainda nao aceites", code: "termos_pendentes" });
    if (!user.onboardingCompleto) return res.status(403).json({ ok: false, error: "Onboarding incompleto", code: "onboarding_incompleto" });
    if (user.role === "profissional" && user.profissionalStatus !== "aprovado") {
      return res.status(403).json({ ok: false, error: "Carteira profissional pendente de aprovacao", code: "carteira_pendente" });
    }
    req.currentUser = user;
    return next();
  } catch (err) {
    return res.status(500).json({ ok: false, error: "Erro ao validar acesso" });
  }
}

function normalizeSpecialty(text) {
  return String(text || "").trim().toLowerCase();
}

function haversineKm(lat1, lon1, lat2, lon2) {
  const toRad = (d) => (d * Math.PI) / 180;
  const R = 6371;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

async function listNearbyFacilities(lat, lng, type, limit = 5) {
  const query = { ativo: true };
  if (type) query.tipo = type;
  const facilities = await Facility.find(query).lean();
  return facilities
    .map((f) => ({ ...f, distanciaKm: haversineKm(lat, lng, f.lat, f.lng) }))
    .sort((a, b) => a.distanciaKm - b.distanciaKm)
    .slice(0, limit);
}

async function generatePdf(filePath, title, lines) {
  let PDFDocument;
  try {
    PDFDocument = require("pdfkit");
  } catch (_err) {
    throw new Error("Dependencia pdfkit ausente. Rode npm install.");
  }

  await new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 40 });
    const stream = fs.createWriteStream(filePath);
    stream.on("finish", resolve);
    stream.on("error", reject);
    doc.pipe(stream);

    doc.fontSize(18).text("Health Connected", { align: "left" });
    doc.moveDown(0.5);
    doc.fontSize(14).text(title, { align: "left" });
    doc.moveDown();
    doc.fontSize(10).text(`Gerado em: ${new Date().toISOString()}`);
    doc.moveDown();

    for (const line of lines) {
      doc.fontSize(11).text(line);
      doc.moveDown(0.4);
    }

    doc.end();
  });
}

async function sendOutbreakAlertsToManagers(alerts) {
  if (!alerts.length) return;
  const managers = await User.find({ role: "gestor", emailVerificado: true }).select("email nome");
  if (!managers.length) return;

  const htmlItems = alerts.map((a) => `<li><b>${a.localidade}</b>: ${a.casos} casos (${a.nivel})</li>`).join("");
  for (const m of managers) {
    await sendEmail({
      to: m.email,
      subject: "Alerta de Surto - Health Connected",
      html: `<p>Ola ${m.nome},</p><p>Foram detectadas zonas com risco epidemiologico:</p><ul>${htmlItems}</ul>`
    });
  }
}

app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "login.html")));
app.get("/health", (_req, res) => res.json({ ok: true, service: "health-connected-api", now: new Date().toISOString() }));
app.get("/ready", (_req, res) => {
  if (!databaseReady) return res.status(503).json({ ok: false, database: "disconnected" });
  return res.json({ ok: true, database: "connected" });
});

app.get("/auth/terms", (_req, res) => res.json({ ok: true, terms: TERMS_TEXT }));

app.post("/auth/cadastro", async (req, res, next) => {
  try {
    const { nome, email, senha } = req.body;
    if (!nome || !email || !senha) return res.status(400).json({ ok: false, error: "Nome, email e senha sao obrigatorios" });
    if (String(senha).length < 6) return res.status(400).json({ ok: false, error: "Senha deve ter no minimo 6 caracteres" });

    const normalizedEmail = String(email).trim().toLowerCase();
    const existing = await User.findOne({ email: normalizedEmail });
    if (existing) return res.status(409).json({ ok: false, error: "Email ja cadastrado" });

    const code = generateEmailCode();
    await User.create({
      nome: String(nome).trim(),
      email: normalizedEmail,
      senha: await bcrypt.hash(String(senha), 10),
      role: "paciente",
      emailVerificado: false,
      emailVerificationCodeHash: hashCode(code),
      emailVerificationCodeExpiresAt: new Date(Date.now() + EMAIL_CODE_TTL_MINUTES * 60 * 1000),
      termosStatus: "pendente",
      onboardingCompleto: false,
      profissionalStatus: "nao_aplicavel"
    });

    await sendVerificationEmail(normalizedEmail, code);
    return res.status(201).json({ ok: true, requiresEmailVerification: true, verificationMode: VERIFICATION_MODE, verificationCode: VERIFICATION_MODE === "app_code" ? code : undefined, message: VERIFICATION_MODE === "app_code" ? "Conta criada. Use o codigo exibido para verificar." : "Conta criada. Verifique o codigo enviado por email." });
  } catch (err) {
    if (err && err.code === 11000) return res.status(409).json({ ok: false, error: "Email ja cadastrado" });
    return next(err);
  }
});

app.post("/auth/verify-email/send", async (req, res, next) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ ok: false, error: "Email obrigatorio" });

    const user = await User.findOne({ email: String(email).trim().toLowerCase() });
    if (!user) return res.status(404).json({ ok: false, error: "Conta nao encontrada" });
    if (user.emailVerificado) return res.json({ ok: true, message: "Email ja verificado" });

    const code = generateEmailCode();
    user.emailVerificationCodeHash = hashCode(code);
    user.emailVerificationCodeExpiresAt = new Date(Date.now() + EMAIL_CODE_TTL_MINUTES * 60 * 1000);
    user.emailVerificationAttempts = 0;
    await user.save();

    await sendVerificationEmail(user.email, code);
    return res.json({ ok: true, verificationMode: VERIFICATION_MODE, verificationCode: VERIFICATION_MODE === "app_code" ? code : undefined, message: VERIFICATION_MODE === "app_code" ? "Novo codigo gerado." : "Novo codigo enviado" });
  } catch (err) {
    return next(err);
  }
});

app.post("/auth/verify-email/confirm", async (req, res, next) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ ok: false, error: "Email e codigo sao obrigatorios" });

    const user = await User.findOne({ email: String(email).trim().toLowerCase() });
    if (!user) return res.status(404).json({ ok: false, error: "Conta nao encontrada" });
    if (user.emailVerificado) return res.json({ ok: true, message: "Email ja verificado" });

    if (!user.emailVerificationCodeExpiresAt || user.emailVerificationCodeExpiresAt.getTime() < Date.now()) return res.status(400).json({ ok: false, error: "Codigo expirado" });
    if ((user.emailVerificationAttempts || 0) >= EMAIL_CODE_MAX_ATTEMPTS) return res.status(429).json({ ok: false, error: "Muitas tentativas. Solicite novo codigo" });

    if (hashCode(code) !== user.emailVerificationCodeHash) {
      user.emailVerificationAttempts = (user.emailVerificationAttempts || 0) + 1;
      await user.save();
      return res.status(400).json({ ok: false, error: "Codigo invalido" });
    }

    user.emailVerificado = true;
    user.emailVerificationCodeHash = "";
    user.emailVerificationCodeExpiresAt = null;
    user.emailVerificationAttempts = 0;
    await user.save();
    return res.json({ ok: true, message: "Email verificado com sucesso" });
  } catch (err) {
    return next(err);
  }
});

app.post("/auth/login", async (req, res, next) => {
  try {
    const { email, senha } = req.body;
    if (!email || !senha) return res.status(400).json({ ok: false, error: "Email e senha sao obrigatorios" });

    const user = await User.findOne({ email: String(email).trim().toLowerCase() });
    if (!user) return res.status(401).json({ ok: false, error: "Credenciais invalidas" });

    const valid = await bcrypt.compare(String(senha), user.senha);
    if (!valid) return res.status(401).json({ ok: false, error: "Credenciais invalidas" });

    if (user.termosStatus === "rejeitado") return res.status(403).json({ ok: false, error: "Termos rejeitados. Contacte o suporte para reativar." });

    const token = jwt.sign(buildSessionPayload(user), JWT_SECRET, { expiresIn: "7d" });
    return res.json({ ok: true, token, nome: user.nome, email: user.email, role: user.role, especialidade: user.especialidade, emailVerificado: user.emailVerificado, termosStatus: user.termosStatus, onboardingCompleto: user.onboardingCompleto, profissionalStatus: user.profissionalStatus });
  } catch (err) {
    return next(err);
  }
});

app.post("/auth/terms/accept", authMiddleware, async (req, res, next) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ ok: false, error: "Usuario nao encontrado" });
    if (!user.emailVerificado) return res.status(403).json({ ok: false, error: "Verifique o email antes de aceitar os termos" });

    user.termosStatus = "aceite";
    user.termosAceiteEm = new Date();
    await user.save();

    return res.json({ ok: true, message: "Termos aceites" });
  } catch (err) {
    return next(err);
  }
});

app.post("/auth/terms/reject", authMiddleware, async (req, res, next) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ ok: false, error: "Usuario nao encontrado" });

    user.termosStatus = "rejeitado";
    user.termosAceiteEm = null;
    await user.save();

    return res.json({ ok: true, message: "Termos rejeitados" });
  } catch (err) {
    return next(err);
  }
});

app.post("/auth/onboarding", authMiddleware, async (req, res, next) => {
  try {
    const { tipoSanguineo, documentoIdentificacao, contactoEmergencia, historicoClinico, alergias } = req.body;
    if (!tipoSanguineo || !documentoIdentificacao || !contactoEmergencia) return res.status(400).json({ ok: false, error: "Tipo sanguineo, documento e contacto de emergencia sao obrigatorios" });

    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ ok: false, error: "Usuario nao encontrado" });
    if (!user.emailVerificado) return res.status(403).json({ ok: false, error: "Verifique o email antes de concluir onboarding" });
    if (user.termosStatus !== "aceite") return res.status(403).json({ ok: false, error: "Aceite os termos antes de concluir onboarding" });

    user.tipoSanguineo = String(tipoSanguineo).trim();
    user.documentoIdentificacao = String(documentoIdentificacao).trim();
    user.contactoEmergencia = String(contactoEmergencia).trim();
    user.historicoClinico = String(historicoClinico || "").trim();
    user.alergias = String(alergias || "").trim();
    user.onboardingCompleto = true;

    if (user.role === "profissional" && user.profissionalStatus === "nao_aplicavel") {
      user.profissionalStatus = "pendente";
      user.profissionalStatusMotivo = "Aguardando verificacao de carteira";
    }

    await user.save();
    return res.json({ ok: true, message: "Onboarding concluido" });
  } catch (err) {
    return next(err);
  }
});

app.get("/auth/me", authMiddleware, async (req, res, next) => {
  try {
    const user = await User.findById(req.userId).select("-senha -emailVerificationCodeHash");
    if (!user) return res.status(404).json({ ok: false, error: "Usuario nao encontrado" });
    return res.json({ ok: true, user });
  } catch (err) {
    return next(err);
  }
});

app.put("/auth/me", authMiddleware, async (req, res, next) => {
  try {
    const allowed = ["nome", "nascimento", "morada", "telefone", "doencas", "peso", "altura", "tipoUsuario", "numeroCarteira", "especialidade"];
    const updates = {};
    for (const key of allowed) if (req.body[key] !== undefined) updates[key] = req.body[key];

    if (req.body.geoLat !== undefined && req.body.geoLng !== undefined && req.body.geoLat !== null && req.body.geoLng !== null) {
      updates.geo = { lat: Number(req.body.geoLat), lng: Number(req.body.geoLng) };
    }

    const current = await User.findById(req.userId);
    if (!current) return res.status(404).json({ ok: false, error: "Usuario nao encontrado" });

    if (updates.tipoUsuario === "Profissional" && current.role === "paciente") {
      updates.role = "profissional";
      updates.profissionalStatus = "pendente";
      updates.profissionalStatusMotivo = "Aguardando verificacao de carteira";
    }

    if (updates.numeroCarteira && (updates.role === "profissional" || current.role === "profissional")) {
      updates.profissionalStatus = "pendente";
      updates.profissionalStatusMotivo = "Aguardando verificacao da carteira pelo gestor";
    }

    const user = await User.findByIdAndUpdate(req.userId, updates, { new: true, runValidators: true }).select("-senha -emailVerificationCodeHash");
    return res.json({ ok: true, user });
  } catch (err) {
    return next(err);
  }
});

app.get("/auth/usuarios", authMiddleware, requireAppAccess, requireRoles("gestor"), async (_req, res, next) => {
  try {
    const users = await User.find().select("nome email role especialidade morada createdAt emailVerificado onboardingCompleto termosStatus profissionalStatus").sort({ createdAt: -1 });
    return res.json({ ok: true, users });
  } catch (err) {
    return next(err);
  }
});

app.get("/api/gestor/profissionais-pendentes", authMiddleware, requireAppAccess, requireRoles("gestor"), async (_req, res, next) => {
  try {
    const profissionais = await User.find({ role: "profissional", profissionalStatus: "pendente" }).select("nome email especialidade numeroCarteira profissionalStatusMotivo createdAt").sort({ createdAt: 1 });
    return res.json({ ok: true, profissionais });
  } catch (err) {
    return next(err);
  }
});

app.post("/api/gestor/profissionais/:id/aprovar", authMiddleware, requireAppAccess, requireRoles("gestor"), async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user || user.role !== "profissional") return res.status(404).json({ ok: false, error: "Profissional nao encontrado" });
    user.profissionalStatus = "aprovado";
    user.profissionalStatusMotivo = "Carteira verificada e aprovada";
    await user.save();
    return res.json({ ok: true, message: "Profissional aprovado" });
  } catch (err) {
    return next(err);
  }
});

app.post("/api/gestor/profissionais/:id/rejeitar", authMiddleware, requireAppAccess, requireRoles("gestor"), async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user || user.role !== "profissional") return res.status(404).json({ ok: false, error: "Profissional nao encontrado" });
    user.profissionalStatus = "rejeitado";
    user.profissionalStatusMotivo = String(req.body.motivo || "Carteira rejeitada pelo gestor");
    await user.save();
    return res.json({ ok: true, message: "Profissional rejeitado" });
  } catch (err) {
    return next(err);
  }
});

app.post("/api/facilities", authMiddleware, requireAppAccess, requireRoles("gestor"), async (req, res, next) => {
  try {
    const { nome, tipo, endereco, lat, lng, especialidades } = req.body;
    if (!nome || !tipo || lat === undefined || lng === undefined) return res.status(400).json({ ok: false, error: "nome, tipo, lat e lng sao obrigatorios" });

    const facility = await Facility.create({ nome: String(nome).trim(), tipo, endereco: String(endereco || "").trim(), lat: Number(lat), lng: Number(lng), especialidades: Array.isArray(especialidades) ? especialidades : [] });
    return res.status(201).json({ ok: true, facility });
  } catch (err) {
    return next(err);
  }
});

app.get("/api/facilities", authMiddleware, requireAppAccess, async (req, res, next) => {
  try {
    const query = { ativo: true };
    if (req.query.type) query.tipo = req.query.type;
    const facilities = await Facility.find(query).sort({ nome: 1 });
    return res.json({ ok: true, facilities });
  } catch (err) {
    return next(err);
  }
});

app.get("/api/facilities/near", authMiddleware, requireAppAccess, async (req, res, next) => {
  try {
    const lat = Number(req.query.lat);
    const lng = Number(req.query.lng);
    if (Number.isNaN(lat) || Number.isNaN(lng)) return res.status(400).json({ ok: false, error: "lat e lng sao obrigatorios" });
    const facilities = await listNearbyFacilities(lat, lng, req.query.type ? String(req.query.type) : undefined, 5);
    return res.json({ ok: true, facilities });
  } catch (err) {
    return next(err);
  }
});

app.post("/api/consultas", authMiddleware, requireAppAccess, async (req, res, next) => {
  try {
    const { especialidade, localId, localNome, horario } = req.body;
    if (!especialidade) return res.status(400).json({ ok: false, error: "Especialidade obrigatoria" });

    const patient = await User.findById(req.userId).select("geo");
    if (!patient) return res.status(404).json({ ok: false, error: "Paciente nao encontrado" });

    let selectedLocal = null;
    if (localId) selectedLocal = await Facility.findById(localId);

    const consulta = await Consultation.create({
      pacienteId: req.userId,
      especialidade: String(especialidade).trim(),
      localNome: selectedLocal ? selectedLocal.nome : String(localNome || "").trim(),
      localEndereco: selectedLocal ? selectedLocal.endereco : "",
      horario: String(horario || ""),
      consentimentoDados: false
    });

    let proximos = [];
    if (patient.geo && patient.geo.lat !== null && patient.geo.lng !== null) {
      proximos = await listNearbyFacilities(patient.geo.lat, patient.geo.lng, "hospital", 3);
    }

    return res.status(201).json({ ok: true, consulta, locaisProximos: proximos });
  } catch (err) {
    return next(err);
  }
});

app.get("/api/consultas/minhas", authMiddleware, requireAppAccess, async (req, res, next) => {
  try {
    const consultas = await Consultation.find({ pacienteId: req.userId }).sort({ createdAt: -1 });
    return res.json({ ok: true, consultas });
  } catch (err) {
    return next(err);
  }
});

app.post("/api/consultas/:id/consent", authMiddleware, requireAppAccess, async (req, res, next) => {
  try {
    const allow = Boolean(req.body.allow);
    const consulta = await Consultation.findById(req.params.id);
    if (!consulta) return res.status(404).json({ ok: false, error: "Consulta nao encontrada" });
    if (String(consulta.pacienteId) !== String(req.userId)) return res.status(403).json({ ok: false, error: "Acesso negado" });
    if (consulta.status !== "pendente") return res.status(400).json({ ok: false, error: "Consentimento so pode ser alterado em consulta pendente" });

    consulta.consentimentoDados = allow;
    consulta.consentimentoAtualizadoEm = new Date();
    await consulta.save();

    return res.json({ ok: true, consulta });
  } catch (err) {
    return next(err);
  }
});

app.get("/api/consultas/pendentes/profissional", authMiddleware, requireAppAccess, requireRoles("profissional"), async (req, res, next) => {
  try {
    const user = await User.findById(req.userId).select("especialidade");
    if (!user || !user.especialidade) return res.status(400).json({ ok: false, error: "Profissional sem especialidade definida" });

    const consultas = await Consultation.find({ status: "pendente", especialidade: new RegExp(`^${user.especialidade}$`, "i") }).populate("pacienteId", "nome email morada telefone doencas").sort({ createdAt: 1 });

    const sanitized = consultas.map((c, idx) => {
      const base = { _id: c._id, especialidade: c.especialidade, localNome: c.localNome, localEndereco: c.localEndereco, horario: c.horario, status: c.status, consentimentoDados: c.consentimentoDados, aliasPaciente: `Paciente ${idx + 1}` };
      if (!c.consentimentoDados) return { ...base, paciente: { nome: `Paciente ${idx + 1}` } };
      return { ...base, paciente: { nome: c.pacienteId?.nome || `Paciente ${idx + 1}`, email: c.pacienteId?.email || "", morada: c.pacienteId?.morada || "", telefone: c.pacienteId?.telefone || "", doencas: c.pacienteId?.doencas || "" } };
    });

    return res.json({ ok: true, especialidade: user.especialidade, consultas: sanitized });
  } catch (err) {
    return next(err);
  }
});

app.get("/api/profissional/consultas/:id", authMiddleware, requireAppAccess, requireRoles("profissional"), async (req, res, next) => {
  try {
    const prof = await User.findById(req.userId).select("especialidade");
    const consulta = await Consultation.findById(req.params.id).populate("pacienteId", "nome email morada telefone doencas tipoSanguineo");
    if (!consulta) return res.status(404).json({ ok: false, error: "Consulta nao encontrada" });
    if (consulta.status !== "pendente") return res.status(403).json({ ok: false, error: "Consulta encerrada. Acesso aos dados revogado" });
    if (normalizeSpecialty(prof?.especialidade) !== normalizeSpecialty(consulta.especialidade)) return res.status(403).json({ ok: false, error: "Especialidade nao autorizada" });

    if (!consulta.consentimentoDados) return res.json({ ok: true, consulta: { _id: consulta._id, especialidade: consulta.especialidade, localNome: consulta.localNome, horario: consulta.horario, paciente: { nome: "Paciente sigiloso" }, consentimentoDados: false } });
    return res.json({ ok: true, consulta, consentimentoDados: true });
  } catch (err) {
    return next(err);
  }
});

app.get("/api/consultas/pendentes/gestor", authMiddleware, requireAppAccess, requireRoles("gestor"), async (_req, res, next) => {
  try {
    const consultas = await Consultation.find({ status: "pendente" }).populate("pacienteId", "nome email morada").sort({ createdAt: 1 });
    return res.json({ ok: true, consultas, privacidade: "Acesso restrito para governanca, auditoria e seguranca." });
  } catch (err) {
    return next(err);
  }
});

app.post("/api/consultas/:id/atender", authMiddleware, requireAppAccess, requireRoles("profissional", "gestor"), async (req, res, next) => {
  try {
    const consulta = await Consultation.findById(req.params.id);
    if (!consulta) return res.status(404).json({ ok: false, error: "Consulta nao encontrada" });
    if (consulta.status !== "pendente") return res.status(400).json({ ok: false, error: "Consulta ja finalizada" });

    if (req.auth.role === "profissional") {
      const user = await User.findById(req.userId).select("especialidade");
      if (!user || normalizeSpecialty(user.especialidade) !== normalizeSpecialty(consulta.especialidade)) return res.status(403).json({ ok: false, error: "Especialidade nao autorizada para esta consulta" });
    }

    consulta.status = "atendida";
    consulta.profissionalId = req.userId;
    consulta.observacaoAtendimento = String(req.body.observacao || "");
    consulta.atendidaEm = new Date();
    consulta.consentimentoDados = false;
    consulta.consentimentoAtualizadoEm = new Date();
    await consulta.save();

    return res.json({ ok: true, consulta });
  } catch (err) {
    return next(err);
  }
});

app.get("/api/consultas/:id/registro.pdf", authMiddleware, requireAppAccess, async (req, res, next) => {
  try {
    const consulta = await Consultation.findById(req.params.id).populate("pacienteId", "nome email morada telefone tipoSanguineo documentoIdentificacao").populate("profissionalId", "nome email especialidade");
    if (!consulta) return res.status(404).json({ ok: false, error: "Consulta nao encontrada" });

    const isGestor = req.auth.role === "gestor";
    const isPacienteOwner = String(consulta.pacienteId?._id || consulta.pacienteId) === String(req.userId);
    const isProfAssigned = req.auth.role === "profissional" && String(consulta.profissionalId?._id || consulta.profissionalId || "") === String(req.userId);
    if (!isGestor && !isPacienteOwner && !isProfAssigned) return res.status(403).json({ ok: false, error: "Sem permissao para este registro" });

    const filePath = path.join(REGISTROS_DIR, `registro-${consulta._id}-${Date.now()}.pdf`);
    await generatePdf(filePath, "Registro Medico", [
      `Consulta: ${consulta._id}`,
      `Especialidade: ${consulta.especialidade}`,
      `Status: ${consulta.status}`,
      `Paciente: ${consulta.pacienteId?.nome || "-"}`,
      `Email paciente: ${consulta.pacienteId?.email || "-"}`,
      `Tipo sanguineo: ${consulta.pacienteId?.tipoSanguineo || "-"}`,
      `Documento: ${consulta.pacienteId?.documentoIdentificacao || "-"}`,
      `Local: ${consulta.localNome || "-"}`,
      `Horario: ${consulta.horario || "-"}`,
      `Observacoes: ${consulta.observacaoAtendimento || "-"}`
    ]);

    return res.download(filePath, `registro-${consulta._id}.pdf`);
  } catch (err) {
    return next(err);
  }
});

app.post("/api/consultas/:id/receita", authMiddleware, requireAppAccess, requireRoles("profissional", "gestor"), async (req, res, next) => {
  try {
    const consulta = await Consultation.findById(req.params.id).populate("pacienteId", "nome email");
    if (!consulta) return res.status(404).json({ ok: false, error: "Consulta nao encontrada" });

    if (req.auth.role === "profissional") {
      if (consulta.status !== "pendente") return res.status(400).json({ ok: false, error: "Consulta encerrada. Nao e possivel emitir receita" });
      const prof = await User.findById(req.userId).select("especialidade");
      if (!prof || normalizeSpecialty(prof.especialidade) !== normalizeSpecialty(consulta.especialidade)) return res.status(403).json({ ok: false, error: "Especialidade nao autorizada" });
      if (!consulta.consentimentoDados) return res.status(403).json({ ok: false, error: "Paciente nao concedeu consentimento para dados sensiveis" });
    }

    const conteudo = String(req.body.conteudo || "").trim();
    if (!conteudo) return res.status(400).json({ ok: false, error: "Conteudo da receita obrigatorio" });

    const filePath = path.join(RECEITAS_DIR, `receita-${consulta._id}-${Date.now()}.pdf`);
    await generatePdf(filePath, "Receita Medica", [`Consulta: ${consulta._id}`, `Paciente: ${consulta.pacienteId?.nome || "-"}`, `Especialidade: ${consulta.especialidade}`, "", conteudo]);

    consulta.receitaPdfPath = filePath;
    consulta.receitaResumo = conteudo.slice(0, 500);
    await consulta.save();

    return res.json({ ok: true, message: "Receita PDF gerada", file: `/api/consultas/${consulta._id}/receita.pdf` });
  } catch (err) {
    return next(err);
  }
});

app.get("/api/consultas/:id/receita.pdf", authMiddleware, requireAppAccess, async (req, res, next) => {
  try {
    const consulta = await Consultation.findById(req.params.id).populate("pacienteId", "_id email").populate("profissionalId", "_id");
    if (!consulta || !consulta.receitaPdfPath) return res.status(404).json({ ok: false, error: "Receita nao encontrada" });

    const isGestor = req.auth.role === "gestor";
    const isPaciente = String(consulta.pacienteId?._id || consulta.pacienteId) === String(req.userId);
    const isProf = String(consulta.profissionalId?._id || consulta.profissionalId || "") === String(req.userId);
    if (!isGestor && !isPaciente && !isProf) return res.status(403).json({ ok: false, error: "Sem permissao" });

    return res.download(consulta.receitaPdfPath, `receita-${consulta._id}.pdf`);
  } catch (err) {
    return next(err);
  }
});

app.post("/api/consultas/:id/receita/enviar", authMiddleware, requireAppAccess, requireRoles("profissional", "gestor"), async (req, res, next) => {
  try {
    const consulta = await Consultation.findById(req.params.id).populate("pacienteId", "nome email");
    if (!consulta || !consulta.receitaPdfPath) return res.status(404).json({ ok: false, error: "Receita nao encontrada" });

    await sendEmail({
      to: consulta.pacienteId?.email,
      subject: "Receita medica - Health Connected",
      html: `<p>Ola ${consulta.pacienteId?.nome || "Paciente"},</p><p>Sua receita medica segue em anexo.</p>`,
      attachments: [{ filename: `receita-${consulta._id}.pdf`, path: consulta.receitaPdfPath }]
    });

    return res.json({ ok: true, message: "Receita enviada ao paciente" });
  } catch (err) {
    return next(err);
  }
});

app.get("/api/surtos", authMiddleware, requireAppAccess, requireRoles("gestor"), async (_req, res, next) => {
  try {
    const users = await User.find({ "geo.lat": { $ne: null }, "geo.lng": { $ne: null } }).select("geo morada");
    const buckets = new Map();

    for (const user of users) {
      const lat = Number(user.geo.lat);
      const lng = Number(user.geo.lng);
      const key = `${lat.toFixed(1)},${lng.toFixed(1)}`;
      const name = user.morada ? String(user.morada).split(",").slice(-2).join(",").trim() : `Zona ${key}`;
      buckets.set(key, { localidade: name || `Zona ${key}`, lat, lng, casos: (buckets.get(key)?.casos || 0) + 1 });
    }

    const data = [...buckets.values()].sort((a, b) => b.casos - a.casos);
    const dayKey = parseDayKey(new Date());

    const alertsToPersist = [];
    for (const item of data) {
      const nivel = item.casos >= 10 ? "alto" : item.casos >= 4 ? "moderado" : "baixo";
      if (nivel === "baixo") continue;
      alertsToPersist.push({ localidade: item.localidade, casos: item.casos, nivel, mensagem: `Risco ${nivel} de surto em ${item.localidade} (${item.casos} casos).`, dayKey });
    }

    const createdAlerts = [];
    for (const al of alertsToPersist) {
      try { createdAlerts.push(await OutbreakAlert.create(al)); } catch (_e) {}
    }

    await sendOutbreakAlertsToManagers(createdAlerts);
    return res.json({ ok: true, totalPatients: users.length, data, newAlerts: createdAlerts.length });
  } catch (err) {
    return next(err);
  }
});

app.get("/api/gestor/alerts", authMiddleware, requireAppAccess, requireRoles("gestor"), async (_req, res, next) => {
  try {
    const alerts = await OutbreakAlert.find().sort({ createdAt: -1 }).limit(50);
    return res.json({ ok: true, alerts });
  } catch (err) {
    return next(err);
  }
});

, "i");
    if (q) query.nome = new RegExp(q, "i");

    const profissionais = await User.find(query)
      .select("nome email especialidade numeroCarteira")
      .sort({ nome: 1 })
      .limit(200);

    return res.json({ ok: true, profissionais });
  } catch (err) {
    return next(err);
  }
});

app.get("/api/chat/conversas", authMiddleware, requireAppAccess, async (req, res, next) => {
  try {
    const userId = req.userId;
    const pipeline = [
      { $match: { $or: [{ senderId: new mongoose.Types.ObjectId(userId) }, { recipientId: new mongoose.Types.ObjectId(userId) }] } },
      { $sort: { createdAt: -1 } },
      {
        $group: {
          _id: {
            $cond: [{ $eq: ["$senderId", new mongoose.Types.ObjectId(userId)] }, "$recipientId", "$senderId"]
          },
          lastMessage: { $first: "$text" },
          lastAt: { $first: "$createdAt" }
        }
      },
      { $sort: { lastAt: -1 } }
    ];

    const convo = await ChatMessage.aggregate(pipeline);
    const ids = convo.map((c2) => c2._id);
    const users = await User.find({ _id: { $in: ids } }).select("nome especialidade role");
    const byId = new Map(users.map((u) => [String(u._id), u]));

    const conversas = convo.map((c2) => ({
      userId: String(c2._id),
      nome: byId.get(String(c2._id))?.nome || "Usuario",
      especialidade: byId.get(String(c2._id))?.especialidade || "",
      role: byId.get(String(c2._id))?.role || "",
      lastMessage: c2.lastMessage,
      lastAt: c2.lastAt
    }));

    return res.json({ ok: true, conversas });
  } catch (err) {
    return next(err);
  }
});

app.get("/api/chat/messages/:otherUserId", authMiddleware, requireAppAccess, async (req, res, next) => {
  try {
    const otherUserId = req.params.otherUserId;
    const limit = Math.min(Number(req.query.limit || 150), 400);

    const messages = await ChatMessage.find({
      $or: [
        { senderId: req.userId, recipientId: otherUserId },
        { senderId: otherUserId, recipientId: req.userId }
      ]
    })
      .sort({ createdAt: 1 })
      .limit(limit)
      .lean();

    return res.json({ ok: true, messages });
  } catch (err) {
    return next(err);
  }
});

app.post("/api/chat/messages/:otherUserId", authMiddleware, requireAppAccess, async (req, res, next) => {
  try {
    const otherUserId = req.params.otherUserId;
    const text = String(req.body.text || "").trim();
    if (!text) return res.status(400).json({ ok: false, error: "Mensagem vazia" });

    const otherUser = await User.findById(otherUserId).select("_id");
    if (!otherUser) return res.status(404).json({ ok: false, error: "Destino nao encontrado" });

    const msg = await ChatMessage.create({ senderId: req.userId, recipientId: otherUserId, text });
    return res.status(201).json({ ok: true, message: msg });
  } catch (err) {
    return next(err);
  }
});
app.get("/api/chatbot/dicionario", authMiddleware, requireAppAccess, (req, res) => {
  const q = String(req.query.q || "").trim().toLowerCase();
  const items = q ? HEALTH_DICTIONARY.filter((d) => d.tema.toLowerCase().includes(q) || d.tags.some((t) => t.includes(q))) : HEALTH_DICTIONARY;
  return res.json({ ok: true, items });
});

app.post("/api/chatbot/reply", authMiddleware, requireAppAccess, (req, res) => {
  const message = String(req.body.message || "").toLowerCase();
  if (!message) return res.status(400).json({ ok: false, error: "Mensagem vazia" });

  const hit = HEALTH_DICTIONARY.find((d) => d.tags.some((t) => message.includes(t)) || message.includes(d.tema.toLowerCase()));
  if (hit) return res.json({ ok: true, reply: `${hit.tema}: ${hit.descricao}`, sugestoes: HEALTH_DICTIONARY.slice(0, 3).map((d) => d.tema) });

  return res.json({ ok: true, reply: "Nao encontrei esse termo no dicionario. Tente: hipertensao, diabetes, febre, saude mental.", sugestoes: HEALTH_DICTIONARY.slice(0, 5).map((d) => d.tema) });
});

app.use((err, _req, res, _next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ ok: false, error: "Erro interno do servidor" });
});

async function ensureSeedFacilities() {
  const count = await Facility.countDocuments();
  if (count === 0) {
    await Facility.insertMany(DEFAULT_FACILITIES);
    console.log("Default facilities seeded.");
  }
}

mongoose.connection.on("connected", async () => {
  databaseReady = true;
  console.log("MongoDB connected.");
  try {
    await ensureSeedFacilities();
  } catch (err) {
    console.error("Failed seeding facilities:", err.message);
  }
});

mongoose.connection.on("disconnected", () => {
  databaseReady = false;
  console.warn("MongoDB disconnected.");
});

const LOCAL_MONGO_URI = process.env.LOCAL_MONGO_URI || "mongodb://127.0.0.1:27017/health_connected";

async function connectDatabase(){
  try {
    await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 10000 });
  } catch (err) {
    databaseReady = false;
    console.error("MongoDB primary connection failed:", err.message);
    if (process.env.MONGO_FALLBACK_LOCAL === "false") return;
    try {
      await mongoose.connect(LOCAL_MONGO_URI, { serverSelectionTimeoutMS: 4000 });
      console.log(`Connected using local MongoDB fallback: ${LOCAL_MONGO_URI}`);
    } catch (err2) {
      databaseReady = false;
      console.error("MongoDB local fallback failed:", err2.message);
    }
  }
}

connectDatabase();

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Health Connected server running on port ${PORT}`);
});









