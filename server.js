const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, "public");
const DB_FILE = path.join(ROOT, "data", "db.json");

const sessions = new Map();

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.pbkdf2Sync(password, salt, 120000, 32, "sha256").toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = String(stored || "").split(":");
  if (!salt || !hash) return false;
  const candidate = hashPassword(password, salt).split(":")[1];
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(candidate));
}

function uid(prefix) {
  return `${prefix}_${crypto.randomBytes(10).toString("hex")}`;
}

function seedDb() {
  const now = new Date().toISOString();
  return {
    users: [
      {
        id: "admin_1",
        role: "admin",
        name: "Dr. Kutay",
        email: "deneme@ornek.com",
        passwordHash: hashPassword("123456"),
        createdAt: now
      },
      {
        id: "client_1",
        role: "client",
        name: "Deneme Danışanı",
        email: "danisan@ornek.com",
        passwordHash: hashPassword("123456"),
        createdAt: now
      }
    ],
    clients: [
      {
        id: "client_1",
        userId: "client_1",
        name: "Deneme Danışanı",
        email: "danisan@ornek.com",
        phone: "0555 111 22 33",
        gender: "Kadın",
        age: "31",
        blood: "A Rh+",
        allergies: "Laktoz",
        goal: "Kilo verme ve gece atıştırmasını azaltma",
        membership: "trial",
        status: "pending",
        registeredAt: now.slice(0, 10),
        planNote: "Deneme süreci isteği panelde bekliyor.",
        weeklyPlans: [],
        weightHistory: [
          { month: "2026-03", kg: 60, note: "Ofis ölçümü" },
          { month: "2026-04", kg: 55, note: "Ofis ölçümü sonrası güncellendi" }
        ]
      }
    ]
  };
}

function ensureDb() {
  if (!fs.existsSync(path.dirname(DB_FILE))) fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
  if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify(seedDb(), null, 2), "utf8");
}

function readDb() {
  ensureDb();
  return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}

function writeDb(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), "utf8");
}

function send(res, status, body, headers = {}) {
  const payload = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": typeof body === "string" ? "text/plain; charset=utf-8" : "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...headers
  });
  res.end(payload);
}

function sendJson(res, status, body) {
  send(res, status, body, { "Content-Type": "application/json; charset=utf-8" });
}

function parseCookies(req) {
  return Object.fromEntries((req.headers.cookie || "").split(";").filter(Boolean).map(part => {
    const [key, ...rest] = part.trim().split("=");
    return [key, decodeURIComponent(rest.join("="))];
  }));
}

function getSession(req) {
  const token = parseCookies(req).session;
  if (!token) return null;
  const session = sessions.get(token);
  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(token);
    return null;
  }
  return session;
}

function createSession(res, user) {
  const token = `${uid("sess")}.${crypto.createHmac("sha256", SESSION_SECRET).update(user.id).digest("hex")}`;
  sessions.set(token, {
    userId: user.id,
    role: user.role,
    expiresAt: Date.now() + 1000 * 60 * 60 * 8
  });
  res.setHeader("Set-Cookie", `session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800`);
}

function clearSession(res) {
  res.setHeader("Set-Cookie", "session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
}

function requireRole(req, res, role) {
  const session = getSession(req);
  if (!session || session.role !== role) {
    sendJson(res, 401, { error: "Yetkisiz giriş." });
    return null;
  }
  return session;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", chunk => {
      data += chunk;
      if (data.length > 1_000_000) {
        reject(new Error("İstek çok büyük."));
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch {
        reject(new Error("Geçersiz JSON."));
      }
    });
  });
}

function publicClient(client) {
  return {
    id: client.id,
    name: client.name,
    email: client.email,
    phone: client.phone,
    gender: client.gender,
    age: client.age,
    blood: client.blood,
    allergies: client.allergies,
    goal: client.goal,
    membership: client.membership,
    status: client.status,
    registeredAt: client.registeredAt,
    planNote: client.planNote,
    weeklyPlans: client.weeklyPlans || [],
    weightHistory: client.weightHistory || []
  };
}

function validateRequired(body, fields) {
  const missing = fields.filter(field => !String(body[field] || "").trim());
  return missing.length ? `${missing.join(", ")} alanları zorunlu.` : null;
}

async function handleApi(req, res, url) {
  const db = readDb();

  if (req.method === "POST" && url.pathname === "/api/auth/admin-login") {
    const body = await readBody(req);
    const user = db.users.find(item => item.role === "admin" && item.email.toLowerCase() === String(body.email || "").toLowerCase());
    if (!user || !verifyPassword(body.password, user.passwordHash)) return sendJson(res, 401, { error: "E-posta veya şifre hatalı." });
    createSession(res, user);
    return sendJson(res, 200, { ok: true, user: { name: user.name, email: user.email, role: user.role } });
  }

  if (req.method === "POST" && url.pathname === "/api/auth/client-login") {
    const body = await readBody(req);
    const user = db.users.find(item => item.role === "client" && item.email.toLowerCase() === String(body.email || "").toLowerCase());
    if (!user || !verifyPassword(body.password, user.passwordHash)) return sendJson(res, 401, { error: "E-posta veya şifre hatalı." });
    createSession(res, user);
    return sendJson(res, 200, { ok: true });
  }

  if (req.method === "POST" && url.pathname === "/api/auth/logout") {
    clearSession(res);
    return sendJson(res, 200, { ok: true });
  }

  if (req.method === "POST" && url.pathname === "/api/trial-register") {
    const body = await readBody(req);
    const error = validateRequired(body, ["name", "surname", "email", "password", "phone", "gender", "age", "allergies", "goal"]);
    if (error) return sendJson(res, 400, { error });
    if (db.users.some(user => user.email.toLowerCase() === body.email.toLowerCase())) return sendJson(res, 409, { error: "Bu e-posta zaten kayıtlı." });

    const userId = uid("client");
    const name = `${body.name} ${body.surname}`.trim();
    db.users.push({
      id: userId,
      role: "client",
      name,
      email: body.email,
      passwordHash: hashPassword(body.password),
      createdAt: new Date().toISOString()
    });
    db.clients.unshift({
      id: uid("profile"),
      userId,
      name,
      email: body.email,
      phone: body.phone,
      gender: body.gender,
      age: body.age,
      blood: body.blood || "Belirtilmedi",
      allergies: body.allergies,
      goal: body.goal,
      membership: "trial",
      status: "pending",
      registeredAt: new Date().toISOString().slice(0, 10),
      planNote: "Deneme süreci isteğiniz Dr. Kutay paneline gönderildi.",
      weeklyPlans: [],
      weightHistory: []
    });
    writeDb(db);
    const user = db.users.find(item => item.id === userId);
    createSession(res, user);
    return sendJson(res, 201, { ok: true });
  }

  if (req.method === "GET" && url.pathname === "/api/client/me") {
    const session = requireRole(req, res, "client");
    if (!session) return;
    const client = db.clients.find(item => item.userId === session.userId);
    return sendJson(res, 200, { client: client ? publicClient(client) : null });
  }

  if (url.pathname.startsWith("/api/admin")) {
    const session = requireRole(req, res, "admin");
    if (!session) return;

    if (req.method === "GET" && url.pathname === "/api/admin/summary") {
      return sendJson(res, 200, {
        pending: db.clients.filter(client => client.membership === "trial" && client.status === "pending").length,
        normal: db.clients.filter(client => client.membership === "normal").length,
        planned: db.clients.filter(client => client.weeklyPlans?.length).length,
        weights: db.clients.reduce((total, client) => total + (client.weightHistory?.length || 0), 0)
      });
    }

    if (req.method === "GET" && url.pathname === "/api/admin/clients") {
      return sendJson(res, 200, { clients: db.clients.map(publicClient) });
    }

    if (req.method === "POST" && url.pathname === "/api/admin/clients") {
      const body = await readBody(req);
      const error = validateRequired(body, ["name", "email", "password", "phone", "gender", "age", "allergies", "goal"]);
      if (error) return sendJson(res, 400, { error });
      if (db.users.some(user => user.email.toLowerCase() === body.email.toLowerCase())) return sendJson(res, 409, { error: "Bu e-posta zaten kayıtlı." });
      const userId = uid("client");
      db.users.push({ id: userId, role: "client", name: body.name, email: body.email, passwordHash: hashPassword(body.password), createdAt: new Date().toISOString() });
      db.clients.unshift({
        id: uid("profile"),
        userId,
        name: body.name,
        email: body.email,
        phone: body.phone,
        gender: body.gender,
        age: body.age,
        blood: body.blood || "Belirtilmedi",
        allergies: body.allergies,
        goal: body.goal,
        membership: body.membership || "normal",
        status: body.membership === "trial" ? "active" : "continued",
        registeredAt: new Date().toISOString().slice(0, 10),
        planNote: "Plan hazırlık aşamasında.",
        weeklyPlans: [],
        weightHistory: []
      });
      writeDb(db);
      return sendJson(res, 201, { ok: true });
    }

    const deleteClientMatch = url.pathname.match(/^\/api\/admin\/clients\/([^/]+)$/);
    if (req.method === "DELETE" && deleteClientMatch) {
      const clientIndex = db.clients.findIndex(item => item.id === deleteClientMatch[1]);
      if (clientIndex === -1) return sendJson(res, 404, { error: "Danışan bulunamadı." });
      const [client] = db.clients.splice(clientIndex, 1);
      db.users = db.users.filter(user => user.id !== client.userId);
      for (const [token, session] of sessions.entries()) {
        if (session.userId === client.userId) sessions.delete(token);
      }
      writeDb(db);
      return sendJson(res, 200, { ok: true });
    }

    const acceptMatch = url.pathname.match(/^\/api\/admin\/clients\/([^/]+)\/accept$/);
    if (req.method === "POST" && acceptMatch) {
      const client = db.clients.find(item => item.id === acceptMatch[1]);
      if (!client) return sendJson(res, 404, { error: "Danışan bulunamadı." });
      client.status = "active";
      client.membership = "trial";
      writeDb(db);
      return sendJson(res, 200, { ok: true });
    }

    const statusMatch = url.pathname.match(/^\/api\/admin\/clients\/([^/]+)\/status$/);
    if (req.method === "PATCH" && statusMatch) {
      const body = await readBody(req);
      const client = db.clients.find(item => item.id === statusMatch[1]);
      if (!client) return sendJson(res, 404, { error: "Danışan bulunamadı." });
      client.status = body.status;
      if (body.status === "continued") client.membership = "normal";
      writeDb(db);
      return sendJson(res, 200, { ok: true });
    }

    const planMatch = url.pathname.match(/^\/api\/admin\/clients\/([^/]+)\/plans$/);
    if (req.method === "POST" && planMatch) {
      const body = await readBody(req);
      const client = db.clients.find(item => item.id === planMatch[1]);
      if (!client) return sendJson(res, 404, { error: "Danışan bulunamadı." });
      const weekNumber = Number(body.weekNumber || 1);
      client.weeklyPlans = client.weeklyPlans || [];
      client.weeklyPlans[weekNumber - 1] = { summary: body.summary || `${weekNumber}. hafta planı`, days: body.days || {}, savedAt: new Date().toISOString() };
      client.planNote = body.summary || client.planNote;
      writeDb(db);
      return sendJson(res, 200, { ok: true });
    }

    const weightMatch = url.pathname.match(/^\/api\/admin\/clients\/([^/]+)\/weights$/);
    if (req.method === "POST" && weightMatch) {
      const body = await readBody(req);
      const client = db.clients.find(item => item.id === weightMatch[1]);
      if (!client) return sendJson(res, 404, { error: "Danışan bulunamadı." });
      client.weightHistory = client.weightHistory || [];
      client.weightHistory.push({ month: body.month, kg: Number(body.kg), note: "Ofis randevusu sonrası diyetisyen tarafından güncellendi" });
      writeDb(db);
      return sendJson(res, 200, { ok: true });
    }
  }

  return sendJson(res, 404, { error: "API bulunamadı." });
}

function contentType(file) {
  const ext = path.extname(file).toLowerCase();
  return {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp"
  }[ext] || "application/octet-stream";
}

function serveStatic(req, res, url) {
  let pathname = decodeURIComponent(url.pathname);
  if (pathname === "/") pathname = "/index.html";
  if (pathname === "/adminpanel" || pathname === "/adminpanel/") pathname = "/adminpanel/index.html";
  const file = path.normalize(path.join(PUBLIC_DIR, pathname));
  if (!file.startsWith(PUBLIC_DIR)) return send(res, 403, "Erişim reddedildi.");
  fs.readFile(file, (err, data) => {
    if (err) return send(res, 404, "Sayfa bulunamadı.");
    res.writeHead(200, { "Content-Type": contentType(file) });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  try {
    if (url.pathname.startsWith("/api/")) return await handleApi(req, res, url);
    serveStatic(req, res, url);
  } catch (error) {
    sendJson(res, 500, { error: error.message || "Sunucu hatası." });
  }
});

ensureDb();
server.listen(PORT, () => {
  console.log(`Diyetisyen takip backend çalışıyor: http://localhost:${PORT}`);
  console.log(`Admin panel: http://localhost:${PORT}/adminpanel`);
});
