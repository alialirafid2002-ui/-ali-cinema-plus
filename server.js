const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");

const app = express();
const db = new Database("cinema.sqlite");
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "change-me-now";
const SITE_NAME = process.env.SITE_NAME || "ALI CINEMA PLUS";
const PAYMENT_INSTRUCTIONS = process.env.PAYMENT_INSTRUCTIONS || "أرسل إثبات الدفع إلى الإدارة.";
if (!process.env.SESSION_SECRET) console.warn("تحذير: عيّن SESSION_SECRET قبل النشر.");

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || "development-only-secret",
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 7*24*60*60*1000 }
}));
app.use(express.static(path.join(__dirname, "public")));

db.exec(`
CREATE TABLE IF NOT EXISTS codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code_hash TEXT UNIQUE NOT NULL,
  label TEXT,
  expires_at TEXT,
  redeemed_by TEXT,
  redeemed_at TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  contact TEXT NOT NULL,
  note TEXT,
  status TEXT DEFAULT 'pending',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS videos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  description TEXT DEFAULT '',
  video_url TEXT NOT NULL,
  poster_url TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

const hash = s => crypto.createHash("sha256").update(s).digest("hex");
const makeCode = () => crypto.randomBytes(6).toString("hex").toUpperCase();
const requireAdmin = (req,res,next) => req.session.admin ? next() : res.status(401).json({error:"يلزم تسجيل دخول الإدارة"});
const requireMember = (req,res,next) => req.session.member ? next() : res.status(401).json({error:"أدخل كود اشتراك صالحاً أولاً"});

app.get("/api/config", (req,res) => res.json({siteName:SITE_NAME, paymentInstructions:PAYMENT_INSTRUCTIONS}));
app.get("/api/session", (req,res) => res.json({member:!!req.session.member, admin:!!req.session.admin}));

app.post("/api/redeem", (req,res) => {
  const code = String(req.body.code || "").trim().toUpperCase();
  if (!/^[A-F0-9]{12}$/.test(code)) return res.status(400).json({error:"صيغة الكود غير صحيحة."});
  const row = db.prepare("SELECT * FROM codes WHERE code_hash=?").get(hash(code));
  if (!row) return res.status(400).json({error:"الكود غير صحيح."});
  if (row.redeemed_by) return res.status(400).json({error:"هذا الكود مستخدم مسبقاً."});
  if (row.expires_at && new Date(row.expires_at) < new Date()) return res.status(400).json({error:"انتهت صلاحية هذا الكود."});
  const memberId = crypto.randomUUID();
  db.prepare("UPDATE codes SET redeemed_by=?, redeemed_at=CURRENT_TIMESTAMP WHERE id=?").run(memberId,row.id);
  req.session.member = memberId;
  res.json({ok:true});
});

app.post("/api/logout", (req,res) => { req.session.destroy(()=>res.json({ok:true})); });
app.post("/api/subscribe", (req,res) => {
  const name = String(req.body.name||"").trim().slice(0,80);
  const contact = String(req.body.contact||"").trim().slice(0,100);
  const note = String(req.body.note||"").trim().slice(0,300);
  if (!name || !contact) return res.status(400).json({error:"اكتب الاسم ورقم التواصل."});
  db.prepare("INSERT INTO requests(name,contact,note) VALUES(?,?,?)").run(name,contact,note);
  res.json({ok:true,message:"وصل طلبك. بعد مراجعة الدفع ستصلك رسالة بكودك الخاص."});
});

app.get("/api/videos", requireMember, (req,res) => {
  res.json(db.prepare("SELECT id,title,category,description,video_url,poster_url FROM videos ORDER BY id DESC").all());
});

app.post("/api/admin/login", (req,res) => {
  if (String(req.body.password||"") !== ADMIN_PASSWORD) return res.status(401).json({error:"كلمة المرور غير صحيحة."});
  req.session.admin = true; res.json({ok:true});
});
app.post("/api/admin/logout", requireAdmin, (req,res) => { req.session.admin=false; res.json({ok:true}); });
app.get("/api/admin/requests", requireAdmin, (req,res) => res.json(db.prepare("SELECT * FROM requests ORDER BY id DESC").all()));
app.post("/api/admin/requests/:id/approve", requireAdmin, (req,res) => {
  const item = db.prepare("SELECT * FROM requests WHERE id=? AND status='pending'").get(req.params.id);
  if (!item) return res.status(404).json({error:"الطلب غير موجود أو تمت معالجته."});
  const code = makeCode();
  const days = Math.max(1, Math.min(3650, Number(req.body.days)||30));
  const expires = new Date(Date.now()+days*86400000).toISOString();
  db.prepare("INSERT INTO codes(code_hash,label,expires_at) VALUES(?,?,?)").run(hash(code), item.name, expires);
  db.prepare("UPDATE requests SET status='approved' WHERE id=?").run(item.id);
  res.json({code,expiresAt:expires,contact:item.contact});
});
app.get("/api/admin/codes", requireAdmin, (req,res) => {
  res.json(db.prepare("SELECT id,label,expires_at,redeemed_at,created_at FROM codes ORDER BY id DESC LIMIT 100").all());
});
app.post("/api/admin/codes", requireAdmin, (req,res) => {
  const code = makeCode();
  const days = Math.max(1, Math.min(3650, Number(req.body.days)||30));
  const expires = new Date(Date.now()+days*86400000).toISOString();
  db.prepare("INSERT INTO codes(code_hash,label,expires_at) VALUES(?,?,?)").run(hash(code), "كود إداري", expires);
  res.json({code,expiresAt:expires});
});
app.post("/api/admin/videos", requireAdmin, (req,res) => {
  const title=String(req.body.title||"").trim().slice(0,120);
  const category=String(req.body.category||"").trim().slice(0,60);
  const videoUrl=String(req.body.video_url||"").trim();
  const posterUrl=String(req.body.poster_url||"").trim();
  const description=String(req.body.description||"").trim().slice(0,500);
  if (!title||!category||!/^https:\/\/.+/i.test(videoUrl)) return res.status(400).json({error:"أدخل العنوان والتصنيف ورابط فيديو HTTPS صالحاً."});
  if (posterUrl && !/^https:\/\/.+/i.test(posterUrl)) return res.status(400).json({error:"رابط الصورة يجب أن يبدأ بـ HTTPS."});
  db.prepare("INSERT INTO videos(title,category,description,video_url,poster_url) VALUES(?,?,?,?,?)").run(title,category,description,videoUrl,posterUrl);
  res.json({ok:true});
});
app.delete("/api/admin/videos/:id", requireAdmin, (req,res) => {
  db.prepare("DELETE FROM videos WHERE id=?").run(req.params.id); res.json({ok:true});
});

app.listen(PORT, () => console.log(`${SITE_NAME} يعمل على http://localhost:${PORT}`));
