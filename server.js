import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

/* =========================
   SECURITY
========================= */

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("ERROR: JWT_SECRET is missing or too short.");
  process.exit(1);
}

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(cors());

app.use(
  express.json({
    limit: "20kb"
  })
);

app.use(express.urlencoded({ extended: false, limit: "20kb" }));

/* =========================
   DATABASE
========================= */

const db = new Database("djalil.db");

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'customer'
  );

  CREATE TABLE IF NOT EXISTS restaurants(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT,
    address TEXT,
    active INTEGER DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS products(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    restaurant_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    category TEXT,
    price INTEGER NOT NULL,
    emoji TEXT DEFAULT '🍽️',
    active INTEGER DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS orders(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    restaurant_id INTEGER,
    items TEXT NOT NULL,
    total INTEGER NOT NULL,
    delivery_fee INTEGER NOT NULL,
    address TEXT NOT NULL,
    phone TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'received',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

/* =========================
   SEED DATA
========================= */

const count = db
  .prepare("SELECT COUNT(*) AS c FROM restaurants")
  .get().c;

if (!count) {
  const r = db
    .prepare(
      "INSERT INTO restaurants(name,phone,address) VALUES(?,?,?)"
    )
    .run(
      "Djalil Food",
      "0550000000",
      "الجزائر"
    );

  const add = db.prepare(
    "INSERT INTO products(restaurant_id,name,category,price,emoji) VALUES(?,?,?,?,?)"
  );

  [
    ["Classic Burger", "برغر", 650, "🍔"],
    ["Double Cheese", "برغر", 850, "🍔"],
    ["Pizza Margherita", "بيتزا", 900, "🍕"],
    ["Crêpe Choko", "كريب", 550, "🥞"],
    ["Tacos Poulet", "تاكوس", 700, "🌯"],
    ["Chicken Box", "دجاج", 800, "🍗"]
  ].forEach((x) => {
    add.run(r.lastInsertRowid, ...x);
  });
}

/* =========================
   RATE LIMITERS
========================= */

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "محاولات كثيرة. حاول مرة أخرى بعد قليل."
  }
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "طلبات كثيرة. حاول مرة أخرى بعد قليل."
  }
});

app.use("/api", apiLimiter);

app.use("/api/register", authLimiter);
app.use("/api/login", authLimiter);

/* =========================
   HELPERS
========================= */

function cleanText(value, maxLength = 100) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}

function cleanPhone(value) {
  if (typeof value !== "string") return "";
  return value.replace(/[^\d+]/g, "").slice(0, 20);
}

function validPhone(phone) {
  return /^(\+213|0)(5|6|7)\d{8}$/.test(phone);
}

function validPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 8 &&
    password.length <= 100
  );
}

/* =========================
   AUTH MIDDLEWARE
========================= */

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "غير مصرح"
      });
    }

    const token = header.slice(7);

    if (!token) {
      return res.status(401).json({
        error: "غير مصرح"
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();
  } catch {
    return res.status(401).json({
      error: "جلسة الدخول غير صالحة أو منتهية"
    });
  }
}

function role(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: "صلاحيات غير كافية"
      });
    }

    next();
  };
}

/* =========================
   REGISTER
========================= */

app.post("/api/register", async (req, res) => {
  try {
    const name = cleanText(req.body?.name, 60);
    const phone = cleanPhone(req.body?.phone);
    const password = req.body?.password;

    if (!name || name.length < 2) {
      return res.status(400).json({
        error: "الاسم غير صالح"
      });
    }

    if (!validPhone(phone)) {
      return res.status(400).json({
        error: "رقم الهاتف غير صالح"
      });
    }

    if (!validPassword(password)) {
      return res.status(400).json({
        error: "كلمة السر يجب أن تكون 8 أحرف على الأقل"
      });
    }

    const existing = db
      .prepare("SELECT id FROM users WHERE phone=?")
      .get(phone);

    if (existing) {
      return res.status(409).json({
        error: "رقم الهاتف مسجل من قبل"
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = db
      .prepare(
        "INSERT INTO users(name,phone,password,role) VALUES(?,?,?,'customer')"
      )
      .run(name, phone, hash);

    const token = jwt.sign(
      {
        id: result.lastInsertRowid,
        name,
        phone,
        role: "customer"
      },
      JWT_SECRET,
      {
        expiresIn: "2d",
        issuer: "djalil-delivery"
      }
    );

    return res.status(201).json({
      token,
      user: {
        id: result.lastInsertRowid,
        name,
        phone,
        role: "customer"
      }
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error.message);

    return res.status(500).json({
      error: "حدث خطأ في إنشاء الحساب"
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/api/login", async (req, res) => {
  try {
    const phone = cleanPhone(req.body?.phone);
    const password = req.body?.password;

    if (!validPhone(phone) || typeof password !== "string") {
      return res.status(401).json({
        error: "رقم الهاتف أو كلمة السر خاطئة"
      });
    }

    const user = db
      .prepare("SELECT * FROM users WHERE phone=?")
      .get(phone);

    if (!user) {
      return res.status(401).json({
        error: "رقم الهاتف أو كلمة السر خاطئة"
      });
    }

    const passwordOK = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordOK) {
      return res.status(401).json({
        error: "رقم الهاتف أو كلمة السر خاطئة"
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        name: user.name,
        phone: user.phone,
        role: user.role
      },
      JWT_SECRET,
      {
        expiresIn: "2d",
        issuer: "djalil-delivery"
      }
    );

    return res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        phone: user.phone,
        role: user.role
      }
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error.message);

    return res.status(500).json({
      error: "حدث خطأ أثناء تسجيل الدخول"
    });
  }
});

/* =========================
   PRODUCTS
========================= */

app.get("/api/products", (req, res) => {
  const products = db
    .prepare(`
      SELECT
        p.*,
        r.name restaurant
      FROM products p
      JOIN restaurants r
        ON r.id = p.restaurant_id
      WHERE p.active=1
        AND r.active=1
    `)
    .all();

  res.json(products);
});

/* =========================
   RESTAURANTS
========================= */

app.get("/api/restaurants", (req, res) => {
  const restaurants = db
    .prepare(
      "SELECT * FROM restaurants WHERE active=1"
    )
    .all();

  res.json(restaurants);
});

/* =========================
   CREATE ORDER
========================= */

app.post("/api/orders", auth, (req, res) => {
  try {
    const items = req.body?.items;
    const address = cleanText(req.body?.address, 300);
    const phone = cleanPhone(req.body?.phone);

    if (
      !Array.isArray(items) ||
      !items.length ||
      items.length > 30 ||
      !address ||
      !validPhone(phone)
    ) {
      return res.status(400).json({
        error: "معلومات الطلب ناقصة أو غير صالحة"
      });
    }

    let total = 0;
    let restaurant = null;
    const clean = [];

    for (const item of items) {
      const id = Number(item?.id);

      if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({
          error: "منتج غير صالح"
        });
      }

      const product = db
        .prepare(
          "SELECT * FROM products WHERE id=? AND active=1"
        )
        .get(id);

      if (!product) {
        return res.status(400).json({
          error: "منتج غير موجود"
        });
      }

      if (restaurant === null) {
        restaurant = product.restaurant_id;
      }

      if (product.restaurant_id !== restaurant) {
        return res.status(400).json({
          error: "اختر منتجات من مطعم واحد"
        });
      }

      const quantity = Math.max(
        1,
        Math.min(20, Number(item?.q) || 1)
      );

      total += product.price * quantity;

      clean.push({
        id: product.id,
        name: product.name,
        price: product.price,
        q: quantity
      });
    }

    const deliveryFee = 300;
    const finalTotal = total + deliveryFee;

    const result = db
      .prepare(`
        INSERT INTO orders(
          user_id,
          restaurant_id,
          items,
          total,
          delivery_fee,
          address,
          phone
        )
        VALUES(?,?,?,?,?,?,?)
      `)
      .run(
        req.user.id,
        restaurant,
        JSON.stringify(clean),
        finalTotal,
        deliveryFee,
        address,
        phone
      );

    return res.status(201).json({
      id: result.lastInsertRowid,
      total: finalTotal,
      status: "received"
    });
  } catch (error) {
    console.error("ORDER ERROR:", error.message);

    return res.status(500).json({
      error: "حدث خطأ أثناء إنشاء الطلب"
    });
  }
});

/* =========================
   MY ORDERS / ADMIN ORDERS
========================= */

app.get("/api/orders", auth, (req, res) => {
  const orders =
    req.user.role === "admin" ||
    req.user.role === "driver"
      ? db
          .prepare(`
            SELECT
              o.*,
              u.name customer
            FROM orders o
            JOIN users u
              ON u.id = o.user_id
            ORDER BY o.id DESC
          `)
          .all()
      : db
          .prepare(`
            SELECT *
            FROM orders
            WHERE user_id=?
            ORDER BY id DESC
          `)
          .all(req.user.id);

  res.json(
    orders.map((order) => ({
      ...order,
      items: JSON.parse(order.items)
    }))
  );
});

/* =========================
   UPDATE ORDER STATUS
========================= */

app.patch(
  "/api/orders/:id/status",
  auth,
  role("admin", "driver"),
  (req, res) => {
    const allowed = [
      "received",
      "preparing",
      "pickup",
      "on_the_way",
      "delivered",
      "cancelled"
    ];

    const status = cleanText(req.body?.status, 30);
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        error: "رقم الطلب غير صالح"
      });
    }

    if (!allowed.includes(status)) {
      return res.status(400).json({
        error: "حالة غير صالحة"
      });
    }

    const result = db
      .prepare(
        "UPDATE orders SET status=? WHERE id=?"
      )
      .run(status, id);

    res.json({
      ok: !!result.changes
    });
  }
);

/* =========================
   ADMIN STATS
========================= */

app.get(
  "/api/admin/stats",
  auth,
  role("admin"),
  (req, res) => {
    res.json({
      orders: db
        .prepare("SELECT COUNT(*) c FROM orders")
        .get().c,

      revenue: db
        .prepare(
          "SELECT COALESCE(SUM(total),0) s FROM orders WHERE status='delivered'"
        )
        .get().s,

      customers: db
        .prepare(
          "SELECT COUNT(*) c FROM users WHERE role='customer'"
        )
        .get().c,

      restaurants: db
        .prepare(
          "SELECT COUNT(*) c FROM restaurants"
        )
        .get().c
    });
  }
);

/* =========================
   FRONTEND
========================= */

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

app.get("*", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});

/* =========================
   START SERVER
========================= */

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(
    `Djalil Delivery running on port ${PORT}`
  );
});
