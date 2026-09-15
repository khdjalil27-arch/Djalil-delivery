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

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("ERROR: JWT_SECRET is missing or too short.");
  process.exit(1);
}

/* =========================
   SECURITY
========================= */

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

app.use(
  express.urlencoded({
    extended: false,
    limit: "20kb"
  })
);

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 200,
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "محاولات كثيرة. حاول مرة أخرى بعد قليل."
  }
});

app.use("/api", apiLimiter);

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
   HELPERS
========================= */

function cleanText(value, max = 200) {
  return String(value ?? "")
    .trim()
    .replace(/\s+/g, " ")
    .slice(0, max);
}

function cleanPhone(value) {
  return String(value ?? "")
    .trim()
    .replace(/\s+/g, "");
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

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      role: user.role,
      phone: user.phone
    },
    JWT_SECRET,
    {
      expiresIn: "2d",
      issuer: "djalil-delivery"
    }
  );
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "غير مسجل الدخول."
      });
    }

    const token = header.slice(7);

    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: "djalil-delivery"
    });

    const user = db
      .prepare(
        "SELECT id,name,phone,role FROM users WHERE id=?"
      )
      .get(decoded.id);

    if (!user) {
      return res.status(401).json({
        error: "المستخدم غير موجود."
      });
    }

    req.user = user;
    next();
  } catch {
    return res.status(401).json({
      error: "جلسة الدخول غير صالحة."
    });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({
      error: "غير مصرح."
    });
  }

  next();
}

function staffOnly(req, res, next) {
  if (
    !req.user ||
    !["admin", "driver"].includes(req.user.role)
  ) {
    return res.status(403).json({
      error: "غير مصرح."
    });
  }

  next();
}

/* =========================
   SEED
========================= */

const restaurantCount = db
  .prepare("SELECT COUNT(*) AS c FROM restaurants")
  .get().c;

if (!restaurantCount) {
  const restaurant = db
    .prepare(
      `
      INSERT INTO restaurants(
        name,
        phone,
        address
      )
      VALUES(?,?,?)
      `
    )
    .run(
      "Djalil Food",
      "0550000000",
      "الجزائر"
    );

  const addProduct = db.prepare(`
    INSERT INTO products(
      restaurant_id,
      name,
      category,
      price,
      emoji
    )
    VALUES(?,?,?,?,?)
  `);

  const products = [
    ["Classic Burger", "برغر", 650, "🍔"],
    ["Double Cheese", "برغر", 850, "🍔"],
    ["Pizza Margherita", "بيتزا", 900, "🍕"],
    ["Crêpe Choko", "كريب", 550, "🥞"],
    ["Tacos Poulet", "تاكوس", 700, "🌯"],
    ["Chicken Box", "دجاج", 800, "🍗"]
  ];

  for (const product of products) {
    addProduct.run(
      restaurant.lastInsertRowid,
      ...product
    );
  }
}

/* =========================
   ADMIN AUTO SETUP
========================= */

async function setupAdmin() {
  const name = cleanText(
    process.env.ADMIN_NAME || "",
    60
  );

  const phone = cleanPhone(
    process.env.ADMIN_PHONE || ""
  );

  const password =
    process.env.ADMIN_PASSWORD || "";

  if (
    !name ||
    !validPhone(phone) ||
    !validPassword(password)
  ) {
    console.log(
      "ADMIN ENV not configured. Skipping admin setup."
    );
    return;
  }

  const existing = db
    .prepare(
      "SELECT id, role FROM users WHERE phone=?"
    )
    .get(phone);

  if (existing) {
    if (existing.role !== "admin") {
      db.prepare(
        "UPDATE users SET role='admin' WHERE id=?"
      ).run(existing.id);

      console.log(
        "Existing user promoted to admin."
      );
    } else {
      console.log(
        "Admin account already exists."
      );
    }

    return;
  }

  const hash = await bcrypt.hash(password, 12);

  db.prepare(`
    INSERT INTO users(
      name,
      phone,
      password,
      role
    )
    VALUES(?,?,?,'admin')
  `).run(
    name,
    phone,
    hash
  );

  console.log(
    "Admin account created successfully."
  );
}

/* =========================
   AUTH
========================= */

app.post(
  "/api/register",
  authLimiter,
  async (req, res) => {
    try {
      const name = cleanText(req.body.name, 60);
      const phone = cleanPhone(req.body.phone);
      const password = req.body.password;

      if (!name) {
        return res.status(400).json({
          error: "الاسم مطلوب."
        });
      }

      if (!validPhone(phone)) {
        return res.status(400).json({
          error: "رقم الهاتف غير صالح."
        });
      }

      if (!validPassword(password)) {
        return res.status(400).json({
          error: "كلمة السر يجب أن تكون 8 أحرف على الأقل."
        });
      }

      const exists = db
        .prepare(
          "SELECT id FROM users WHERE phone=?"
        )
        .get(phone);

      if (exists) {
        return res.status(409).json({
          error: "رقم الهاتف مسجل من قبل."
        });
      }

      const hash = await bcrypt.hash(
        password,
        12
      );

      const result = db
        .prepare(
          `
          INSERT INTO users(
            name,
            phone,
            password,
            role
          )
          VALUES(?,?,?,'customer')
          `
        )
        .run(
          name,
          phone,
          hash
        );

      const user = db
        .prepare(
          "SELECT id,name,phone,role FROM users WHERE id=?"
        )
        .get(result.lastInsertRowid);

      const token = createToken(user);

      res.status(201).json({
        message: "تم إنشاء الحساب بنجاح.",
        token,
        user
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "حدث خطأ في إنشاء الحساب."
      });
    }
  }
);

app.post(
  "/api/login",
  authLimiter,
  async (req, res) => {
    try {
      const phone = cleanPhone(req.body.phone);
      const password = req.body.password;

      if (!validPhone(phone)) {
        return res.status(400).json({
          error: "رقم الهاتف غير صالح."
        });
      }

      if (!validPassword(password)) {
        return res.status(400).json({
          error: "كلمة السر غير صالحة."
        });
      }

      const user = db
        .prepare(
          "SELECT * FROM users WHERE phone=?"
        )
        .get(phone);

      if (!user) {
        return res.status(401).json({
          error: "رقم الهاتف أو كلمة السر خاطئة."
        });
      }

      const match = await bcrypt.compare(
        password,
        user.password
      );

      if (!match) {
        return res.status(401).json({
          error: "رقم الهاتف أو كلمة السر خاطئة."
        });
      }

      const safeUser = {
        id: user.id,
        name: user.name,
        phone: user.phone,
        role: user.role
      };

      const token = createToken(safeUser);

      res.json({
        message: "تم تسجيل الدخول.",
        token,
        user: safeUser
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "حدث خطأ في تسجيل الدخول."
      });
    }
  }
);

app.get(
  "/api/me",
  auth,
  (req, res) => {
    res.json({
      user: req.user
    });
  }
);

/* =========================
   RESTAURANTS
========================= */

app.get(
  "/api/restaurants",
  (req, res) => {
    const restaurants = db
      .prepare(
        `
        SELECT id,name,phone,address,active
        FROM restaurants
        WHERE active=1
        ORDER BY id DESC
        `
      )
      .all();

    res.json(restaurants);
  }
);

/* =========================
   PRODUCTS
========================= */

app.get(
  "/api/products",
  (req, res) => {
    const products = db
      .prepare(
        `
        SELECT
          p.id,
          p.restaurant_id,
          p.name,
          p.category,
          p.price,
          p.emoji,
          p.active,
          r.name AS restaurant
        FROM products p
        JOIN restaurants r
          ON r.id=p.restaurant_id
        WHERE p.active=1
          AND r.active=1
        ORDER BY p.id ASC
        `
      )
      .all();

    res.json(products);
  }
);

/* =========================
   ORDERS
========================= */

app.post(
  "/api/orders",
  auth,
  (req, res) => {
    try {
      const items = req.body.items;
      const address = cleanText(
        req.body.address,
        300
      );
      const phone = cleanPhone(
        req.body.phone || req.user.phone
      );

      if (!Array.isArray(items) || items.length === 0) {
        return res.status(400).json({
          error: "السلة فارغة."
        });
      }

      if (!address) {
        return res.status(400).json({
          error: "العنوان مطلوب."
        });
      }

      if (!validPhone(phone)) {
        return res.status(400).json({
          error: "رقم الهاتف غير صالح."
        });
      }

      if (items.length > 50) {
        return res.status(400).json({
          error: "عدد المنتجات كبير."
        });
      }

      const ids = items.map((item) =>
        Number(item.product_id || item.id)
      );

      if (ids.some((id) => !Number.isInteger(id) || id <= 0)) {
        return res.status(400).json({
          error: "منتج غير صالح."
        });
      }

      const uniqueIds = [...new Set(ids)];

      const placeholders = uniqueIds
        .map(() => "?")
        .join(",");

      const products = db
        .prepare(
          `
          SELECT *
          FROM products
          WHERE id IN (${placeholders})
            AND active=1
          `
        )
        .all(...uniqueIds);

      if (products.length !== uniqueIds.length) {
        return res.status(400).json({
          error: "يوجد منتج غير متوفر."
        });
      }

      const restaurantId =
        products[0].restaurant_id;

      if (
        products.some(
          (product) =>
            product.restaurant_id !== restaurantId
        )
      ) {
        return res.status(400).json({
          error:
            "لا يمكن الطلب من أكثر من مطعم في نفس الطلب."
        });
      }

      const productMap = new Map(
        products.map((product) => [
          product.id,
          product
        ])
      );

      const finalItems = [];
      let subtotal = 0;

      for (const item of items) {
        const productId = Number(
          item.product_id || item.id
        );

        const quantity = Number(
          item.quantity || 1
        );

        if (
          !Number.isInteger(quantity) ||
          quantity < 1 ||
          quantity > 20
        ) {
          return res.status(400).json({
            error: "كمية غير صالحة."
          });
        }

        const product =
          productMap.get(productId);

        if (!product) {
          return res.status(400).json({
            error: "منتج غير موجود."
          });
        }

        const lineTotal =
          product.price * quantity;

        subtotal += lineTotal;

        finalItems.push({
          product_id: product.id,
          name: product.name,
          price: product.price,
          quantity,
          emoji: product.emoji
        });
      }

      const deliveryFee = 300;
      const total = subtotal + deliveryFee;

      const result = db
        .prepare(
          `
          INSERT INTO orders(
            user_id,
            restaurant_id,
            items,
            total,
            delivery_fee,
            address,
            phone,
            status
          )
          VALUES(?,?,?,?,?,?,?,'received')
          `
        )
        .run(
          req.user.id,
          restaurantId,
          JSON.stringify(finalItems),
          total,
          deliveryFee,
          address,
          phone
        );

      res.status(201).json({
        message: "تم إرسال الطلب بنجاح.",
        order: {
          id: result.lastInsertRowid,
          subtotal,
          delivery_fee: deliveryFee,
          total,
          status: "received"
        }
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "حدث خطأ أثناء إنشاء الطلب."
      });
    }
  }
);

app.get(
  "/api/orders",
  auth,
  (req, res) => {
    let orders;

    if (
      req.user.role === "admin" ||
      req.user.role === "driver"
    ) {
      orders = db
        .prepare(
          `
          SELECT
            o.*,
            u.name AS customer_name,
            u.phone AS customer_phone,
            r.name AS restaurant
          FROM orders o
          JOIN users u
            ON u.id=o.user_id
          LEFT JOIN restaurants r
            ON r.id=o.restaurant_id
          ORDER BY o.id DESC
          `
        )
        .all();
    } else {
      orders = db
        .prepare(
          `
          SELECT
            o.*,
            r.name AS restaurant
          FROM orders o
          LEFT JOIN restaurants r
            ON r.id=o.restaurant_id
          WHERE o.user_id=?
          ORDER BY o.id DESC
          `
        )
        .all(req.user.id);
    }

    const result = orders.map((order) => ({
      ...order,
      items: JSON.parse(order.items)
    }));

    res.json(result);
  }
);

/* =========================
   ORDER STATUS
========================= */

const allowedStatuses = [
  "received",
  "preparing",
  "pickup",
  "on_the_way",
  "delivered",
  "cancelled"
];

app.patch(
  "/api/orders/:id/status",
  auth,
  staffOnly,
  (req, res) => {
    const id = Number(req.params.id);
    const status = cleanText(
      req.body.status,
      30
    );

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        error: "رقم الطلب غير صالح."
      });
    }

    if (!allowedStatuses.includes(status)) {
      return res.status(400).json({
        error: "حالة الطلب غير صالحة."
      });
    }

    const result = db
      .prepare(
        "UPDATE orders SET status=? WHERE id=?"
      )
      .run(status, id);

    if (!result.changes) {
      return res.status(404).json({
        error: "الطلب غير موجود."
      });
    }

    res.json({
      message: "تم تحديث حالة الطلب.",
      status
    });
  }
);

/* =========================
   ADMIN STATS
========================= */

app.get(
  "/api/admin/stats",
  auth,
  adminOnly,
  (req, res) => {
    const orders = db
      .prepare(
        "SELECT COUNT(*) AS c FROM orders"
      )
      .get().c;

    const deliveredRevenue = db
      .prepare(
        `
        SELECT COALESCE(SUM(total),0) AS total
        FROM orders
        WHERE status='delivered'
        `
      )
      .get().total;

    const customers = db
      .prepare(
        `
        SELECT COUNT(*) AS c
        FROM users
        WHERE role='customer'
        `
      )
      .get().c;

    const drivers = db
      .prepare(
        `
        SELECT COUNT(*) AS c
        FROM users
        WHERE role='driver'
        `
      )
      .get().c;

    const restaurants = db
      .prepare(
        `
        SELECT COUNT(*) AS c
        FROM restaurants
        WHERE active=1
        `
      )
      .get().c;

    const pending = db
      .prepare(
        `
        SELECT COUNT(*) AS c
        FROM orders
        WHERE status IN(
          'received',
          'preparing',
          'pickup',
          'on_the_way'
        )
        `
      )
      .get().c;

    res.json({
      orders,
      deliveredRevenue,
      customers,
      drivers,
      restaurants,
      pending
    });
  }
);

/* =========================
   ADMIN ORDERS
========================= */

app.get(
  "/api/admin/orders",
  auth,
  adminOnly,
  (req, res) => {
    const orders = db
      .prepare(
        `
        SELECT
          o.*,
          u.name AS customer_name,
          u.phone AS customer_phone,
          r.name AS restaurant
        FROM orders o
        JOIN users u
          ON u.id=o.user_id
        LEFT JOIN restaurants r
          ON r.id=o.restaurant_id
        ORDER BY o.id DESC
        `
      )
      .all();

    res.json(
      orders.map((order) => ({
        ...order,
        items: JSON.parse(order.items)
      }))
    );
  }
);

/* =========================
   ADMIN USERS
========================= */

app.get(
  "/api/admin/users",
  auth,
  adminOnly,
  (req, res) => {
    const users = db
      .prepare(
        `
        SELECT
          id,
          name,
          phone,
          role
        FROM users
        ORDER BY id DESC
        `
      )
      .all();

    res.json(users);
  }
);

app.patch(
  "/api/admin/users/:id/role",
  auth,
  adminOnly,
  (req, res) => {
    const id = Number(req.params.id);
    const role = cleanText(
      req.body.role,
      20
    );

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        error: "معرف المستخدم غير صالح."
      });
    }

    if (
      !["customer", "driver", "admin"].includes(role)
    ) {
      return res.status(400).json({
        error: "الدور غير صالح."
      });
    }

    if (id === req.user.id) {
      return res.status(400).json({
        error:
          "لا يمكنك تغيير دور حسابك الحالي."
      });
    }

    const result = db
      .prepare(
        "UPDATE users SET role=? WHERE id=?"
      )
      .run(role, id);

    if (!result.changes) {
      return res.status(404).json({
        error: "المستخدم غير موجود."
      });
    }

    res.json({
      message: "تم تحديث دور المستخدم."
    });
  }
);

/* =========================
   ADMIN PRODUCTS
========================= */

app.get(
  "/api/admin/products",
  auth,
  adminOnly,
  (req, res) => {
    const products = db
      .prepare(
        `
        SELECT
          p.*,
          r.name AS restaurant
        FROM products p
        JOIN restaurants r
          ON r.id=p.restaurant_id
        ORDER BY p.id DESC
        `
      )
      .all();

    res.json(products);
  }
);

app.post(
  "/api/admin/products",
  auth,
  adminOnly,
  (req, res) => {
    const name = cleanText(
      req.body.name,
      100
    );

    const category = cleanText(
      req.body.category,
      60
    );

    const price = Number(req.body.price);
    const emoji = cleanText(
      req.body.emoji || "🍽️",
      10
    );

    const restaurantId = Number(
      req.body.restaurant_id || 1
    );

    if (!name) {
      return res.status(400).json({
        error: "اسم المنتج مطلوب."
      });
    }

    if (
      !Number.isInteger(price) ||
      price <= 0 ||
      price > 10000000
    ) {
      return res.status(400).json({
        error: "السعر غير صالح."
      });
    }

    const restaurant = db
      .prepare(
        "SELECT id FROM restaurants WHERE id=? AND active=1"
      )
      .get(restaurantId);

    if (!restaurant) {
      return res.status(400).json({
        error: "المطعم غير موجود."
      });
    }

    const result = db
      .prepare(
        `
        INSERT INTO products(
          restaurant_id,
          name,
          category,
          price,
          emoji
        )
        VALUES(?,?,?,?,?)
        `
      )
      .run(
        restaurantId,
        name,
        category,
        price,
        emoji
      );

    res.status(201).json({
      message: "تمت إضافة المنتج.",
      id: result.lastInsertRowid
    });
  }
);

app.patch(
  "/api/admin/products/:id",
  auth,
  adminOnly,
  (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        error: "معرف المنتج غير صالح."
      });
    }

    const existing = db
      .prepare(
        "SELECT * FROM products WHERE id=?"
      )
      .get(id);

    if (!existing) {
      return res.status(404).json({
        error: "المنتج غير موجود."
      });
    }

    const name =
      req.body.name !== undefined
        ? cleanText(req.body.name, 100)
        : existing.name;

    const category =
      req.body.category !== undefined
        ? cleanText(req.body.category, 60)
        : existing.category;

    const price =
      req.body.price !== undefined
        ? Number(req.body.price)
        : existing.price;

    const emoji =
      req.body.emoji !== undefined
        ? cleanText(req.body.emoji, 10)
        : existing.emoji;

    const active =
      req.body.active !== undefined
        ? Number(req.body.active) ? 1 : 0
        : existing.active;

    if (!name) {
      return res.status(400).json({
        error: "اسم المنتج مطلوب."
      });
    }

    if (
      !Number.isInteger(price) ||
      price <= 0
    ) {
      return res.status(400).json({
        error: "السعر غير صالح."
      });
    }

    db.prepare(
      `
      UPDATE products
      SET
        name=?,
        category=?,
        price=?,
        emoji=?,
        active=?
      WHERE id=?
      `
    ).run(
      name,
      category,
      price,
      emoji,
      active,
      id
    );

    res.json({
      message: "تم تحديث المنتج."
    });
  }
);

app.delete(
  "/api/admin/products/:id",
  auth,
  adminOnly,
  (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        error: "معرف المنتج غير صالح."
      });
    }

    const result = db
      .prepare(
        "UPDATE products SET active=0 WHERE id=?"
      )
      .run(id);

    if (!result.changes) {
      return res.status(404).json({
        error: "المنتج غير موجود."
      });
    }

    res.json({
      message: "تم تعطيل المنتج."
    });
  }
);

/* =========================
   ADMIN RESTAURANTS
========================= */

app.get(
  "/api/admin/restaurants",
  auth,
  adminOnly,
  (req, res) => {
    const restaurants = db
      .prepare(
        `
        SELECT *
        FROM restaurants
        ORDER BY id DESC
        `
      )
      .all();

    res.json(restaurants);
  }
);

app.post(
  "/api/admin/restaurants",
  auth,
  adminOnly,
  (req, res) => {
    const name = cleanText(
      req.body.name,
      100
    );

    const phone = cleanPhone(
      req.body.phone || ""
    );

    const address = cleanText(
      req.body.address || "",
      300
    );

    if (!name) {
      return res.status(400).json({
        error: "اسم المطعم مطلوب."
      });
    }

    if (
      phone &&
      !validPhone(phone)
    ) {
      return res.status(400).json({
        error: "رقم الهاتف غير صالح."
      });
    }

    const result = db
      .prepare(
        `
        INSERT INTO restaurants(
          name,
          phone,
          address,
          active
        )
        VALUES(?,?,?,1)
        `
      )
      .run(
        name,
        phone,
        address
      );

    res.status(201).json({
      message: "تمت إضافة المطعم.",
      id: result.lastInsertRowid
    });
  }
);

app.patch(
  "/api/admin/restaurants/:id",
  auth,
  adminOnly,
  (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        error: "معرف المطعم غير صالح."
      });
    }

    const existing = db
      .prepare(
        "SELECT * FROM restaurants WHERE id=?"
      )
      .get(id);

    if (!existing) {
      return res.status(404).json({
        error: "المطعم غير موجود."
      });
    }

    const name =
      req.body.name !== undefined
        ? cleanText(req.body.name, 100)
        : existing.name;

    const phone =
      req.body.phone !== undefined
        ? cleanPhone(req.body.phone)
        : existing.phone;

    const address =
      req.body.address !== undefined
        ? cleanText(req.body.address, 300)
        : existing.address;

    const active =
      req.body.active !== undefined
        ? Number(req.body.active) ? 1 : 0
        : existing.active;

    if (!name) {
      return res.status(400).json({
        error: "اسم المطعم مطلوب."
      });
    }

    if (
      phone &&
      !validPhone(phone)
    ) {
      return res.status(400).json({
        error: "رقم الهاتف غير صالح."
      });
    }

    db.prepare(
      `
      UPDATE restaurants
      SET
        name=?,
        phone=?,
        address=?,
        active=?
      WHERE id=?
      `
    ).run(
      name,
      phone,
      address,
      active,
      id
    );

    res.json({
      message: "تم تحديث المطعم."
    });
  }
);

app.delete(
  "/api/admin/restaurants/:id",
  auth,
  adminOnly,
  (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        error: "معرف المطعم غير صالح."
      });
    }

    const activeProducts = db
      .prepare(
        `
        SELECT COUNT(*) AS c
        FROM products
        WHERE restaurant_id=?
          AND active=1
        `
      )
      .get(id).c;

    if (activeProducts > 0) {
      return res.status(400).json({
        error:
          "عطّل منتجات المطعم أولاً."
      });
    }

    const result = db
      .prepare(
        "UPDATE restaurants SET active=0 WHERE id=?"
      )
      .run(id);

    if (!result.changes) {
      return res.status(404).json({
        error: "المطعم غير موجود."
      });
    }

    res.json({
      message: "تم تعطيل المطعم."
    });
  }
);

/* =========================
   ADMIN DRIVERS
========================= */

app.post(
  "/api/admin/drivers",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const name = cleanText(
        req.body.name,
        60
      );

      const phone = cleanPhone(
        req.body.phone
      );

      const password =
        req.body.password;

      if (!name) {
        return res.status(400).json({
          error: "الاسم مطلوب."
        });
      }

      if (!validPhone(phone)) {
        return res.status(400).json({
          error: "رقم الهاتف غير صالح."
        });
      }

      if (!validPassword(password)) {
        return res.status(400).json({
          error:
            "كلمة السر يجب أن تكون 8 أحرف على الأقل."
        });
      }

      const exists = db
        .prepare(
          "SELECT id FROM users WHERE phone=?"
        )
        .get(phone);

      if (exists) {
        return res.status(409).json({
          error: "رقم الهاتف مسجل من قبل."
        });
      }

      const hash = await bcrypt.hash(
        password,
        12
      );

      const result = db
        .prepare(
          `
          INSERT INTO users(
            name,
            phone,
            password,
            role
          )
          VALUES(?,?,?,'driver')
          `
        )
        .run(
          name,
          phone,
          hash
        );

      res.status(201).json({
        message: "تم إنشاء حساب السائق.",
        id: result.lastInsertRowid
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "حدث خطأ أثناء إنشاء السائق."
      });
    }
  }
);

/* =========================
   HEALTH
========================= */

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      ok: true,
      service: "Djalil Delivery"
    });
  }
);

/* =========================
   STATIC WEBSITE
========================= */

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);

app.get(
  "*",
  (req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );
  }
);

/* =========================
   START
========================= */

await setupAdmin();

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `Djalil Delivery running on port ${PORT}`
    );
  }
);
