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

app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);

app.use(cors());

app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: true, limit: "20kb" }));

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "طلبات كثيرة، حاول بعد قليل.",
  },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "محاولات كثيرة، حاول بعد قليل.",
  },
});

app.use("/api", apiLimiter);

const db = new Database("delivery.db");

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'customer',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS restaurants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    address TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    restaurant_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price INTEGER NOT NULL,
    emoji TEXT DEFAULT '🍔',
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (restaurant_id) REFERENCES restaurants(id)
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    restaurant_id INTEGER NOT NULL,
    items TEXT NOT NULL,
    total INTEGER NOT NULL,
    delivery_fee INTEGER NOT NULL DEFAULT 300,
    address TEXT NOT NULL,
    phone TEXT NOT NULL,
    latitude REAL,
    longitude REAL,
    status TEXT NOT NULL DEFAULT 'received',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (restaurant_id) REFERENCES restaurants(id)
  );
`);

/*
  Migration:
  إذا كانت قاعدة البيانات القديمة موجودة،
  نضيف latitude و longitude بدون حذف الطلبات القديمة.
*/
const orderColumns = db
  .prepare("PRAGMA table_info(orders)")
  .all()
  .map((column) => column.name);

if (!orderColumns.includes("latitude")) {
  db.exec("ALTER TABLE orders ADD COLUMN latitude REAL");
}

if (!orderColumns.includes("longitude")) {
  db.exec("ALTER TABLE orders ADD COLUMN longitude REAL");
}

/* =========================
   SEED RESTAURANT
========================= */

const restaurantCount = db
  .prepare("SELECT COUNT(*) AS count FROM restaurants")
  .get();

if (restaurantCount.count === 0) {
  const restaurant = db
    .prepare(
      `
      INSERT INTO restaurants(name, phone, address, active)
      VALUES(?,?,?,1)
      `
    )
    .run(
      "Djalil Food",
      "0550000000",
      "الجزائر"
    );

  const restaurantId = restaurant.lastInsertRowid;

  const products = [
    ["Classic Burger", "burger", 650, "🍔"],
    ["Double Cheese", "burger", 850, "🍔"],
    ["Pizza Margherita", "pizza", 900, "🍕"],
    ["Crêpe Choko", "crepe", 550, "🥞"],
    ["Tacos Poulet", "tacos", 700, "🌯"],
    ["Chicken Box", "chicken", 800, "🍗"],
  ];

  const insertProduct = db.prepare(`
    INSERT INTO products(
      restaurant_id,
      name,
      category,
      price,
      emoji,
      active
    )
    VALUES(?,?,?,?,?,1)
  `);

  const seedProducts = db.transaction(() => {
    for (const product of products) {
      insertProduct.run(
        restaurantId,
        product[0],
        product[1],
        product[2],
        product[3]
      );
    }
  });

  seedProducts();
}

/* =========================
   HELPERS
========================= */

function validPhone(phone) {
  return /^(\+213|0)(5|6|7)\d{8}$/.test(phone);
}

function signToken(user) {
  return jwt.sign(
    {
      id: user.id,
      name: user.name,
      phone: user.phone,
      role: user.role,
    },
    JWT_SECRET,
    {
      expiresIn: "2d",
      issuer: "djalil-delivery",
    }
  );
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "غير مسجل الدخول.",
      });
    }

    const token = header.slice(7);

    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: "djalil-delivery",
    });

    const user = db
      .prepare(
        `
        SELECT id, name, phone, role
        FROM users
        WHERE id = ?
        `
      )
      .get(decoded.id);

    if (!user) {
      return res.status(401).json({
        error: "المستخدم غير موجود.",
      });
    }

    req.user = user;
    next();
  } catch {
    return res.status(401).json({
      error: "الجلسة غير صالحة أو منتهية.",
    });
  }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({
      error: "غير مسموح.",
    });
  }

  next();
}

function adminOrDriver(req, res, next) {
  if (
    req.user?.role !== "admin" &&
    req.user?.role !== "driver"
  ) {
    return res.status(403).json({
      error: "غير مسموح.",
    });
  }

  next();
}

/* =========================
   AUTH
========================= */

app.post("/api/register", authLimiter, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const phone = String(req.body.phone || "").trim();
    const password = String(req.body.password || "");

    if (name.length < 2 || name.length > 80) {
      return res.status(400).json({
        error: "الاسم غير صالح.",
      });
    }

    if (!validPhone(phone)) {
      return res.status(400).json({
        error: "رقم الهاتف غير صالح.",
      });
    }

    if (password.length < 8 || password.length > 100) {
      return res.status(400).json({
        error: "كلمة السر يجب أن تكون 8 أحرف على الأقل.",
      });
    }

    const existing = db
      .prepare("SELECT id FROM users WHERE phone = ?")
      .get(phone);

    if (existing) {
      return res.status(409).json({
        error: "رقم الهاتف مسجل من قبل.",
      });
    }

    const hash = await bcrypt.hash(password, 12);

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
      .run(name, phone, hash);

    const user = {
      id: result.lastInsertRowid,
      name,
      phone,
      role: "customer",
    };

    const token = signToken(user);

    res.status(201).json({
      message: "تم إنشاء الحساب بنجاح.",
      token,
      user,
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "حدث خطأ في التسجيل.",
    });
  }
});

app.post("/api/login", authLimiter, async (req, res) => {
  try {
    const phone = String(req.body.phone || "").trim();
    const password = String(req.body.password || "");

    const user = db
      .prepare(
        `
        SELECT id, name, phone, password, role
        FROM users
        WHERE phone = ?
        `
      )
      .get(phone);

    if (!user) {
      return res.status(401).json({
        error: "رقم الهاتف أو كلمة السر غير صحيحة.",
      });
    }

    const valid = await bcrypt.compare(
      password,
      user.password
    );

    if (!valid) {
      return res.status(401).json({
        error: "رقم الهاتف أو كلمة السر غير صحيحة.",
      });
    }

    const safeUser = {
      id: user.id,
      name: user.name,
      phone: user.phone,
      role: user.role,
    };

    const token = signToken(safeUser);

    res.json({
      message: "تم تسجيل الدخول.",
      token,
      user: safeUser,
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "حدث خطأ في تسجيل الدخول.",
    });
  }
});

app.get("/api/me", auth, (req, res) => {
  res.json({
    user: req.user,
  });
});

/* =========================
   RESTAURANTS
========================= */

app.get("/api/restaurants", (req, res) => {
  const restaurants = db
    .prepare(
      `
      SELECT id, name, phone, address, active
      FROM restaurants
      WHERE active = 1
      ORDER BY id DESC
      `
    )
    .all();

  res.json({
    restaurants,
  });
});

/* =========================
   PRODUCTS
========================= */

app.get("/api/products", (req, res) => {
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
        r.name AS restaurant_name
      FROM products p
      JOIN restaurants r
        ON r.id = p.restaurant_id
      WHERE p.active = 1
        AND r.active = 1
      ORDER BY p.id DESC
      `
    )
    .all();

  res.json({
    products,
  });
});

/* =========================
   CREATE ORDER
========================= */

app.post("/api/orders", auth, (req, res) => {
  try {
    const restaurantId = Number(req.body.restaurantId);
    const items = req.body.items;
    const address = String(req.body.address || "").trim();
    const phone = String(req.body.phone || "").trim();

    /*
      الموقع الجغرافي
    */
    const latitude = Number(req.body.latitude);
    const longitude = Number(req.body.longitude);

    if (!Number.isInteger(restaurantId) || restaurantId <= 0) {
      return res.status(400).json({
        error: "المطعم غير صالح.",
      });
    }

    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({
        error: "السلة فارغة.",
      });
    }

    if (items.length > 50) {
      return res.status(400).json({
        error: "عدد المنتجات كبير.",
      });
    }

    if (address.length < 3 || address.length > 500) {
      return res.status(400).json({
        error: "العنوان غير صالح.",
      });
    }

    if (!validPhone(phone)) {
      return res.status(400).json({
        error: "رقم الهاتف غير صالح.",
      });
    }

    /*
      لازم يكون الزوج كامل:
      latitude + longitude
    */
    if (
      !Number.isFinite(latitude) ||
      latitude < -90 ||
      latitude > 90
    ) {
      return res.status(400).json({
        error: "الموقع الجغرافي غير صالح.",
      });
    }

    if (
      !Number.isFinite(longitude) ||
      longitude < -180 ||
      longitude > 180
    ) {
      return res.status(400).json({
        error: "الموقع الجغرافي غير صالح.",
      });
    }

    const restaurant = db
      .prepare(
        `
        SELECT id
        FROM restaurants
        WHERE id = ?
          AND active = 1
        `
      )
      .get(restaurantId);

    if (!restaurant) {
      return res.status(400).json({
        error: "المطعم غير موجود.",
      });
    }

    const productIds = [
      ...new Set(
        items.map((item) => Number(item.productId))
      ),
    ];

    if (
      productIds.length === 0 ||
      productIds.some(
        (id) => !Number.isInteger(id) || id <= 0
      )
    ) {
      return res.status(400).json({
        error: "المنتجات غير صالحة.",
      });
    }

    const placeholders = productIds
      .map(() => "?")
      .join(",");

    const products = db
      .prepare(
        `
        SELECT
          id,
          restaurant_id,
          name,
          price
        FROM products
        WHERE id IN (${placeholders})
          AND active = 1
        `
      )
      .all(...productIds);

    if (products.length !== productIds.length) {
      return res.status(400).json({
        error: "بعض المنتجات غير موجودة.",
      });
    }

    const productMap = new Map(
      products.map((product) => [
        product.id,
        product,
      ])
    );

    let subtotal = 0;

    const cleanItems = [];

    for (const item of items) {
      const productId = Number(item.productId);
      const quantity = Number(item.quantity);

      if (
        !Number.isInteger(quantity) ||
        quantity < 1 ||
        quantity > 20
      ) {
        return res.status(400).json({
          error: "كمية المنتج غير صالحة.",
        });
      }

      const product = productMap.get(productId);

      if (!product) {
        return res.status(400).json({
          error: "المنتج غير موجود.",
        });
      }

      if (product.restaurant_id !== restaurantId) {
        return res.status(400).json({
          error: "لا يمكن الطلب من مطاعم مختلفة.",
        });
      }

      const lineTotal = product.price * quantity;

      subtotal += lineTotal;

      cleanItems.push({
        productId: product.id,
        name: product.name,
        price: product.price,
        quantity,
        total: lineTotal,
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
          latitude,
          longitude,
          status
        )
        VALUES(?,?,?,?,?,?,?,?,?,'received')
        `
      )
      .run(
        req.user.id,
        restaurantId,
        JSON.stringify(cleanItems),
        total,
        deliveryFee,
        address,
        phone,
        latitude,
        longitude
      );

    const order = db
      .prepare(
        `
        SELECT *
        FROM orders
        WHERE id = ?
        `
      )
      .get(result.lastInsertRowid);

    res.status(201).json({
      message: "تم إنشاء الطلب بنجاح.",
      order,
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "حدث خطأ أثناء إنشاء الطلب.",
    });
  }
});

/* =========================
   CUSTOMER ORDERS
========================= */

app.get("/api/orders", auth, (req, res) => {
  try {
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
            r.name AS restaurant_name
          FROM orders o
          JOIN users u
            ON u.id = o.user_id
          JOIN restaurants r
            ON r.id = o.restaurant_id
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
            r.name AS restaurant_name
          FROM orders o
          JOIN restaurants r
            ON r.id = o.restaurant_id
          WHERE o.user_id = ?
          ORDER BY o.id DESC
          `
        )
        .all(req.user.id);
    }

    res.json({
      orders,
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "تعذر جلب الطلبات.",
    });
  }
});

/* =========================
   UPDATE ORDER STATUS
========================= */

const allowedStatuses = [
  "received",
  "preparing",
  "pickup",
  "on_the_way",
  "delivered",
  "cancelled",
];

app.patch(
  "/api/orders/:id/status",
  auth,
  adminOrDriver,
  (req, res) => {
    try {
      const orderId = Number(req.params.id);
      const status = String(req.body.status || "");

      if (!Number.isInteger(orderId) || orderId <= 0) {
        return res.status(400).json({
          error: "رقم الطلب غير صالح.",
        });
      }

      if (!allowedStatuses.includes(status)) {
        return res.status(400).json({
          error: "حالة الطلب غير صالحة.",
        });
      }

      const order = db
        .prepare(
          `
          SELECT id
          FROM orders
          WHERE id = ?
          `
        )
        .get(orderId);

      if (!order) {
        return res.status(404).json({
          error: "الطلب غير موجود.",
        });
      }

      db.prepare(
        `
        UPDATE orders
        SET status = ?
        WHERE id = ?
        `
      ).run(status, orderId);

      const updatedOrder = db
        .prepare(
          `
          SELECT *
          FROM orders
          WHERE id = ?
          `
        )
        .get(orderId);

      res.json({
        message: "تم تحديث حالة الطلب.",
        order: updatedOrder,
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "تعذر تحديث حالة الطلب.",
      });
    }
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
    try {
      const orders = db
        .prepare(
          "SELECT COUNT(*) AS count FROM orders"
        )
        .get().count;

      const deliveredRevenue = db
        .prepare(
          `
          SELECT COALESCE(SUM(total), 0) AS total
          FROM orders
          WHERE status = 'delivered'
          `
        )
        .get().total;

      const customers = db
        .prepare(
          `
          SELECT COUNT(*) AS count
          FROM users
          WHERE role = 'customer'
          `
        )
        .get().count;

      const restaurants = db
        .prepare(
          `
          SELECT COUNT(*) AS count
          FROM restaurants
          WHERE active = 1
          `
        )
        .get().count;

      const drivers = db
        .prepare(
          `
          SELECT COUNT(*) AS count
          FROM users
          WHERE role = 'driver'
          `
        )
        .get().count;

      const pending = db
        .prepare(
          `
          SELECT COUNT(*) AS count
          FROM orders
          WHERE status IN(
            'received',
            'preparing',
            'pickup',
            'on_the_way'
          )
          `
        )
        .get().count;

      res.json({
        orders,
        deliveredRevenue,
        customers,
        restaurants,
        drivers,
        pending,
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "تعذر جلب الإحصائيات.",
      });
    }
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
          role,
          created_at
        FROM users
        ORDER BY id DESC
        `
      )
      .all();

    res.json({
      users,
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
          r.name AS restaurant_name
        FROM products p
        JOIN restaurants r
          ON r.id = p.restaurant_id
        ORDER BY p.id DESC
        `
      )
      .all();

    res.json({
      products,
    });
  }
);

app.post(
  "/api/admin/products",
  auth,
  adminOnly,
  (req, res) => {
    try {
      const restaurantId = Number(
        req.body.restaurantId
      );

      const name = String(
        req.body.name || ""
      ).trim();

      const category = String(
        req.body.category || ""
      ).trim();

      const price = Number(req.body.price);

      const emoji = String(
        req.body.emoji || "🍔"
      ).trim();

      if (
        !Number.isInteger(restaurantId) ||
        restaurantId <= 0
      ) {
        return res.status(400).json({
          error: "المطعم غير صالح.",
        });
      }

      if (name.length < 2 || name.length > 100) {
        return res.status(400).json({
          error: "اسم المنتج غير صالح.",
        });
      }

      if (
        !Number.isFinite(price) ||
        price <= 0 ||
        price > 1000000
      ) {
        return res.status(400).json({
          error: "السعر غير صالح.",
        });
      }

      const restaurant = db
        .prepare(
          `
          SELECT id
          FROM restaurants
          WHERE id = ?
            AND active = 1
          `
        )
        .get(restaurantId);

      if (!restaurant) {
        return res.status(400).json({
          error: "المطعم غير موجود.",
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
            emoji,
            active
          )
          VALUES(?,?,?,?,?,1)
          `
        )
        .run(
          restaurantId,
          name,
          category || "other",
          Math.round(price),
          emoji
        );

      res.status(201).json({
        message: "تمت إضافة المنتج.",
        id: result.lastInsertRowid,
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "تعذر إضافة المنتج.",
      });
    }
  }
);

app.patch(
  "/api/admin/products/:id",
  auth,
  adminOnly,
  (req, res) => {
    try {
      const id = Number(req.params.id);

      const name =
        req.body.name !== undefined
          ? String(req.body.name).trim()
          : undefined;

      const category =
        req.body.category !== undefined
          ? String(req.body.category).trim()
          : undefined;

      const price =
        req.body.price !== undefined
          ? Number(req.body.price)
          : undefined;

      const emoji =
        req.body.emoji !== undefined
          ? String(req.body.emoji).trim()
          : undefined;

      const active =
        req.body.active !== undefined
          ? Boolean(req.body.active)
          : undefined;

      const existing = db
        .prepare(
          `
          SELECT *
          FROM products
          WHERE id = ?
          `
        )
        .get(id);

      if (!existing) {
        return res.status(404).json({
          error: "المنتج غير موجود.",
        });
      }

      const finalName =
        name !== undefined
          ? name
          : existing.name;

      const finalCategory =
        category !== undefined
          ? category
          : existing.category;

      const finalPrice =
        price !== undefined
          ? price
          : existing.price;

      const finalEmoji =
        emoji !== undefined
          ? emoji
          : existing.emoji;

      const finalActive =
        active !== undefined
          ? active
            ? 1
            : 0
          : existing.active;

      if (
        finalName.length < 2 ||
        finalName.length > 100
      ) {
        return res.status(400).json({
          error: "اسم المنتج غير صالح.",
        });
      }

      if (
        !Number.isFinite(finalPrice) ||
        finalPrice <= 0
      ) {
        return res.status(400).json({
          error: "السعر غير صالح.",
        });
      }

      db.prepare(
        `
        UPDATE products
        SET
          name = ?,
          category = ?,
          price = ?,
          emoji = ?,
          active = ?
        WHERE id = ?
        `
      ).run(
        finalName,
        finalCategory,
        Math.round(finalPrice),
        finalEmoji,
        finalActive,
        id
      );

      res.json({
        message: "تم تحديث المنتج.",
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "تعذر تحديث المنتج.",
      });
    }
  }
);

app.delete(
  "/api/admin/products/:id",
  auth,
  adminOnly,
  (req, res) => {
    try {
      const id = Number(req.params.id);

      const result = db
        .prepare(
          `
          UPDATE products
          SET active = 0
          WHERE id = ?
          `
        )
        .run(id);

      if (result.changes === 0) {
        return res.status(404).json({
          error: "المنتج غير موجود.",
        });
      }

      res.json({
        message: "تم تعطيل المنتج.",
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "تعذر حذف المنتج.",
      });
    }
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

    res.json({
      restaurants,
    });
  }
);

app.post(
  "/api/admin/restaurants",
  auth,
  adminOnly,
  (req, res) => {
    try {
      const name = String(
        req.body.name || ""
      ).trim();

      const phone = String(
        req.body.phone || ""
      ).trim();

      const address = String(
        req.body.address || ""
      ).trim();

      if (
        name.length < 2 ||
        name.length > 100
      ) {
        return res.status(400).json({
          error: "اسم المطعم غير صالح.",
        });
      }

      if (!validPhone(phone)) {
        return res.status(400).json({
          error: "رقم الهاتف غير صالح.",
        });
      }

      if (
        address.length < 2 ||
        address.length > 300
      ) {
        return res.status(400).json({
          error: "العنوان غير صالح.",
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
        id: result.lastInsertRowid,
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "تعذر إضافة المطعم.",
      });
    }
  }
);

app.patch(
  "/api/admin/restaurants/:id",
  auth,
  adminOnly,
  (req, res) => {
    try {
      const id = Number(req.params.id);

      const existing = db
        .prepare(
          `
          SELECT *
          FROM restaurants
          WHERE id = ?
          `
        )
        .get(id);

      if (!existing) {
        return res.status(404).json({
          error: "المطعم غير موجود.",
        });
      }

      const name =
        req.body.name !== undefined
          ? String(req.body.name).trim()
          : existing.name;

      const phone =
        req.body.phone !== undefined
          ? String(req.body.phone).trim()
          : existing.phone;

      const address =
        req.body.address !== undefined
          ? String(req.body.address).trim()
          : existing.address;

      const active =
        req.body.active !== undefined
          ? Boolean(req.body.active)
            ? 1
            : 0
          : existing.active;

      if (
        name.length < 2 ||
        name.length > 100
      ) {
        return res.status(400).json({
          error: "اسم المطعم غير صالح.",
        });
      }

      if (!validPhone(phone)) {
        return res.status(400).json({
          error: "رقم الهاتف غير صالح.",
        });
      }

      if (
        address.length < 2 ||
        address.length > 300
      ) {
        return res.status(400).json({
          error: "العنوان غير صالح.",
        });
      }

      db.prepare(
        `
        UPDATE restaurants
        SET
          name = ?,
          phone = ?,
          address = ?,
          active = ?
        WHERE id = ?
        `
      ).run(
        name,
        phone,
        address,
        active,
        id
      );

      res.json({
        message: "تم تحديث المطعم.",
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "تعذر تحديث المطعم.",
      });
    }
  }
);

app.delete(
  "/api/admin/restaurants/:id",
  auth,
  adminOnly,
  (req, res) => {
    try {
      const id = Number(req.params.id);

      const activeProducts = db
        .prepare(
          `
          SELECT COUNT(*) AS count
          FROM products
          WHERE restaurant_id = ?
            AND active = 1
          `
        )
        .get(id).count;

      if (activeProducts > 0) {
        return res.status(400).json({
          error:
            "لا يمكن تعطيل المطعم قبل تعطيل منتجاته.",
        });
      }

      const result = db
        .prepare(
          `
          UPDATE restaurants
          SET active = 0
          WHERE id = ?
          `
        )
        .run(id);

      if (result.changes === 0) {
        return res.status(404).json({
          error: "المطعم غير موجود.",
        });
      }

      res.json({
        message: "تم تعطيل المطعم.",
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "تعذر تعطيل المطعم.",
      });
    }
  }
);

/* =========================
   ADMIN / DRIVER ORDERS
========================= */

app.get(
  "/api/admin/orders",
  auth,
  adminOrDriver,
  (req, res) => {
    try {
      const orders = db
        .prepare(
          `
          SELECT
            o.*,
            u.name AS customer_name,
            u.phone AS customer_phone,
            r.name AS restaurant_name,
            r.address AS restaurant_address
          FROM orders o
          JOIN users u
            ON u.id = o.user_id
          JOIN restaurants r
            ON r.id = o.restaurant_id
          ORDER BY o.id DESC
          `
        )
        .all();

      res.json({
        orders,
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "تعذر جلب الطلبات.",
      });
    }
  }
);

/* =========================
   DRIVERS
========================= */

app.post(
  "/api/admin/drivers",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const name = String(
        req.body.name || ""
      ).trim();

      const phone = String(
        req.body.phone || ""
      ).trim();

      const password = String(
        req.body.password || ""
      );

      if (
        name.length < 2 ||
        name.length > 80
      ) {
        return res.status(400).json({
          error: "اسم السائق غير صالح.",
        });
      }

      if (!validPhone(phone)) {
        return res.status(400).json({
          error: "رقم الهاتف غير صالح.",
        });
      }

      if (
        password.length < 8 ||
        password.length > 100
      ) {
        return res.status(400).json({
          error:
            "كلمة السر يجب أن تكون 8 أحرف على الأقل.",
        });
      }

      const existing = db
        .prepare(
          "SELECT id FROM users WHERE phone = ?"
        )
        .get(phone);

      if (existing) {
        return res.status(409).json({
          error: "رقم الهاتف مسجل من قبل.",
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
        id: result.lastInsertRowid,
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "تعذر إنشاء السائق.",
      });
    }
  }
);

/* =========================
   CHANGE USER ROLE
========================= */

app.patch(
  "/api/admin/users/:id/role",
  auth,
  adminOnly,
  (req, res) => {
    try {
      const id = Number(req.params.id);
      const role = String(req.body.role || "");

      const allowedRoles = [
        "customer",
        "driver",
        "admin",
      ];

      if (!allowedRoles.includes(role)) {
        return res.status(400).json({
          error: "الدور غير صالح.",
        });
      }

      if (id === req.user.id) {
        return res.status(400).json({
          error: "لا يمكنك تغيير دور حسابك بنفسك.",
        });
      }

      const result = db
        .prepare(
          `
          UPDATE users
          SET role = ?
          WHERE id = ?
          `
        )
        .run(role, id);

      if (result.changes === 0) {
        return res.status(404).json({
          error: "المستخدم غير موجود.",
        });
      }

      res.json({
        message: "تم تغيير دور المستخدم.",
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "تعذر تغيير الدور.",
      });
    }
  }
);

/* =========================
   HEALTH
========================= */

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "Djalil Delivery",
  });
});

/* =========================
   ADMIN SETUP
========================= */

async function setupAdmin() {
  const name = String(
    process.env.ADMIN_NAME || ""
  ).trim();

  const phone = String(
    process.env.ADMIN_PHONE || ""
  ).trim();

  const password = String(
    process.env.ADMIN_PASSWORD || ""
  );

  if (!name || !phone || !password) {
    console.warn(
      "Admin environment variables are not fully configured."
    );
    return;
  }

  if (!validPhone(phone)) {
    console.warn(
      "ADMIN_PHONE is invalid."
    );
    return;
  }

  if (
    password.length < 8 ||
    password.length > 100
  ) {
    console.warn(
      "ADMIN_PASSWORD is invalid."
    );
    return;
  }

  const existing = db
    .prepare(
      `
      SELECT id, role
      FROM users
      WHERE phone = ?
      `
    )
    .get(phone);

  if (!existing) {
    const hash = await bcrypt.hash(
      password,
      12
    );

    db.prepare(
      `
      INSERT INTO users(
        name,
        phone,
        password,
        role
      )
      VALUES(?,?,?,'admin')
      `
    ).run(
      name,
      phone,
      hash
    );

    console.log("Admin account created.");
  } else if (existing.role !== "admin") {
    db.prepare(
      `
      UPDATE users
      SET role = 'admin'
      WHERE id = ?
      `
    ).run(existing.id);

    console.log("Existing account promoted to admin.");
  }
}

/* =========================
   STATIC FRONTEND
========================= */

app.use(express.static(path.join(__dirname, "public")));

app.get("*", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

/* =========================
   START SERVER
========================= */

await setupAdmin();

app.listen(PORT, () => {
  console.log(
    `Djalil Delivery running on port ${PORT}`
  );
});
