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

app.use(
  express.urlencoded({
    extended: false,
    limit: "20kb"
  })
);

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
   SEED RESTAURANT + PRODUCTS
========================= */

const restaurantCount = db
  .prepare("SELECT COUNT(*) AS c FROM restaurants")
  .get().c;

if (!restaurantCount) {
  const r = db
    .prepare(
      "INSERT INTO restaurants(name,phone,address) VALUES(?,?,?)"
    )
    .run(
      "Djalil Food",
      "0550000000",
      "الجزائر"
    );

  const add = db.prepare(`
    INSERT INTO products(
      restaurant_id,
      name,
      category,
      price,
      emoji
    )
    VALUES(?,?,?,?,?)
  `);

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
   ADMIN AUTO SETUP
========================= */

/*
  في Render نقدر نضيف:
  ADMIN_NAME
  ADMIN_PHONE
  ADMIN_PASSWORD

  وإذا الحساب غير موجود، يتخلق تلقائياً كـ admin.
*/

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

  if (!name || !validPhone(phone) || !validPassword(password)) {
    console.log(
      "ADMIN ENV not configured. Skipping automatic admin creation."
    );
    return;
  }

  try {
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

    const hash = await bcrypt.hash(
      password,
      12
    );

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
  } catch (error) {
    console.error(
      "ADMIN SETUP ERROR:",
      error.message
    );
  }
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
    error:
      "محاولات كثيرة. حاول مرة أخرى بعد قليل."
  }
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 100
