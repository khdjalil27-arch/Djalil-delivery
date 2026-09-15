import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
import path from "path";
import {fileURLToPath} from "url";

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const app=express();
const db=new Database("djalil.db");
const JWT_SECRET=process.env.JWT_SECRET||"CHANGE_THIS_SECRET_IN_PRODUCTION";
app.use(cors()); app.use(express.json()); app.use(express.static(path.join(__dirname,"public")));

db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,phone TEXT UNIQUE NOT NULL,password TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'customer');
CREATE TABLE IF NOT EXISTS restaurants(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,phone TEXT,address TEXT,active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY AUTOINCREMENT,restaurant_id INTEGER NOT NULL,name TEXT NOT NULL,category TEXT,price INTEGER NOT NULL,emoji TEXT DEFAULT '🍽️',active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,restaurant_id INTEGER,items TEXT NOT NULL,total INTEGER NOT NULL,delivery_fee INTEGER NOT NULL,address TEXT NOT NULL,phone TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'received',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);
const count=db.prepare("SELECT COUNT(*) c FROM restaurants").get().c;
if(!count){
 const r=db.prepare("INSERT INTO restaurants(name,phone,address) VALUES(?,?,?)").run("Djalil Food","0550000000","الجزائر");
 const add=db.prepare("INSERT INTO products(restaurant_id,name,category,price,emoji) VALUES(?,?,?,?,?)");
 [["Classic Burger","برغر",650,"🍔"],["Double Cheese","برغر",850,"🍔"],["Pizza Margherita","بيتزا",900,"🍕"],["Crêpe Choko","كريب",550,"🥞"],["Tacos Poulet","تاكوس",700,"🌯"],["Chicken Box","دجاج",800,"🍗"]].forEach(x=>add.run(r.lastInsertRowid,...x));
}
function auth(req,res,next){try{const h=req.headers.authorization||"";req.user=jwt.verify(h.replace("Bearer ",""),JWT_SECRET);next()}catch{res.status(401).json({error:"غير مصرح"})}}
function role(...roles){return (req,res,next)=>roles.includes(req.user.role)?next():res.status(403).json({error:"صلاحيات غير كافية"})}

app.post("/api/register",async(req,res)=>{
 const {name,phone,password}=req.body||{};
 if(!name||!phone||!password)return res.status(400).json({error:"أكمل المعلومات"});
 try{const hash=await bcrypt.hash(password,10);const x=db.prepare("INSERT INTO users(name,phone,password) VALUES(?,?,?)").run(name,phone,hash);const token=jwt.sign({id:x.lastInsertRowid,name,phone,role:"customer"},JWT_SECRET,{expiresIn:"7d"});res.json({token,user:{id:x.lastInsertRowid,name,phone,role:"customer"}})}
 catch{res.status(409).json({error:"رقم الهاتف مسجل من قبل"})}
});
app.post("/api/login",async(req,res)=>{
 const u=db.prepare("SELECT * FROM users WHERE phone=?").get(req.body.phone);
 if(!u||!(await bcrypt.compare(req.body.password||"",u.password)))return res.status(401).json({error:"رقم الهاتف أو كلمة السر خاطئة"});
 const token=jwt.sign({id:u.id,name:u.name,phone:u.phone,role:u.role},JWT_SECRET,{expiresIn:"7d"});res.json({token,user:{id:u.id,name:u.name,phone:u.phone,role:u.role}});
});
app.get("/api/products",(req,res)=>res.json(db.prepare("SELECT p.*,r.name restaurant FROM products p JOIN restaurants r ON r.id=p.restaurant_id WHERE p.active=1 AND r.active=1").all()));
app.get("/api/restaurants",(req,res)=>res.json(db.prepare("SELECT * FROM restaurants WHERE active=1").all()));

app.post("/api/orders",auth,(req,res)=>{
 const {items,address,phone}=req.body||{};
 if(!Array.isArray(items)||!items.length||!address||!phone)return res.status(400).json({error:"معلومات الطلب ناقصة"});
 let total=0; let restaurant=null; const clean=[];
 for(const i of items){
   const p=db.prepare("SELECT * FROM products WHERE id=? AND active=1").get(i.id);
   if(!p)return res.status(400).json({error:"منتج غير موجود"});
   restaurant ??=p.restaurant_id; if(p.restaurant_id!==restaurant)return res.status(400).json({error:"اختر منتجات من مطعم واحد"});
   const q=Math.max(1,Math.min(20,Number(i.q)||1)); total+=p.price*q; clean.push({id:p.id,name:p.name,price:p.price,q});
 }
 const delivery_fee=300, final=total+delivery_fee;
 const x=db.prepare("INSERT INTO orders(user_id,restaurant_id,items,total,delivery_fee,address,phone) VALUES(?,?,?,?,?,?,?)").run(req.user.id,restaurant,JSON.stringify(clean),final,delivery_fee,address,phone);
 res.json({id:x.lastInsertRowid,total:final,status:"received"});
});
app.get("/api/orders",auth,(req,res)=>{
 const q=req.user.role==="admin"||req.user.role==="driver"?
 db.prepare("SELECT o.*,u.name customer FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC").all():
 db.prepare("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC").all(req.user.id);
 res.json(q.map(o=>({...o,items:JSON.parse(o.items)})));
});
app.patch("/api/orders/:id/status",auth,role("admin","driver"),(req,res)=>{
 const allowed=["received","preparing","pickup","on_the_way","delivered","cancelled"];
 if(!allowed.includes(req.body.status))return res.status(400).json({error:"حالة غير صالحة"});
 const x=db.prepare("UPDATE orders SET status=? WHERE id=?").run(req.body.status,req.params.id);
 res.json({ok:!!x.changes});
});
app.get("/api/admin/stats",auth,role("admin"),(req,res)=>{
 res.json({
   orders:db.prepare("SELECT COUNT(*) c FROM orders").get().c,
   revenue:db.prepare("SELECT COALESCE(SUM(total),0) s FROM orders WHERE status='delivered'").get().s,
   customers:db.prepare("SELECT COUNT(*) c FROM users WHERE role='customer'").get().c,
   restaurants:db.prepare("SELECT COUNT(*) c FROM restaurants").get().c
 });
});
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(process.env.PORT||3000,()=>console.log("Djalil Delivery running on port "+(process.env.PORT||3000)));
