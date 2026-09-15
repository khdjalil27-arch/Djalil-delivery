# Djalil Delivery — Full Stack

## التشغيل محلياً
1. ثبّت Node.js 20+.
2. افتح هذا المجلد في Terminal.
3. نفّذ: `npm install`
4. غيّر JWT_SECRET في بيئة التشغيل إلى قيمة قوية.
5. نفّذ: `npm start`
6. افتح `http://localhost:3000`

## ما هو موجود
- حسابات الزبائن وتسجيل الدخول
- قاعدة بيانات SQLite
- مطاعم ومنتجات
- سلة
- إنشاء طلب حقيقي وتخزينه
- رسوم توصيل
- تتبع حالة الطلب عبر API
- صلاحيات customer/driver/admin
- إحصائيات Admin API

## للنشر
يمكن نشره على أي استضافة تدعم Node.js. للإنتاج استخدم PostgreSQL/MySQL بدلاً من SQLite، HTTPS، secret قوي، ونظام دفع إلكتروني موثوق.
