import os
import json
import secrets
import sqlite3
from functools import wraps
from pathlib import Path
from datetime import datetime, timedelta
from hmac import compare_digest

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "compound_cafe.db"
UPLOAD_DIR = BASE_DIR / "static" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif"}
ALLOWED_RECEIPT_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "pdf"}
MAX_UPLOAD_BYTES = 5 * 1024 * 1024

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
    PREFERRED_URL_SCHEME="https",
)


def now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def allowed_file(filename, extensions):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in extensions


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS menu_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT DEFAULT '',
        price REAL NOT NULL DEFAULT 0,
        category TEXT NOT NULL DEFAULT 'coffee',
        image TEXT DEFAULT '',
        available INTEGER NOT NULL DEFAULT 1,
        sort_order INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
        comment TEXT NOT NULL,
        approved INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_name TEXT NOT NULL,
        phone TEXT NOT NULL,
        address TEXT NOT NULL,
        items_json TEXT NOT NULL,
        total REAL NOT NULL,
        payment_method TEXT NOT NULL DEFAULT 'gcash',
        payment_status TEXT NOT NULL DEFAULT 'pending',
        receipt_path TEXT DEFAULT '',
        status TEXT NOT NULL DEFAULT 'new',
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS income (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER UNIQUE NOT NULL,
        amount REAL NOT NULL,
        source TEXT NOT NULL DEFAULT 'order',
        recorded_at TEXT NOT NULL,
        FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        attempted_at TEXT NOT NULL,
        success INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_orders_created ON orders(created_at);
    CREATE INDEX IF NOT EXISTS idx_income_recorded ON income(recorded_at);
    CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time ON login_attempts(ip, attempted_at);
    """)

    # Migrate older databases safely.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(orders)").fetchall()}
    for name, definition in [
        ("address", "TEXT NOT NULL DEFAULT ''"),
        ("payment_method", "TEXT NOT NULL DEFAULT 'gcash'"),
        ("payment_status", "TEXT NOT NULL DEFAULT 'pending'"),
        ("receipt_path", "TEXT DEFAULT ''"),
    ]:
        if name not in cols:
            conn.execute(f"ALTER TABLE orders ADD COLUMN {name} {definition}")

    if conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0] == 0:
        username = os.environ.get("ADMIN_USERNAME", "admin").strip()
        password = os.environ.get("ADMIN_PASSWORD", "admin")
        if not password:
            password = "admin"
        print("Admin account initialized. Username: admin | Password: admin")
        conn.execute(
            "INSERT INTO admins(username,password_hash,created_at) VALUES(?,?,?)",
            (username, generate_password_hash(password), now_iso()),
        )

    defaults = {
        "site_name": "COMPOUND CAFÉ",
        "hero_eyebrow": "WELCOME TO COMPOUND CAFÉ",
        "hero_title": "Good Coffee.<br>Good Moments.",
        "hero_text": "Handcrafted coffee, delicious pastries, and beautiful moments — all served in one cozy place.",
        "about_eyebrow": "OUR STORY",
        "about_title": "A Little Place<br>With A Big Heart.",
        "about_text_1": "COMPOUND CAFÉ was created for people who love great coffee, relaxing conversations and unforgettable moments.",
        "about_text_2": "From carefully selected coffee beans to freshly baked pastries, everything is prepared with passion.",
        "about_text_3": "Come in, take a seat, and make yourself at home.",
        "about_year": "2019",
        "footer_text": "Coffee • Pastries • Good Moments",
        "footer_year": "2026",
        "about_image": "https://images.unsplash.com/photo-1445116572660-236099ec97a0?auto=format&fit=crop&w=1200&q=85",
        "announcement": "",
        "gcash_name": "",
        "gcash_number": "",
        "gcash_qr": "",
    }
    for k, v in defaults.items():
        conn.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v))

    if conn.execute("SELECT COUNT(*) FROM menu_items").fetchone()[0] == 0:
        items = [
            ("Espresso", "Rich and bold classic espresso.", 100, "coffee", "", 1, 1),
            ("Cappuccino", "Smooth espresso with steamed milk foam.", 150, "coffee", "", 1, 2),
            ("Iced Latte", "Chilled espresso and creamy milk.", 165, "coffee", "", 1, 3),
            ("Matcha Latte", "Creamy premium matcha latte.", 170, "noncoffee", "", 1, 4),
            ("Chocolate Cake", "Moist chocolate cake with rich frosting.", 180, "pastry", "", 1, 5),
            ("Butter Croissant", "Flaky, buttery and freshly baked.", 120, "pastry", "", 1, 6),
        ]
        conn.executemany("""INSERT INTO menu_items
            (name,description,price,category,image,available,sort_order)
            VALUES(?,?,?,?,?,?,?)""", items)
    conn.commit()
    conn.close()


def settings_dict():
    conn = db()
    rows = conn.execute("SELECT key,value FROM settings").fetchall()
    conn.close()
    return {r["key"]: r["value"] for r in rows}


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def verify_csrf():
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    expected = session.get("csrf_token", "")
    if not sent or not expected or not compare_digest(sent, expected):
        abort(400, description="Invalid security token.")


@app.context_processor
def inject_globals():
    return {"admin_logged_in": bool(session.get("admin_id")), "csrf_token": csrf_token}


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' https://images.unsplash.com data:; "
        "style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; "
        "font-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    )
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get("admin_id"):
            return redirect(url_for("admin_login", next=request.path))
        return f(*args, **kwargs)
    return wrapped


def login_rate_limited(ip):
    conn = db()
    cutoff = (datetime.utcnow() - timedelta(minutes=15)).isoformat()
    count = conn.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE ip=? AND attempted_at>? AND success=0",
        (ip, cutoff),
    ).fetchone()[0]
    conn.close()
    return count >= 8


def record_login(ip, success):
    conn = db()
    conn.execute("INSERT INTO login_attempts(ip,attempted_at,success) VALUES(?,?,?)", (ip, now_iso(), int(success)))
    cutoff = (datetime.utcnow() - timedelta(days=2)).isoformat()
    conn.execute("DELETE FROM login_attempts WHERE attempted_at<?", (cutoff,))
    conn.commit(); conn.close()


def create_income_if_paid(conn, order_id):
    order = conn.execute("SELECT total,payment_status,status FROM orders WHERE id=?", (order_id,)).fetchone()
    if not order or order["payment_status"] != "paid" or order["status"] == "cancelled":
        return
    conn.execute(
        "INSERT OR IGNORE INTO income(order_id,amount,source,recorded_at) VALUES(?,?,?,?)",
        (order_id, order["total"], "order", now_iso()),
    )


def remove_income(conn, order_id):
    conn.execute("DELETE FROM income WHERE order_id=?", (order_id,))


@app.route("/")
def home():
    conn = db()
    items = [dict(r) for r in conn.execute("SELECT * FROM menu_items WHERE available=1 ORDER BY sort_order,id").fetchall()]
    reviews = [dict(r) for r in conn.execute("SELECT * FROM reviews WHERE approved=1 ORDER BY id DESC").fetchall()]
    conn.close()
    return render_template("index.html", settings=settings_dict(), menu=items, reviews=reviews)


@app.post("/api/reviews")
def add_review():
    data = request.get_json(silent=True) or request.form
    name = str(data.get("name", "")).strip()[:80]
    comment = str(data.get("comment", "")).strip()[:1000]
    try:
        rating = int(data.get("rating", 0))
    except (ValueError, TypeError):
        rating = 0
    if not name or not comment or rating not in range(1, 6):
        return jsonify(error="Please provide a name, comment, and 1–5 star rating."), 400
    conn = db()
    conn.execute("INSERT INTO reviews(name,rating,comment,approved,created_at) VALUES(?,?,?,?,?)", (name, rating, comment, 0, now_iso()))
    conn.commit(); conn.close()
    return jsonify(ok=True, message="Review submitted for approval.")


@app.post("/api/orders")
def add_order():
    name = str(request.form.get("name", "")).strip()[:80]
    phone = str(request.form.get("phone", "")).strip()[:30]
    address = str(request.form.get("address", "")).strip()[:300]
    payment_method = str(request.form.get("payment_method", "")).strip().lower()
    try:
        items = json.loads(request.form.get("items_json", "[]"))
    except json.JSONDecodeError:
        items = []

    if not name or not phone or not address or not isinstance(items, list) or not items or payment_method not in {"gcash", "cod"}:
        return jsonify(error="Name, contact number, delivery address, items, and a payment method are required."), 400

    # Recalculate the total from the server's menu prices; never trust a browser-supplied total.
    conn = db()
    clean_items = []
    total = 0.0
    for raw in items:
        try:
            item_id = int(raw.get("id")); qty = int(raw.get("qty", 0))
        except (TypeError, ValueError, AttributeError):
            conn.close(); return jsonify(error="Invalid cart."), 400
        if qty < 1 or qty > 50:
            conn.close(); return jsonify(error="Invalid quantity."), 400
        row = conn.execute("SELECT id,name,price FROM menu_items WHERE id=? AND available=1", (item_id,)).fetchone()
        if not row:
            conn.close(); return jsonify(error="One of the selected items is no longer available."), 400
        line_total = float(row["price"]) * qty
        total += line_total
        clean_items.append({"id": row["id"], "name": row["name"], "price": float(row["price"]), "qty": qty, "line_total": line_total})

    receipt_path = ""
    if payment_method == "gcash":
        receipt = request.files.get("receipt")
        if not receipt or not receipt.filename or not allowed_file(receipt.filename, ALLOWED_RECEIPT_EXTENSIONS):
            conn.close(); return jsonify(error="For GCash orders, please upload your payment receipt (JPG, PNG, WEBP, or PDF)."), 400
        ext = Path(secure_filename(receipt.filename)).suffix.lower()
        filename = f"receipt-{secrets.token_hex(12)}{ext}"
        receipt.save(UPLOAD_DIR / filename)
        receipt_path = "/static/uploads/" + filename

    conn.execute("""INSERT INTO orders(customer_name,phone,address,items_json,total,payment_method,payment_status,receipt_path,status,created_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?)""",
                 (name, phone, address, json.dumps(clean_items), total, payment_method, "pending", receipt_path, "new", now_iso()))
    order_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.commit(); conn.close()
    return jsonify(ok=True, order_id=order_id, total=total, message="Order received. We will confirm it shortly.")


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("admin_id"):
        return redirect(url_for("admin_dashboard"))
    if request.method == "POST":
        if login_rate_limited(request.remote_addr or "unknown"):
            flash("Too many failed attempts. Please wait 15 minutes.", "error")
            return render_template("admin/login.html"), 429
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = db(); admin = conn.execute("SELECT * FROM admins WHERE username=?", (username,)).fetchone(); conn.close()
        ok = bool(admin and check_password_hash(admin["password_hash"], password))
        record_login(request.remote_addr or "unknown", ok)
        if ok:
            session.clear()
            session["admin_id"] = admin["id"]
            session["admin_username"] = admin["username"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(request.args.get("next") or url_for("admin_dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("admin/login.html")


@app.post("/admin/logout")
@admin_required
def admin_logout():
    verify_csrf(); session.clear(); return redirect(url_for("admin_login"))


@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = db()
    total_income = conn.execute("SELECT COALESCE(SUM(amount),0) FROM income").fetchone()[0]
    month_income = conn.execute("SELECT COALESCE(SUM(amount),0) FROM income WHERE recorded_at >= ?", ((datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)).isoformat() + "Z",)).fetchone()[0]
    today_income = conn.execute("SELECT COALESCE(SUM(amount),0) FROM income WHERE recorded_at >= ?", (datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0).isoformat() + "Z",)).fetchone()[0]
    stats = {
        "menu": conn.execute("SELECT COUNT(*) FROM menu_items").fetchone()[0],
        "reviews": conn.execute("SELECT COUNT(*) FROM reviews").fetchone()[0],
        "pending_reviews": conn.execute("SELECT COUNT(*) FROM reviews WHERE approved=0").fetchone()[0],
        "orders": conn.execute("SELECT COUNT(*) FROM orders WHERE status IN ('new','preparing')").fetchone()[0],
        "total_income": total_income,
        "month_income": month_income,
        "today_income": today_income,
    }
    recent_orders = conn.execute("SELECT * FROM orders ORDER BY id DESC LIMIT 8").fetchall()
    recent_income = conn.execute("SELECT * FROM income ORDER BY id DESC LIMIT 8").fetchall()
    conn.close()
    return render_template("admin/dashboard.html", stats=stats, orders=recent_orders, income=recent_income)


@app.route("/admin/income")
@admin_required
def admin_income():
    conn = db()
    total = conn.execute("SELECT COALESCE(SUM(amount),0) FROM income").fetchone()[0]
    by_month = conn.execute("""SELECT substr(recorded_at,1,7) month, SUM(amount) amount, COUNT(*) orders
                              FROM income GROUP BY substr(recorded_at,1,7) ORDER BY month DESC LIMIT 12""").fetchall()
    rows = conn.execute("""SELECT income.*, orders.customer_name, orders.payment_method
                          FROM income JOIN orders ON orders.id=income.order_id ORDER BY income.id DESC""").fetchall()
    conn.close()
    return render_template("admin/income.html", total=total, by_month=by_month, income=rows)


@app.route("/admin/content", methods=["GET", "POST"])
@admin_required
def admin_content():
    fields = ["site_name","hero_eyebrow","hero_title","hero_text","about_eyebrow","about_title","about_text_1","about_text_2","about_text_3","about_year","about_image","footer_text","footer_year","announcement"]
    if request.method == "POST":
        verify_csrf(); conn = db()
        for key in fields:
            conn.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, request.form.get(key, "")))
        conn.commit(); conn.close(); flash("Website content updated.", "success"); return redirect(url_for("admin_content"))
    return render_template("admin/content.html", settings=settings_dict())


@app.post("/admin/upload-about-image")
@admin_required
def admin_upload_about_image():
    verify_csrf(); photo = request.files.get("photo")
    if not photo or not photo.filename or not allowed_file(photo.filename, ALLOWED_IMAGE_EXTENSIONS):
        flash("Unsupported image type. Use PNG, JPG, JPEG, WEBP, or GIF.", "error"); return redirect(url_for("admin_content"))
    ext = Path(secure_filename(photo.filename)).suffix.lower(); filename = f"about-{secrets.token_hex(12)}{ext}"
    photo.save(UPLOAD_DIR / filename)
    conn = db(); conn.execute("INSERT INTO settings(key,value) VALUES('about_image',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", ("/static/uploads/" + filename,)); conn.commit(); conn.close()
    flash("About photo uploaded.", "success"); return redirect(url_for("admin_content"))


@app.route("/admin/menu")
@admin_required
def admin_menu():
    conn = db(); items = conn.execute("SELECT * FROM menu_items ORDER BY sort_order,id").fetchall(); conn.close()
    return render_template("admin/menu.html", items=items)


@app.route("/admin/menu/new", methods=["GET", "POST"])
@app.route("/admin/menu/<int:item_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_menu_edit(item_id=None):
    conn = db(); item = conn.execute("SELECT * FROM menu_items WHERE id=?", (item_id,)).fetchone() if item_id else None
    if request.method == "POST":
        verify_csrf()
        try: price = float(request.form.get("price", 0) or 0)
        except ValueError: price = -1
        if price < 0: conn.close(); flash("Price must be zero or greater.", "error"); return redirect(request.url)
        image_path = item["image"] if item else ""
        photo = request.files.get("photo")
        if photo and photo.filename:
            if not allowed_file(photo.filename, ALLOWED_IMAGE_EXTENSIONS):
                conn.close(); flash("Unsupported image type.", "error"); return redirect(request.url)
            ext = Path(secure_filename(photo.filename)).suffix.lower(); filename = f"product-{secrets.token_hex(12)}{ext}"; photo.save(UPLOAD_DIR / filename); image_path = "/static/uploads/" + filename
        values = (request.form.get("name", "").strip()[:100], request.form.get("description", "").strip()[:500], price, request.form.get("category", "coffee"), image_path, 1 if request.form.get("available") else 0, int(request.form.get("sort_order", 0) or 0))
        if not values[0]: conn.close(); flash("Menu item name is required.", "error"); return redirect(request.url)
        if item: conn.execute("UPDATE menu_items SET name=?,description=?,price=?,category=?,image=?,available=?,sort_order=? WHERE id=?", values + (item_id,))
        else: conn.execute("INSERT INTO menu_items(name,description,price,category,image,available,sort_order) VALUES(?,?,?,?,?,?,?)", values)
        conn.commit(); conn.close(); flash("Menu item saved.", "success"); return redirect(url_for("admin_menu"))
    conn.close(); return render_template("admin/menu_edit.html", item=item)


@app.post("/admin/menu/<int:item_id>/delete")
@admin_required
def admin_menu_delete(item_id):
    verify_csrf(); conn=db(); conn.execute("DELETE FROM menu_items WHERE id=?", (item_id,)); conn.commit(); conn.close(); flash("Menu item deleted.", "success"); return redirect(url_for("admin_menu"))


@app.route("/admin/reviews")
@admin_required
def admin_reviews():
    conn=db(); reviews=conn.execute("SELECT * FROM reviews ORDER BY id DESC").fetchall(); conn.close(); return render_template("admin/reviews.html", reviews=reviews)


@app.post("/admin/reviews/<int:review_id>/<action>")
@admin_required
def admin_review_action(review_id, action):
    verify_csrf(); conn=db()
    if action == "delete": conn.execute("DELETE FROM reviews WHERE id=?", (review_id,))
    elif action == "approve": conn.execute("UPDATE reviews SET approved=1 WHERE id=?", (review_id,))
    elif action == "hide": conn.execute("UPDATE reviews SET approved=0 WHERE id=?", (review_id,))
    else: conn.close(); abort(404)
    conn.commit(); conn.close(); return redirect(url_for("admin_reviews"))


@app.route("/admin/orders")
@admin_required
def admin_orders():
    conn=db(); orders=conn.execute("SELECT * FROM orders ORDER BY id DESC").fetchall(); conn.close(); return render_template("admin/orders.html", orders=orders)


@app.post("/admin/orders/<int:order_id>/status")
@admin_required
def admin_order_status(order_id):
    verify_csrf(); status=request.form.get("status", "new")
    if status not in {"new","preparing","completed","cancelled"}: abort(400)
    conn=db(); conn.execute("UPDATE orders SET status=? WHERE id=?", (status,order_id))
    if status == "cancelled": remove_income(conn, order_id)
    else: create_income_if_paid(conn, order_id)
    conn.commit(); conn.close(); return redirect(url_for("admin_orders"))


@app.post("/admin/orders/<int:order_id>/payment")
@admin_required
def admin_order_payment(order_id):
    verify_csrf(); payment_status=request.form.get("payment_status", "pending")
    if payment_status not in {"pending","paid","refunded"}: abort(400)
    conn=db(); conn.execute("UPDATE orders SET payment_status=? WHERE id=?", (payment_status, order_id))
    if payment_status == "paid": create_income_if_paid(conn, order_id)
    else: remove_income(conn, order_id)
    conn.commit(); conn.close(); return redirect(url_for("admin_orders"))


@app.post("/admin/orders/<int:order_id>/delete")
@admin_required
def admin_order_delete(order_id):
    verify_csrf(); conn=db(); conn.execute("DELETE FROM orders WHERE id=?", (order_id,)); conn.commit(); conn.close(); return redirect(url_for("admin_orders"))


@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    if request.method == "POST":
        verify_csrf(); new_username=request.form.get("username", "").strip()[:80]; new_password=request.form.get("password", "")
        conn=db()
        if new_username:
            try:
                conn.execute("UPDATE admins SET username=? WHERE id=?", (new_username, session["admin_id"])); session["admin_username"] = new_username
            except sqlite3.IntegrityError:
                conn.close(); flash("That username is already in use.", "error"); return redirect(url_for("admin_settings"))
        if new_password:
            if len(new_password) < 4: conn.close(); flash("Use an admin password of at least 4 characters.", "error"); return redirect(url_for("admin_settings"))
            conn.execute("UPDATE admins SET password_hash=? WHERE id=?", (generate_password_hash(new_password), session["admin_id"]))
        for key in ["gcash_name", "gcash_number"]:
            conn.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, request.form.get(key, "").strip()[:100]))
        conn.commit(); conn.close(); flash("Admin and payment settings updated.", "success")

    return render_template("admin/settings.html", settings=settings_dict())


@app.post("/admin/upload-gcash-qr")
@admin_required
def admin_upload_gcash_qr():
    verify_csrf(); photo=request.files.get("photo")
    if not photo or not photo.filename or not allowed_file(photo.filename, ALLOWED_IMAGE_EXTENSIONS):
        flash("Please upload a PNG, JPG, JPEG, WEBP, or GIF QR image.", "error"); return redirect(url_for("admin_settings"))
    ext=Path(secure_filename(photo.filename)).suffix.lower(); filename=f"gcash-qr-{secrets.token_hex(12)}{ext}"; photo.save(UPLOAD_DIR / filename)
    conn=db(); conn.execute("INSERT INTO settings(key,value) VALUES('gcash_qr',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", ("/static/uploads/"+filename,)); conn.commit(); conn.close(); flash("GCash QR updated.", "success"); return redirect(url_for("admin_settings"))


@app.get("/api/menu")
def api_menu():
    conn=db(); rows=conn.execute("SELECT * FROM menu_items WHERE available=1 ORDER BY sort_order,id").fetchall(); conn.close(); return jsonify([dict(r) for r in rows])


@app.get("/api/reviews")
def api_reviews():
    conn=db(); rows=conn.execute("SELECT * FROM reviews WHERE approved=1 ORDER BY id DESC").fetchall(); conn.close(); return jsonify([dict(r) for r in rows])


@app.errorhandler(413)
def too_large(_):
    return jsonify(error="File is too large. Maximum size is 5 MB."), 413


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(debug=False)
