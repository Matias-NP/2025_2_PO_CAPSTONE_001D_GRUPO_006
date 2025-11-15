import os
import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash

# === Ruta ABSOLUTA a tu base de datos (ajústala si cambias de carpeta) ===
DB_PATH = r"Fase 2/Evidencias Proyecto/Evidencias de sistema/Pepsi/pepsi.db"

# ------------------ Config básica ------------------
app = Flask(__name__)
app.secret_key = "cambia-esta-clave-super-segura"   # requerido para sesiones/flash

def db():
    """Abre conexión SQLite con FK y chequeo de integridad."""
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON;")
    # Comprobación rápida de integridad: si hay corrupción, falla aquí
    ok = con.execute("PRAGMA integrity_check").fetchone()[0]
    if ok != "ok":
        con.close()
        raise sqlite3.DatabaseError(f"Integrity check failed: {ok}")
    return con

# ------------------ Utilidades ------------------
def contraseña_valida(hash_guardado: str, password_entrada: str) -> bool:
    """
    Valida la contraseña. Si el campo parece un hash de Werkzeug, usa check_password_hash.
    Si no (modo dev), compara texto plano.
    """
    if not hash_guardado:
        return False
    # Heurística simple: hashes de Werkzeug suelen ser largos (>=60)
    if len(hash_guardado) >= 60:
        try:
            return check_password_hash(hash_guardado, password_entrada)
        except Exception:
            return False
    # MODO DEV (no seguro): compara en claro
    return hash_guardado == password_entrada

# ------------------ Decoradores ------------------
def login_required(fn):
    @wraps(fn)
    def _wrap(*a, **k):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return fn(*a, **k)
    return _wrap

def require_role(role):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            if session.get("role") != role:
                return redirect(url_for("login", role=role))
            return fn(*a, **k)
        return wrapper
    return deco

# ------------------ Rutas ------------------
@app.route("/")
def home():
    # portada → selección de rol
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    role = (request.args.get("role") or request.form.get("role") or "").strip().lower()

    if request.method == "POST":
        email = (request.form.get("email") or request.form.get("correo") or "").strip().lower()
        password = request.form.get("password") or ""

        if not role:
            flash("Ingresa desde un rol válido (mecánico, conductor, administrador o seguridad).")
            return render_template("login.html", role=role)
        if not email or not password:
            flash("Completa correo y contraseña.")
            return render_template("login.html", role=role)

        con = db()
        cur = con.cursor()
        # Busca usuario por email + rol + activo, y trae el hash y el nombre
        cur.execute("""
            SELECT u.id_usuario, u.email, u.activo, u.nombre_completo,
                   tu.nombre AS rol,
                   c.password_hash
            FROM usuario u
            JOIN credencial c    ON c.id_usuario = u.id_usuario
            JOIN tipo_usuario tu ON tu.id_tipo_usuario = u.id_tipo_usuario
            WHERE u.email = ? AND tu.nombre = ? AND u.activo = 1
            LIMIT 1
        """, (email, role))
        user = cur.fetchone()

        if not user or not contraseña_valida(user["password_hash"], password):
            con.close()
            flash("Credenciales incorrectas o rol inválido.")
            return render_template("login.html", role=role)

        # Actualiza último login si tienes la columna
        try:
            cur.execute(
                "UPDATE credencial SET ultimo_login=CURRENT_TIMESTAMP WHERE id_usuario=?",
                (user["id_usuario"],)
            )
            con.commit()
        except Exception:
            pass
        finally:
            con.close()

        # Guarda sesión y redirige al portal
        session["user_id"] = user["id_usuario"]
        session["email"]   = user["email"]
        session["role"]    = user["rol"]                 # 'mecanico' / 'conductor' / 'administrador' / 'seguridad'
        session["name"]    = user["nombre_completo"]

        return redirect(url_for("portal"))

    # GET
    return render_template("login.html", role=role)

@app.route("/portal")
@login_required
def portal():
    # Portal común después de iniciar sesión
    return render_template(
        "portal.html",           # asegúrate de tener este template
        name=session.get("name"),
        role=session.get("role")
    )

# ====== RUTAS DEL PORTAL (stubs para que no falle url_for en portal.html) ======
@app.route("/agenda")
@login_required
def agenda():
    return "Agenda móvil (en construcción)"

@app.route("/estado-vehiculos")
@login_required
def estado_vehiculos():
    return "Actualizar estado de vehículos (en construcción)"

@app.route("/seguimiento")
@login_required
def seguimiento():
    return "Seguimiento de vehículos (en construcción)"

@app.route("/contactar-chofer")
@login_required
def contactar_chofer():
    return "Contactar chofer (en construcción)"

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))

# ---- Dashboards por rol (placeholders, si los necesitas) ----
@app.route("/mecanico")
@require_role("mecanico")
def dashboard_mecanico():
    return "Panel MECÁNICO"

@app.route("/conductor")
@require_role("conductor")
def dashboard_conductor():
    return "Panel CONDUCTOR"

@app.route("/administrador")
@require_role("administrador")
def dashboard_administrador():
    return "Panel ADMINISTRADOR"

@app.route("/seguridad")
@require_role("seguridad")
def dashboard_seguridad():
    return "Panel SEGURIDAD"

# ---- Ruta de prueba rápida ----
@app.route("/ping")
def ping():
    ok = os.path.exists(DB_PATH)
    return {"status": "ok", "db_exists": ok, "db_path": DB_PATH}

# ------------------ Main ------------------
if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print("⚠ No se encontró pepsi.db en:", DB_PATH)
    app.run(debug=True)

