from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from functools import wraps
import pymysql
import hashlib
import os
import secrets
import bcrypt
import hmac as _hmac
import base64
import requests
from datetime import timedelta, datetime
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()  # Carga variables desde .env si existe

app = Flask(__name__)

# ── Rate Limiter global ───────────────────────────────────────────────────────
# Usa memoria en desarrollo; en producción cambiar a redis://...
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],          # Sin límite global — solo en rutas específicas
    storage_uri='memory://',
)

# ── CSRF: token por sesión ────────────────────────────────────────────────────
# El token se genera al iniciar sesión y el frontend lo envía en cada POST/PUT
# como header X-CSRF-Token. El login queda exento (aún no hay sesión).

def get_csrf_token():
    """Devuelve el token CSRF de la sesión, creándolo si no existe."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def csrf_protect(f):
    """Decorador que valida X-CSRF-Token en rutas protegidas POST/PUT/DELETE."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ('POST', 'PUT', 'DELETE'):
            token_enviado   = request.headers.get('X-CSRF-Token', '')
            token_sesion    = session.get('csrf_token', '')
            if not token_sesion or not secrets.compare_digest(token_enviado, token_sesion):
                registrar_log('seguridad', 'csrf_invalido', 'denegado',
                              {'ruta': request.path, 'method': request.method})
                return jsonify(success=False, message='Token de seguridad inválido. Recarga la página.'), 403
        return f(*args, **kwargs)
    return decorated

# ── Inyectar csrf_token en todos los templates ────────────────────────────────
@app.context_processor
def inject_csrf():
    """Disponible como {{ csrf_token() }} en cualquier template."""
    return dict(csrf_token=get_csrf_token)

# ── Headers de seguridad ──────────────────────────────────────────────────────
# Se aplican a TODAS las respuestas. HSTS solo se activa con HTTPS real.
@app.after_request
def set_security_headers(response):
    # Evita que la app se incruste en iframes de otros dominios (clickjacking)
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Evita que el navegador adivine el tipo MIME (MIME sniffing)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Fuerza HTTPS durante 1 año — solo activo si la conexión ya es HTTPS
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Política de contenido: solo recursos del propio dominio + CDNs usadas
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https://tile.openstreetmap.org https://*.tile.openstreetmap.org; "
        "connect-src 'self'; "
        "frame-src 'self' https://www.openstreetmap.org; "
        "frame-ancestors 'self';"
    )
    # No enviar Referer a sitios externos
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    # Bloquear acceso a cámara, micrófono, geolocalización
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response

# ── Clave secreta desde .env (nunca hardcodeada en producción) ───────────────
# Genera una con: python -c "import secrets; print(secrets.token_hex(32))"
_secret = os.environ.get('SECRET_KEY', '')
if not _secret or len(_secret) < 32:
    import warnings
    warnings.warn(
        "SECRET_KEY no configurada o muy corta. "
        "Agrega SECRET_KEY=<32+ bytes hex> en tu archivo .env",
        stacklevel=2
    )
    _secret = 'fandrade.8041_CAMBIA_ESTO_EN_PRODUCCION_usa_32_bytes_minimo'
app.secret_key = _secret

# ── Sesión: 30 minutos de inactividad ────────────────────────────────────────
# ── Sesión: timeout configurable desde .env (default 30 min) ─────────────────
_session_timeout = int(os.environ.get('SESSION_TIMEOUT_MINUTES', 30))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=_session_timeout)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE']  = os.environ.get('HTTPS', 'false').lower() == 'true'

# ── Conexión a MySQL / phpMyAdmin ─────────────────────────────────────────────
DB_CONFIG = {
    'host':     os.environ.get('MYSQL_HOST',     os.environ.get('MYSQLHOST',     'localhost')),
    'port':     int(os.environ.get('MYSQL_PORT', os.environ.get('MYSQLPORT',     3306))),
    'user':     os.environ.get('MYSQL_USER',     os.environ.get('MYSQLUSER',     'root')),
    'password': os.environ.get('MYSQL_PASSWORD', os.environ.get('MYSQLPASSWORD', '')),
    'database': os.environ.get('MYSQL_DATABASE', os.environ.get('MYSQLDATABASE', 'arepazo_db')),
    'cursorclass': pymysql.cursors.DictCursor,
    'charset':  'utf8mb4',
}

def get_db():
    return pymysql.connect(**DB_CONFIG)

# ── Sanitización de inputs ────────────────────────────────────────────────────
# Limpia texto libre eliminando caracteres de control y limitando longitud.
# NO reemplaza el uso de parámetros preparados en SQL — los complementa.

_CTRL_CHARS = dict.fromkeys(range(32), None)   # caracteres de control ASCII

def sanitizar(valor, max_len=255):
    """Limpia un string: elimina chars de control, recorta a max_len."""
    if not isinstance(valor, str):
        return ''
    return valor.strip().translate(_CTRL_CHARS)[:max_len]

def safe_int(valor, default=0, min_val=None, max_val=None):
    """Convierte a int de forma segura; retorna default si falla."""
    try:
        result = int(valor)
        if min_val is not None and result < min_val:
            return default
        if max_val is not None and result > max_val:
            return default
        return result
    except (TypeError, ValueError):
        return default

def safe_float(valor, default=0.0, min_val=None, max_val=None):
    """Convierte a float de forma segura; retorna default si falla."""
    try:
        result = float(valor)
        if min_val is not None and result < min_val:
            return default
        if max_val is not None and result > max_val:
            return default
        return result
    except (TypeError, ValueError):
        return default

# ── Ítem 69 — Cifrado AES-256-GCM para datos personales ─────────────────────
# Cifra direccion y nombre_cliente en la tabla ordenes.
# Los valores cifrados tienen el prefijo "enc:" para detectar migración lazy.
# Si ENCRYPTION_KEY no está configurada, los datos se guardan en texto plano
# con una advertencia (para no romper el sistema en desarrollo sin la variable).

def _get_enc_key() -> bytes:
    """Lee y valida la clave AES-256 del entorno (32 bytes = 64 hex chars)."""
    hex_key = os.environ.get('ENCRYPTION_KEY', '')
    if len(hex_key) == 64:
        try:
            return bytes.fromhex(hex_key)
        except ValueError:
            pass
    return b''  # Clave inválida → modo sin cifrado

def encrypt_field(value: str) -> str:
    """Cifra un campo con AES-256-GCM. Retorna 'enc:<base64>' o el valor original si no hay clave."""
    if not value:
        return value
    key = _get_enc_key()
    if not key:
        return value  # Sin clave → texto plano (modo desarrollo)
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce      = os.urandom(12)                        # 96 bits para GCM
        ciphertext = AESGCM(key).encrypt(nonce, value.encode('utf-8'), None)
        return 'enc:' + base64.b64encode(nonce + ciphertext).decode('utf-8')
    except Exception:
        return value  # Si falla el cifrado, guardar en texto plano

def decrypt_field(value: str) -> str:
    """Descifra un campo 'enc:<base64>'. Si es texto plano, lo devuelve tal cual (migración lazy)."""
    if not value or not value.startswith('enc:'):
        return value  # Texto plano legacy o None
    key = _get_enc_key()
    if not key:
        return value  # Sin clave → devolver tal cual
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        raw        = base64.b64decode(value[4:])
        nonce, ct  = raw[:12], raw[12:]
        return AESGCM(key).decrypt(nonce, ct, None).decode('utf-8')
    except Exception:
        return value  # Si falla el descifrado, devolver el valor sin procesar

# ── Ítem 70 — HMAC para firmar SQL generado por el Chat IA ───────────────────
# Flujo: Claude genera SQL → backend firma con HMAC → devuelve SQL + firma
# al frontend → frontend envía SQL + firma al ejecutar → backend verifica
# que el SQL no fue modificado entre generación y ejecución.

def _get_hmac_secret() -> bytes:
    """Lee la clave HMAC del entorno."""
    hex_key = os.environ.get('HMAC_SECRET', '')
    if len(hex_key) >= 32:
        try:
            return bytes.fromhex(hex_key) if len(hex_key) == 64 else hex_key.encode()
        except ValueError:
            return hex_key.encode()
    # Fallback en desarrollo: usar SECRET_KEY + sufijo fijo
    return (os.environ.get('SECRET_KEY', 'dev') + '_hmac_sql').encode()

def firmar_sql(sql: str) -> str:
    """Genera firma HMAC-SHA256 del SQL."""
    return _hmac.new(_get_hmac_secret(), sql.encode('utf-8'), 'sha256').hexdigest()

def verificar_firma_sql(sql: str, firma: str) -> bool:
    """Verifica que el SQL no fue modificado desde que se generó."""
    if not firma:
        return False
    esperada = firmar_sql(sql)
    return _hmac.compare_digest(esperada, firma)

# ── Auditoría ─────────────────────────────────────────────────────────────────
import json as _json_audit

def registrar_log(modulo, accion, resultado='ok', detalle=None):
    """
    Registra una acción en audit_log.
    - Nunca lanza excepción (no debe bloquear la operación principal).
    - Nunca guarda contraseñas (responsabilidad del llamador no incluirlas).
    """
    try:
        uid      = session.get('user_id')
        uname    = session.get('username', 'anónimo')
        rol      = session.get('role', '')
        ip       = request.headers.get('X-Forwarded-For', request.remote_addr or '')
        ip       = ip.split(',')[0].strip()[:45]   # primer IP si hay proxy

        detalle_json = None
        if detalle:
            # Nunca guardar contraseñas aunque el llamador las incluya
            if isinstance(detalle, dict):
                detalle = {k: v for k, v in detalle.items()
                           if k.lower() not in ('password', 'contraseña', 'password_hash', 'clave')}
            detalle_json = _json_audit.dumps(detalle, ensure_ascii=False, default=str)

        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                """INSERT INTO audit_log
                   (usuario_id, username, rol, ip, modulo, accion, detalle, resultado)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (uid, uname, rol, ip, modulo, accion, detalle_json, resultado)
            )
        db.commit()
        db.close()
    except Exception:
        pass  # El log nunca debe romper la operación principal

# ── Configuración del sistema ─────────────────────────────────────────────────
def get_config(clave: str, default: str = '') -> str:
    """Lee un valor de la tabla configuracion. Devuelve default si no existe."""
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT valor FROM configuracion WHERE clave=%s", (clave,))
            row = cur.fetchone()
        db.close()
        return row['valor'] if row else default
    except Exception:
        return default

def set_config(clave: str, valor: str) -> bool:
    """Guarda o actualiza un valor en la tabla configuracion."""
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO configuracion (clave, valor) VALUES (%s,%s) "
                "ON DUPLICATE KEY UPDATE valor=%s",
                (clave, valor, valor)
            )
        db.commit()
        db.close()
        return True
    except Exception:
        return False

# ── Claude API (Anthropic) ────────────────────────────────────────────────────
# Motor de IA para el Chat IA del restaurante.
# Configura tu API key en una variable de entorno o directamente aquí.
# ── Claude API (Anthropic) ────────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
CLAUDE_MODEL    = 'claude-haiku-4-5-20251001'  # Haiku: 20x más barato que Sonnet
CLAUDE_API_URL  = 'https://api.anthropic.com/v1/messages'

# Ítem 41 — umbral de alerta de diferencia de caja (en pesos)
CAJA_UMBRAL_DIFERENCIA = safe_int(os.environ.get('CAJA_UMBRAL_DIFERENCIA', 5000), default=5000, min_val=0)

# ── Sesiones revocadas (usuarios deshabilitados) ─────────────────────────────
# Set en memoria: guarda user_id de usuarios deshabilitados.
# Al hacer login la sesión se limpia, así que es suficiente para entornos de 1 proceso.
_sesiones_revocadas = set()

# ── Decorador: rutas protegidas ───────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login_page'))
        # Verificar si el usuario fue deshabilitado en esta sesión
        if session.get('user_id') in _sesiones_revocadas:
            session.clear()
            return redirect(url_for('login_page'))
        # Forzar cambio de contraseña si viene de recuperación con código de emergencia
        if session.get('must_change_password') and request.endpoint != 'cambiar_password_page':
            return redirect(url_for('cambiar_password_page'))
        session.modified = True
        return f(*args, **kwargs)
    return decorated

# ── Hashing de contraseñas ────────────────────────────────────────────────────
# SISTEMA DUAL: acepta hashes viejos (sha256) y nuevos (bcrypt).
# Al hacer login exitoso con hash viejo, lo migra a bcrypt automáticamente.

def _hash_sha256_legacy(password: str) -> str:
    """Hash viejo — solo para verificar usuarios pre-V11. NO usar para nuevos."""
    salt = 'fandrade.8041'[:16]   # salt original fijo de V1–V10
    return hashlib.sha256((salt + password).encode()).hexdigest()

def hash_password_bcrypt(password: str) -> str:
    """Genera un hash bcrypt nuevo (rounds=12). Usar para crear/cambiar contraseñas."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')

def verificar_password(password: str, stored_hash: str, hash_type: str) -> bool:
    """Verifica la contraseña contra el hash, sea sha256 o bcrypt."""
    try:
        if hash_type == 'bcrypt':
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
        else:  # sha256 legacy
            return _hash_sha256_legacy(password) == stored_hash
    except Exception:
        return False

# Alias para compatibilidad: nuevos usuarios siempre usan bcrypt
def hash_password(password: str) -> str:
    return hash_password_bcrypt(password)

# ═══════════════════════════════════════════════════════════════════════════════
#  RUTAS PÚBLICAS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET'])
def login_page():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
@limiter.limit('5 per 10 minutes', error_message='Demasiados intentos. Espera 10 minutos.')
def login_post():
    data = request.get_json(silent=True) or request.form
    username = sanitizar(data.get('username') or '', max_len=64)
    password = (data.get('password') or '').strip()

    if not username or not password:
        return jsonify(success=False, message='Completa todos los campos.'), 400

    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                """SELECT id, username, password_hash, hash_type, role,
                          intentos_fallidos, bloqueado_hasta
                   FROM usuarios WHERE username = %s LIMIT 1""",
                (username,)
            )
            user = cur.fetchone()
        db.close()
    except Exception as e:
        return jsonify(success=False, message='Error de conexión con la base de datos.'), 500

    # ── Verificar si la cuenta está bloqueada ─────────────────────────────────
    if user and user.get('bloqueado_hasta'):
        ahora = datetime.now()
        if user['bloqueado_hasta'] > ahora:
            minutos = int((user['bloqueado_hasta'] - ahora).seconds / 60) + 1
            return jsonify(
                success=False,
                message=f'Cuenta bloqueada. Intenta de nuevo en {minutos} minuto(s).'
            ), 429

    hash_type = (user.get('hash_type') or 'sha256') if user else 'sha256'

    if user and verificar_password(password, user['password_hash'], hash_type):
        # ── Login exitoso: resetear contadores ────────────────────────────────
        try:
            db2 = get_db()
            with db2.cursor() as cur2:
                cur2.execute(
                    "UPDATE usuarios SET intentos_fallidos=0, bloqueado_hasta=NULL WHERE id=%s",
                    (user['id'],)
                )
                if hash_type != 'bcrypt':
                    nuevo_hash = hash_password_bcrypt(password)
                    cur2.execute(
                        "UPDATE usuarios SET password_hash=%s, hash_type='bcrypt' WHERE id=%s",
                        (nuevo_hash, user['id'])
                    )
            db2.commit()
            db2.close()
        except Exception:
            pass

        # ── Ítem 78 — Si tiene TOTP activo, pedir el código antes de dar sesión
        try:
            db_t = get_db()
            with db_t.cursor() as cur_t:
                cur_t.execute("SELECT totp_activo, totp_secret FROM usuarios WHERE id=%s", (user['id'],))
                totp_row = cur_t.fetchone()
            db_t.close()
        except Exception:
            totp_row = None

        if totp_row and totp_row.get('totp_activo') and totp_row.get('totp_secret'):
            # Guardar datos de login pendiente en sesión (sin dar acceso completo)
            session['totp_pending_id']       = user['id']
            session['totp_pending_username'] = user['username']
            session['totp_pending_role']     = user['role']
            session['totp_pending_recordar'] = bool(data.get('recordar')) and user['role'] == 'admin'
            registrar_log('login', 'totp_requerido', 'ok', {'username': username})
            return jsonify(success=True, totp_required=True)

        # Ítem 65 — recordar sesión: admin puede pedir 30 días, resto 30 min
        recordar = bool(data.get('recordar')) and user['role'] == 'admin'
        session.permanent = True
        if recordar:
            from flask import current_app
            current_app.permanent_session_lifetime = timedelta(days=30)
        session['user_id']  = user['id']
        session['username'] = user['username']
        session['role']     = user['role']
        session['recordar'] = recordar
        # Ítem 43 — registrar último login
        try:
            db_ul = get_db()
            with db_ul.cursor() as cur_ul:
                cur_ul.execute("UPDATE usuarios SET ultimo_login=NOW() WHERE id=%s", (user['id'],))
            db_ul.commit()
            db_ul.close()
        except Exception:
            pass
        registrar_log('login', 'login_ok', 'ok', {'role': user['role']})
        # Redirigir según rol
        _role = user['role']
        if _role == 'cocina':
            _redirect = url_for('vista_cocina')
        elif _role == 'repartidor':
            _redirect = url_for('vista_repartidor')
        elif _role in ('cajero', 'mesero'):
            _redirect = url_for('dashboard_nueva_orden')
        else:
            _redirect = url_for('dashboard')
        return jsonify(success=True, redirect=_redirect)

    else:
        # ── Login fallido: incrementar contador y bloquear si llega a 5 ──────
        if user:
            try:
                nuevos_intentos = int(user.get('intentos_fallidos') or 0) + 1
                bloqueo = None
                if nuevos_intentos >= 5:
                    bloqueo = datetime.now() + timedelta(minutes=10)
                    nuevos_intentos = 0  # Resetear para el próximo ciclo
                db3 = get_db()
                with db3.cursor() as cur3:
                    cur3.execute(
                        "UPDATE usuarios SET intentos_fallidos=%s, bloqueado_hasta=%s WHERE id=%s",
                        (nuevos_intentos, bloqueo, user['id'])
                    )
                db3.commit()
                db3.close()
                if bloqueo:
                    registrar_log('login', 'cuenta_bloqueada', 'error', {'username': username})
                    return jsonify(
                        success=False,
                        message='Cuenta bloqueada por 10 minutos tras 5 intentos fallidos.'
                    ), 429
                else:
                    registrar_log('login', 'login_fallido', 'error', {'username': username, 'intentos': nuevos_intentos})
            except Exception:
                pass
        else:
            registrar_log('login', 'login_fallido', 'error', {'username': username})

        return jsonify(success=False, message='Usuario o contraseña incorrectos.'), 401

@app.route('/logout')
def logout():
    registrar_log('login', 'logout', 'ok')
    session.clear()
    return redirect(url_for('index'))

@app.route('/api/csrf-token', methods=['GET'])
@login_required
def api_csrf_token():
    """El frontend llama esto al cargar el dashboard para obtener el token."""
    return jsonify(csrf_token=get_csrf_token())

# ═══════════════════════════════════════════════════════════════════════════════
#  DASHBOARD (protegido)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/dashboard')
@login_required
def dashboard():
    return redirect(url_for('dashboard_chat_ia'))



@app.route('/dashboard/configuracion')
@login_required
def dashboard_configuracion():
    return render_template('dashboard.html', section='configuracion')

# ═══════════════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
#  MÓDULO DE ÓRDENES  — agregar en app.py
#  Pegar ANTES de:  
@app.route('/api/productos/<int:pid>/imagen', methods=['POST'])
@login_required
def api_subir_imagen_producto(pid):
    """Sube o reemplaza la imagen de un producto."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    if 'imagen' not in request.files:
        return jsonify(success=False, message='No se recibió imagen.'), 400
    f = request.files['imagen']
    if not f or not f.filename:
        return jsonify(success=False, message='Archivo vacío.'), 400
    ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
    if ext not in ('jpg','jpeg','png','webp'):
        return jsonify(success=False, message='Solo JPG, PNG o WEBP.'), 400
    filename  = f'producto_{pid}.{ext}'
    save_dir  = os.path.join(os.path.dirname(__file__), 'static', 'img', 'arepas')
    os.makedirs(save_dir, exist_ok=True)
    f.save(os.path.join(save_dir, filename))
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("UPDATE productos SET imagen=%s WHERE id=%s", (filename, pid))
        db.commit(); db.close()
        return jsonify(success=True, imagen=filename, url=f'/static/img/arepas/{filename}')
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

# ═══════════════════════════════════════════════════════════════════════════════

import json as _json


@app.route('/api/ordenes', methods=['POST'])
@login_required
@csrf_protect
def api_crear_orden():
    """Guarda una orden nueva. Nunca borra — solo marca activa=0 para anular."""
    data = request.get_json(silent=True) or {}

    tipo       = (data.get('tipo') or '').strip()          # 'domicilio' | 'mesa'
    items      = data.get('items', [])                     # lista de dicts
    subtotal   = safe_int(data.get('subtotal', 0), min_val=0)
    costo_dom  = safe_int(data.get('costo_domicilio', 0), min_val=0)
    total      = safe_int(data.get('total', 0), min_val=0)
    direccion  = sanitizar(data.get('direccion') or '', max_len=200) or None
    nombre     = sanitizar(data.get('nombre_cliente') or '', max_len=100) or None
    forma_pago = sanitizar(data.get('forma_pago') or 'efectivo', max_len=20)

    # Validar que la caja esté abierta antes de crear una orden
    try:
        _db = get_db()
        with _db.cursor() as _cur:
            _cur.execute("SELECT id FROM caja WHERE fecha=CURDATE() AND estado='abierta' LIMIT 1")
            _caja = _cur.fetchone()
        _db.close()
        if not _caja:
            return jsonify(success=False,
                           message='⚠️ No hay caja abierta. Abre la caja antes de crear órdenes.'), 400
    except Exception:
        pass  # Si falla la consulta de caja, permitir continuar

    # Ítem 69 — cifrar datos personales antes de guardar
    if direccion: direccion = encrypt_field(direccion)
    if nombre:    nombre    = encrypt_field(nombre)

    FORMAS_PAGO_VALIDAS = ('efectivo', 'nequi', 'daviplata')
    if forma_pago not in FORMAS_PAGO_VALIDAS:
        forma_pago = 'efectivo'

    if tipo not in ('domicilio', 'mesa') or not items:
        return jsonify(success=False, message='Datos incompletos.'), 400

    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                """INSERT INTO ordenes
                   (tipo, direccion, nombre_cliente, costo_domicilio,
                    items, subtotal, total, forma_pago, activa, created_by)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 1, %s)""",
                (tipo, direccion, nombre, costo_dom,
                 _json.dumps(items, ensure_ascii=False),
                 subtotal, total, forma_pago, session['user_id'])
            )
            oid = cur.lastrowid
            # ── Descontar stock automáticamente ──────────────────────────────
            try:
                descontar_stock_orden(items, oid, db)
            except Exception:
                pass  # No bloquear la orden si falla el descuento
        db.commit()
        db.close()
        registrar_log('ordenes', 'crear_orden', 'ok', {'orden_id': oid, 'tipo': tipo, 'total': total})
        return jsonify(success=True, orden_id=oid, total=total)
    except Exception as e:
        registrar_log('ordenes', 'crear_orden', 'error', {'error': str(e)})
        return jsonify(success=False, message=str(e)), 500


@app.route('/api/ordenes', methods=['GET'])
@login_required
def api_listar_ordenes():
    """Devuelve órdenes activas del día. Mesero solo ve las propias (ítem 36)."""
    try:
        db = get_db()
        with db.cursor() as cur:
            role = session.get('role', '')
            if role == 'mesero':
                # Ítem 36 — mesero solo ve órdenes que él creó
                cur.execute(
                    """SELECT id, tipo, direccion, nombre_cliente,
                              costo_domicilio, items, subtotal, total, created_at
                       FROM ordenes
                       WHERE activa = 1
                         AND DATE(created_at) = CURDATE()
                         AND created_by = %s
                       ORDER BY id DESC""",
                    (session['user_id'],)
                )
            else:
                cur.execute(
                    """SELECT id, tipo, direccion, nombre_cliente,
                              costo_domicilio, items, subtotal, total, created_at
                       FROM ordenes
                       WHERE activa = 1
                         AND DATE(created_at) = CURDATE()
                       ORDER BY id DESC""",
                )
            rows = cur.fetchall()
        db.close()
        for r in rows:
            r['items']      = _json.loads(r['items'])
            r['created_at'] = r['created_at'].strftime('%H:%M')
        return jsonify(success=True, ordenes=rows)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500


@app.route('/api/ordenes/<int:oid>/anular', methods=['POST'])
@login_required
@csrf_protect
def api_anular_orden(oid):
    """Marca una orden como inactiva (no la borra físicamente)."""
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("UPDATE ordenes SET activa=0 WHERE id=%s", (oid,))
        db.commit()
        db.close()
        registrar_log('ordenes', 'anular_orden', 'ok', {'orden_id': oid})
        return jsonify(success=True)
    except Exception as e:
        registrar_log('ordenes', 'anular_orden', 'error', {'orden_id': oid, 'error': str(e)})
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/ordenes/<int:oid>', methods=['PUT'])
@login_required
@csrf_protect
def api_editar_orden(oid):
    """Actualiza items, tipo y datos de una orden existente."""
    data = request.get_json(silent=True) or {}
    tipo      = (data.get('tipo') or '').strip()
    items     = data.get('items', [])
    subtotal  = safe_int(data.get('subtotal', 0), min_val=0)
    costo_dom = safe_int(data.get('costo_domicilio', 0), min_val=0)
    total     = safe_int(data.get('total', 0), min_val=0)
    direccion = sanitizar(data.get('direccion') or '', max_len=200) or None
    nombre    = sanitizar(data.get('nombre_cliente') or '', max_len=100) or None

    if tipo not in ('domicilio', 'mesa') or not items:
        return jsonify(success=False, message='Datos incompletos.'), 400
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                """UPDATE ordenes SET tipo=%s, items=%s, subtotal=%s,
                   costo_domicilio=%s, total=%s, direccion=%s, nombre_cliente=%s
                   WHERE id=%s AND activa=1""",
                (tipo, _json.dumps(items, ensure_ascii=False),
                 subtotal, costo_dom, total, direccion, nombre, oid)
            )
        db.commit()
        db.close()
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

# ═══════════════════════════════════════════════════════════════════════════════
#  MÓDULO DE PRODUCTOS — pegar en app.py antes de  if __name__ == '__main__':
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/dashboard/productos')
@login_required
def dashboard_productos():
    return render_template('dashboard.html', section='productos')


@app.route('/api/productos', methods=['GET'])
@login_required
def api_listar_productos():
    """Devuelve todos los productos. Marca sin_stock=True si algún insumo de su receta está agotado."""
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT * FROM productos ORDER BY categoria, orden, id")
            rows = cur.fetchall()

            # Productos sin stock: aquellos cuya receta tiene ≥1 insumo con stock ≤ 0
            try:
                cur.execute("""
                    SELECT DISTINCT r.producto_id
                    FROM recetas r
                    JOIN insumos i ON r.insumo_id = i.id
                    WHERE i.stock_actual <= 0
                """)
                sin_stock_ids = {row['producto_id'] for row in cur.fetchall()}
            except Exception:
                sin_stock_ids = set()

        db.close()
        for r in rows:
            if r.get('updated_at'):
                r['updated_at'] = r['updated_at'].strftime('%Y-%m-%d %H:%M')
            r['sin_stock'] = r['id'] in sin_stock_ids
        return jsonify(success=True, productos=rows)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500


@app.route('/api/productos', methods=['POST'])
@login_required
@csrf_protect
def api_crear_producto():
    """Crea un producto nuevo."""
    data = request.get_json(silent=True) or {}
    nombre    = sanitizar(data.get('nombre') or '', max_len=100)
    categoria = sanitizar(data.get('categoria') or '', max_len=50)
    desc      = sanitizar(data.get('descripcion') or '', max_len=300)
    precio    = safe_int(data.get('precio'), min_val=0)

    CATS = ('arepas', 'especiales', 'adicionales', 'bebidas')
    if not nombre or categoria not in CATS:
        return jsonify(success=False, message='Nombre y categoría válida son obligatorios.'), 400

    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT COALESCE(MAX(orden),0)+1 AS sig FROM productos WHERE categoria=%s",
                (categoria,)
            )
            sig = cur.fetchone()['sig']
            cur.execute(
                """INSERT INTO productos (categoria, nombre, descripcion, precio, disponible, orden)
                   VALUES (%s, %s, %s, %s, 1, %s)""",
                (categoria, nombre, desc, precio, sig)
            )
            nuevo_id = cur.lastrowid
        db.commit()
        db.close()
        return jsonify(success=True, id=nuevo_id)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500


@app.route('/api/productos/<int:pid>', methods=['PUT'])
@login_required
@csrf_protect
def api_editar_producto(pid):
    """Edita producto y registra auditoría con valores antes/después."""
    data = request.get_json(silent=True) or {}
    nombre    = (data.get('nombre') or '').strip()
    desc      = (data.get('descripcion') or '').strip()
    precio    = safe_int(data.get('precio'), min_val=0)
    disponible = 1 if data.get('disponible') else 0
    categoria  = (data.get('categoria') or '').strip()

    CATS = ('arepas', 'especiales', 'adicionales', 'bebidas')
    if not nombre or categoria not in CATS:
        return jsonify(success=False, message='Datos inválidos.'), 400

    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT nombre, precio, disponible, categoria FROM productos WHERE id=%s", (pid,))
            antes = cur.fetchone() or {}
            cur.execute(
                """UPDATE productos SET nombre=%s, descripcion=%s, precio=%s,
                   disponible=%s, categoria=%s WHERE id=%s""",
                (nombre, desc, precio, disponible, categoria, pid)
            )
        db.commit()
        db.close()
        cambios = {}
        if antes.get('nombre')     != nombre:     cambios['nombre']     = {'antes': antes.get('nombre'),     'despues': nombre}
        if int(antes.get('precio',0)) != precio:  cambios['precio']     = {'antes': int(antes.get('precio',0)), 'despues': precio}
        if int(antes.get('disponible',0)) != disponible: cambios['disponible'] = {'antes': bool(antes.get('disponible')), 'despues': bool(disponible)}
        if antes.get('categoria')  != categoria:  cambios['categoria']  = {'antes': antes.get('categoria'),  'despues': categoria}
        registrar_log('productos', 'editar_producto', 'ok', {'producto_id': pid, 'nombre': nombre, 'cambios': cambios})
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500


@app.route('/api/productos/<int:pid>/toggle', methods=['POST'])
@login_required
@csrf_protect
def api_toggle_producto(pid):
    """Alterna disponible. Al habilitar, verifica que todos los insumos de la receta tengan stock > 0."""
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT disponible FROM productos WHERE id=%s", (pid,))
            row = cur.fetchone()
            if not row:
                db.close()
                return jsonify(success=False, message='Producto no encontrado.'), 404

            estado_actual = row['disponible']
            nuevo = 1 - estado_actual

            # Si va a habilitarse, verificar que todos los insumos de la receta tengan stock > 0
            if nuevo == 1:
                try:
                    cur.execute("""
                        SELECT i.nombre, i.stock_actual
                        FROM recetas r
                        JOIN insumos i ON r.insumo_id = i.id
                        WHERE r.producto_id = %s AND i.stock_actual <= 0
                    """, (pid,))
                    sin_stock = cur.fetchall()
                    if sin_stock:
                        nombres = ', '.join(r['nombre'] for r in sin_stock)
                        db.close()
                        return jsonify(
                            success=False,
                            message=f'No se puede habilitar: sin stock de → {nombres}'
                        ), 400
                except Exception:
                    pass  # Si recetas no existe aún, permitir el toggle

            cur.execute("UPDATE productos SET disponible=%s WHERE id=%s", (nuevo, pid))
        cur.execute("SELECT nombre FROM productos WHERE id=%s", (pid,))
        prod = cur.fetchone()
        db.commit()
        db.close()
        registrar_log('productos', 'toggle_disponible', 'ok',
                      {'producto_id': pid, 'nombre': prod['nombre'] if prod else pid,
                       'antes': bool(not nuevo), 'despues': bool(nuevo)})
        return jsonify(success=True, disponible=nuevo)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

# ═══════════════════════════════════════════════════════════════════════════════
#  MÓDULO DE STOCK — pegar en app.py antes de  if __name__ == '__main__':
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/dashboard/stock')
@login_required
def dashboard_stock():
    return render_template('dashboard.html', section='stock')



# ═══════════════════════════════════════════════════════════════════════════════
#  RECETAS — qué insumos usa cada producto
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/api/recetas/<int:producto_id>', methods=['GET'])
@login_required
def api_get_receta(producto_id):
    """Devuelve la receta de un producto con nombres de insumos."""
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("""
                SELECT r.id, r.insumo_id, r.cantidad, i.nombre, i.unidad, i.stock_actual
                FROM recetas r JOIN insumos i ON r.insumo_id=i.id
                WHERE r.producto_id=%s ORDER BY i.nombre
            """, (producto_id,))
            receta = cur.fetchall()
            # Todos los insumos disponibles para el selector
            cur.execute("SELECT id, nombre, unidad, stock_actual FROM insumos WHERE activo=1 ORDER BY nombre")
            todos = cur.fetchall()
        db.close()
        for r in receta:
            r['stock_actual'] = float(r['stock_actual'])
            r['cantidad']     = float(r['cantidad'])
        for i in todos:
            i['stock_actual'] = float(i['stock_actual'])
        return jsonify(success=True, receta=receta, insumos=todos)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/recetas/<int:producto_id>', methods=['POST'])
@login_required
@csrf_protect
def api_guardar_receta(producto_id):
    """Guarda la receta completa de un producto (reemplaza la anterior)."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    data       = request.get_json(silent=True) or {}
    ingredientes = data.get('ingredientes', [])   # [{insumo_id, cantidad}]
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM recetas WHERE producto_id=%s", (producto_id,))
            for ing in ingredientes:
                iid  = int(ing.get('insumo_id', 0))
                cant = float(ing.get('cantidad', 0))
                if iid > 0 and cant > 0:
                    cur.execute(
                        "INSERT INTO recetas (producto_id, insumo_id, cantidad) VALUES (%s,%s,%s)",
                        (producto_id, iid, cant)
                    )
        db.commit(); db.close()
        registrar_log('recetas', 'guardar', 'ok', {
            'producto_id': producto_id,
            'ingredientes': len(ingredientes),
            'lista': [{'insumo_id': i.get('insumo_id'), 'cantidad': i.get('cantidad')} for i in ingredientes[:10]]
        })
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/stock/movimientos', methods=['GET'])
@login_required
def api_stock_movimientos():
    """Historial de movimientos de stock."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    insumo_id = request.args.get('insumo_id')
    limit     = min(100, int(request.args.get('limit', 50)))
    try:
        db = get_db()
        with db.cursor() as cur:
            if insumo_id:
                cur.execute("""
                    SELECT m.*, i.nombre AS insumo_nombre, i.unidad
                    FROM movimientos_stock m JOIN insumos i ON m.insumo_id=i.id
                    WHERE m.insumo_id=%s ORDER BY m.id DESC LIMIT %s
                """, (insumo_id, limit))
            else:
                cur.execute("""
                    SELECT m.*, i.nombre AS insumo_nombre, i.unidad
                    FROM movimientos_stock m JOIN insumos i ON m.insumo_id=i.id
                    ORDER BY m.id DESC LIMIT %s
                """, (limit,))
            movs = cur.fetchall()
        db.close()
        for m in movs:
            m['created_at']    = m['created_at'].strftime('%Y-%m-%d %H:%M')
            m['cantidad']      = float(m['cantidad'])
            m['stock_antes']   = float(m['stock_antes'])
            m['stock_despues'] = float(m['stock_despues'])
        return jsonify(success=True, movimientos=movs)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

# ── Insumos ──────────────────────────────────────────────────────────────────

@app.route('/api/insumos', methods=['GET'])
@login_required
def api_listar_insumos():
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT * FROM insumos ORDER BY categoria, nombre")
            rows = cur.fetchall()
        db.close()
        from datetime import date
        hoy = date.today()
        for r in rows:
            r['stock_actual'] = float(r['stock_actual'])
            r['stock_minimo'] = float(r['stock_minimo'])
            if r.get('updated_at'):
                r['updated_at'] = r['updated_at'].strftime('%Y-%m-%d %H:%M')
            # Calcular días para vencer
            fv = r.get('fecha_vencimiento')
            if fv:
                r['fecha_vencimiento'] = fv.strftime('%Y-%m-%d') if hasattr(fv,'strftime') else str(fv)
                try:
                    fv_date = fv if isinstance(fv, date) else date.fromisoformat(str(fv))
                    r['dias_para_vencer'] = (fv_date - hoy).days
                except Exception:
                    r['dias_para_vencer'] = None
            else:
                r['dias_para_vencer'] = None
        return jsonify(success=True, insumos=rows)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500


@app.route('/api/insumos', methods=['POST'])
@login_required
@csrf_protect
def api_crear_insumo():
    data = request.get_json(silent=True) or {}
    nombre     = sanitizar(data.get('nombre') or '', max_len=100)
    unidad     = sanitizar(data.get('unidad') or 'und', max_len=20)
    stock      = safe_float(data.get('stock_actual'), min_val=0)
    minimo     = safe_float(data.get('stock_minimo'), min_val=0)
    costo      = safe_int(data.get('costo_unitario'), min_val=0)
    categoria  = sanitizar(data.get('categoria') or 'cocina', max_len=50)
    fecha_venc = (data.get('fecha_vencimiento') or '').strip() or None
    dias_alerta= safe_int(data.get('dias_alerta_vencimiento'), default=7, min_val=1, max_val=365)
    if not nombre:
        return jsonify(success=False, message='El nombre es obligatorio.'), 400
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                """INSERT INTO insumos (nombre,unidad,stock_actual,stock_minimo,costo_unitario,categoria,fecha_vencimiento,dias_alerta_vencimiento)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                (nombre, unidad, stock, minimo, costo, categoria, fecha_venc, dias_alerta)
            )
            nid = cur.lastrowid
        db.commit()
        db.close()
        return jsonify(success=True, id=nid)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500


@app.route('/api/insumos/<int:iid>', methods=['PUT'])
@login_required
@csrf_protect
def api_editar_insumo(iid):
    data = request.get_json(silent=True) or {}
    nombre     = (data.get('nombre') or '').strip()
    unidad     = (data.get('unidad') or 'und').strip()
    minimo     = safe_float(data.get('stock_minimo'), min_val=0)
    costo      = safe_int(data.get('costo_unitario'), min_val=0)
    categoria  = (data.get('categoria') or 'cocina').strip()
    activo     = 1 if data.get('activo') else 0
    fecha_venc = (data.get('fecha_vencimiento') or '').strip() or None
    dias_alerta= int(data.get('dias_alerta_vencimiento') or 7)
    if not nombre:
        return jsonify(success=False, message='El nombre es obligatorio.'), 400
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT nombre, costo_unitario, stock_minimo, activo FROM insumos WHERE id=%s", (iid,))
            antes = cur.fetchone() or {}
            cur.execute(
                """UPDATE insumos SET nombre=%s,unidad=%s,stock_minimo=%s,
                   costo_unitario=%s,categoria=%s,activo=%s,
                   fecha_vencimiento=%s,dias_alerta_vencimiento=%s WHERE id=%s""",
                (nombre, unidad, minimo, costo, categoria, activo, fecha_venc, dias_alerta, iid)
            )
        db.commit()
        db.close()
        cambios = {}
        if antes.get('nombre') != nombre:                   cambios['nombre']  = {'antes': antes.get('nombre'),  'despues': nombre}
        if int(antes.get('costo_unitario',0)) != costo:     cambios['costo']   = {'antes': int(antes.get('costo_unitario',0)), 'despues': costo}
        if float(antes.get('stock_minimo',0)) != minimo:    cambios['minimo']  = {'antes': float(antes.get('stock_minimo',0)), 'despues': minimo}
        if int(antes.get('activo',1)) != activo:            cambios['activo']  = {'antes': bool(antes.get('activo')), 'despues': bool(activo)}
        registrar_log('stock', 'editar_insumo', 'ok', {'insumo_id': iid, 'nombre': nombre, 'cambios': cambios})
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500


# ── Movimientos ───────────────────────────────────────────────────────────────

@app.route('/api/stock/movimiento', methods=['POST'])
@login_required
@csrf_protect
def api_movimiento_stock():
    """Registra entrada, salida manual o ajuste de stock."""
    data      = request.get_json(silent=True) or {}
    insumo_id = safe_int(data.get('insumo_id'), min_val=1)
    tipo      = sanitizar(data.get('tipo') or '', max_len=20)   # entrada|salida_manual|ajuste
    cantidad  = safe_float(data.get('cantidad'))
    motivo    = sanitizar(data.get('motivo') or '', max_len=200)
    costo_u   = safe_int(data.get('costo_unitario'), min_val=0)

    TIPOS_VALIDOS = ('entrada', 'salida_manual', 'ajuste')
    if not insumo_id or tipo not in TIPOS_VALIDOS or cantidad == 0:
        return jsonify(success=False, message='Datos inválidos.'), 400

    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT stock_actual FROM insumos WHERE id=%s", (insumo_id,))
            row = cur.fetchone()
            if not row:
                return jsonify(success=False, message='Insumo no encontrado.'), 404
            stock_antes = float(row['stock_actual'])

            # Para ajuste: cantidad es el stock real nuevo, calculamos diferencia
            if tipo == 'ajuste':
                delta = cantidad - stock_antes
                stock_nuevo = cantidad
            elif tipo == 'entrada':
                delta = abs(cantidad)
                stock_nuevo = stock_antes + delta
            else:  # salida_manual
                delta = -abs(cantidad)
                stock_nuevo = max(0, stock_antes + delta)

            cur.execute(
                "UPDATE insumos SET stock_actual=%s WHERE id=%s",
                (round(stock_nuevo, 2), insumo_id)
            )
            cur.execute(
                """INSERT INTO movimientos_stock
                   (insumo_id,tipo,cantidad,stock_antes,stock_despues,motivo,costo_unitario,created_by)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                (insumo_id, tipo, round(delta, 2), stock_antes,
                 round(stock_nuevo, 2), motivo, costo_u, session['user_id'])
            )
        db.commit()
        db.close()
        registrar_log('stock', 'ajuste_manual', 'ok',
                      {'insumo_id': insumo_id, 'tipo': tipo, 'cantidad': delta, 'stock_nuevo': round(stock_nuevo,2)})
        return jsonify(success=True, stock_nuevo=round(stock_nuevo, 2))
    except Exception as e:
        registrar_log('stock', 'movimiento_stock', 'error', {'insumo_id': insumo_id, 'error': str(e)})
        return jsonify(success=False, message=str(e)), 500


@app.route('/api/stock/movimientos', methods=['GET'])
@login_required
def api_historial_movimientos():
    insumo_id = request.args.get('insumo_id')
    limite    = safe_int(request.args.get('limite'), default=50, min_val=1, max_val=200)
    try:
        db = get_db()
        with db.cursor() as cur:
            if insumo_id:
                cur.execute(
                    """SELECT m.*,i.nombre AS insumo_nombre,i.unidad
                       FROM movimientos_stock m JOIN insumos i ON m.insumo_id=i.id
                       WHERE m.insumo_id=%s ORDER BY m.created_at DESC LIMIT %s""",
                    (insumo_id, limite)
                )
            else:
                cur.execute(
                    """SELECT m.*,i.nombre AS insumo_nombre,i.unidad
                       FROM movimientos_stock m JOIN insumos i ON m.insumo_id=i.id
                       ORDER BY m.created_at DESC LIMIT %s""",
                    (limite,)
                )
            rows = cur.fetchall()
        db.close()
        for r in rows:
            r['cantidad']      = float(r['cantidad'])
            r['stock_antes']   = float(r['stock_antes'])
            r['stock_despues'] = float(r['stock_despues'])
            r['created_at']    = r['created_at'].strftime('%Y-%m-%d %H:%M')
        return jsonify(success=True, movimientos=rows)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500


# ── Recetas ───────────────────────────────────────────────────────────────────

@app.route('/api/recetas/<int:pid>', methods=['GET'])
@login_required
def api_receta_producto(pid):
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                """SELECT r.*,i.nombre AS insumo_nombre,i.unidad,i.costo_unitario
                   FROM recetas r JOIN insumos i ON r.insumo_id=i.id
                   WHERE r.producto_id=%s""",
                (pid,)
            )
            rows = cur.fetchall()
        db.close()
        for r in rows:
            r['cantidad'] = float(r['cantidad'])
        return jsonify(success=True, receta=rows)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500


@app.route('/api/recetas/<int:pid>', methods=['PUT'])
@login_required
@csrf_protect
def api_actualizar_receta(pid):
    """Reemplaza la receta completa de un producto."""
    data  = request.get_json(silent=True) or {}
    items = data.get('items', [])  # [{insumo_id, cantidad}]
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM recetas WHERE producto_id=%s", (pid,))
            for it in items:
                iid = int(it.get('insumo_id') or 0)
                qty = float(it.get('cantidad') or 0)
                if iid and qty > 0:
                    cur.execute(
                        "INSERT INTO recetas (producto_id,insumo_id,cantidad) VALUES (%s,%s,%s)",
                        (pid, iid, qty)
                    )
        db.commit()
        db.close()
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500


# ── Descuento automático al guardar una orden ─────────────────────────────────
def descontar_stock_orden(orden_items, orden_id, db):
    """Descuenta stock según recetas con logging de errores."""
    import traceback, sys
    try:
        db2 = get_db()
        cur = db2.cursor()
        for it in orden_items:
            pid  = it.get('producto_id') or it.get('id')
            cant = int(it.get('cantidad') or it.get('qty') or 1)
            print(f'[STOCK] orden={orden_id} producto_id={pid} cant={cant}', file=sys.stderr)
            if not pid:
                continue
            cur.execute(
                "SELECT r.insumo_id, r.cantidad, i.stock_actual "
                "FROM recetas r JOIN insumos i ON r.insumo_id=i.id "
                "WHERE r.producto_id=%s", (pid,)
            )
            receta = cur.fetchall()
            print(f'[STOCK] receta filas={len(receta)}', file=sys.stderr)
            for rec in receta:
                consumo   = round(float(rec['cantidad']) * cant, 3)
                stock_ant = float(rec['stock_actual'])
                stock_new = round(stock_ant - consumo, 3)
                print(f'[STOCK] insumo={rec["insumo_id"]} {stock_ant} -> {stock_new}', file=sys.stderr)
                cur.execute(
                    "UPDATE insumos SET stock_actual=%s WHERE id=%s",
                    (stock_new, rec['insumo_id'])
                )
                cur.execute(
                    "INSERT INTO movimientos_stock "
                    "(insumo_id,tipo,cantidad,stock_antes,stock_despues,motivo,orden_id,created_by) "
                    "VALUES (%s,'consumo',%s,%s,%s,%s,%s,0)",
                    (rec['insumo_id'], consumo, stock_ant, stock_new,
                     'Orden #' + str(orden_id), orden_id)
                )
        db2.commit()
        cur.close()
        db2.close()
        print(f'[STOCK] orden={orden_id} COMMIT OK', file=sys.stderr)
    except Exception as e:
        print(f'[STOCK ERROR] {e}', file=sys.stderr)
        traceback.print_exc(file=sys.stderr)

def devolver_stock_orden(orden_id, db):
    """Devuelve el stock consumido cuando se anula una orden."""
    with db.cursor() as cur:
        try:
            cur.execute(
                """SELECT insumo_id, cantidad FROM movimientos_stock
                   WHERE orden_id=%s AND tipo='consumo'""", (orden_id,)
            )
            movs = cur.fetchall()
        except Exception:
            return  # tabla no existe aún

        for mov in movs:
            cur.execute("SELECT stock_actual FROM insumos WHERE id=%s", (mov['insumo_id'],))
            ins = cur.fetchone()
            if not ins:
                continue
            stock_ant = float(ins['stock_actual'])
            stock_new = round(stock_ant + float(mov['cantidad']), 3)
            cur.execute(
                "UPDATE insumos SET stock_actual=%s WHERE id=%s",
                (stock_new, mov['insumo_id'])
            )
            try:
                cur.execute(
                    """INSERT INTO movimientos_stock
                       (insumo_id,tipo,cantidad,stock_antes,stock_despues,motivo,orden_id,created_by)
                       VALUES (%s,'devolucion',%s,%s,%s,%s,%s,0)""",
                    (mov['insumo_id'], mov['cantidad'], stock_ant, stock_new,
                     'Anulación orden #' + str(orden_id), orden_id)
                )
            except Exception:
                pass

# ═══════════════════════════════════════════════════════════════════════════════
#  V8 — Rutas nuevas: roles, historial, estado órdenes, usuarios
#  Pegar en app.py antes de  if __name__ == '__main__':
# ═══════════════════════════════════════════════════════════════════════════════

# ── Decoradores por rol ───────────────────────────────────────────────────────
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login_page'))
            if session.get('role') not in roles:
                return jsonify(success=False, message='Sin permisos.'), 403
            session.modified = True
            return f(*args, **kwargs)
        return decorated
    return decorator

ROLES_DASHBOARD = ('admin', 'cajero', 'mesero')
ROLES_ADMIN     = ('admin',)
ROLES_COCINA    = ('admin', 'cocina')
ROLES_REPARTO   = ('admin', 'repartidor')

# ── Vistas del dashboard por rol ──────────────────────────────────────────────
@app.route('/dashboard/nueva-orden')
@login_required
def dashboard_nueva_orden():
    role = session.get('role','')
    if role in ('cocina',):
        return redirect(url_for('vista_cocina'))
    if role in ('repartidor',):
        return redirect(url_for('vista_repartidor'))
    return render_template('dashboard.html', section='nueva_orden')

@app.route('/dashboard/historial')
@login_required
def dashboard_historial():
    if session.get('role') not in ('admin','cajero'):
        return redirect(url_for('dashboard'))
    return render_template('dashboard.html', section='historial')

@app.route('/dashboard/usuarios')
@login_required
def dashboard_usuarios():
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    return render_template('dashboard.html', section='usuarios')

# ── Vistas dedicadas móvil ────────────────────────────────────────────────────
@app.route('/cocina')
@login_required
def vista_cocina():
    if session.get('role') not in ('admin','cocina'):
        return redirect(url_for('dashboard'))
    return render_template('cocina.html')

@app.route('/repartidor')
@login_required
def vista_repartidor():
    if session.get('role') not in ('admin','repartidor'):
        return redirect(url_for('dashboard'))
    return render_template('repartidor.html')

# ── Estado de órdenes ─────────────────────────────────────────────────────────
ESTADOS_VALIDOS = ('pendiente','en_preparacion','lista','en_camino','entregada')

@app.route('/api/ordenes/<int:oid>/estado', methods=['POST'])
@login_required
@csrf_protect
def api_cambiar_estado(oid):
    data   = request.get_json(silent=True) or {}
    estado = (data.get('estado') or '').strip()
    role   = session.get('role','')

    # Cocina solo puede mover a en_preparacion / lista
    if role == 'cocina' and estado not in ('en_preparacion','lista'):
        return jsonify(success=False, message='Sin permisos para ese estado.'), 403
    # Repartidor solo puede mover a en_camino / entregada
    if role == 'repartidor' and estado not in ('en_camino','entregada'):
        return jsonify(success=False, message='Sin permisos para ese estado.'), 403

    if estado not in ESTADOS_VALIDOS:
        return jsonify(success=False, message='Estado inválido.'), 400
    try:
        db = get_db()
        with db.cursor() as cur:
            # Al finalizar (entregada), desactivar la orden para que no reaparezca
            if estado == 'entregada':
                cur.execute(
                    "UPDATE ordenes SET estado=%s, activa=0 WHERE id=%s",
                    (estado, oid)
                )
            else:
                cur.execute(
                    "UPDATE ordenes SET estado=%s WHERE id=%s AND activa=1",
                    (estado, oid)
                )
        db.commit()
        db.close()
        return jsonify(success=True, estado=estado)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

# ── Órdenes activas para cocina (pendiente + en_preparacion) ─────────────────
@app.route('/api/ordenes/cocina', methods=['GET'])
@login_required
def api_ordenes_cocina():
    if session.get('role') not in ('admin','cocina'):
        return jsonify(success=False, message='Sin permisos.'), 403
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                """SELECT id,tipo,items,estado,created_at
                   FROM ordenes WHERE activa=1
                   AND estado IN ('pendiente','en_preparacion')
                   ORDER BY id ASC"""
            )
            rows = cur.fetchall()
        db.close()
        for r in rows:
            r['items']      = _json.loads(r['items'])
            r['created_at'] = r['created_at'].strftime('%H:%M')
        return jsonify(success=True, ordenes=rows)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

# ── Órdenes para repartidor (lista + en_camino, solo domicilio) ───────────────
@app.route('/api/ordenes/repartidor', methods=['GET'])
@login_required
def api_ordenes_repartidor():
    if session.get('role') not in ('admin','repartidor'):
        return jsonify(success=False, message='Sin permisos.'), 403
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                """SELECT id,tipo,items,estado,direccion,nombre_cliente,
                          costo_domicilio,total,created_at
                   FROM ordenes WHERE activa=1 AND tipo='domicilio'
                   AND estado IN ('lista','en_camino')
                   ORDER BY id ASC"""
            )
            rows = cur.fetchall()
        db.close()
        for r in rows:
            r['items']      = _json.loads(r['items'])
            r['created_at'] = r['created_at'].strftime('%H:%M')
            r['total']      = int(r['total'])
        return jsonify(success=True, ordenes=rows)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

# ── Historial de órdenes con filtros ─────────────────────────────────────────
@app.route('/api/ordenes/historial', methods=['GET'])
@login_required
def api_historial_ordenes():
    if session.get('role') not in ('admin','cajero'):
        return jsonify(success=False, message='Sin permisos.'), 403

    desde  = request.args.get('desde')   # YYYY-MM-DD
    hasta  = request.args.get('hasta')   # YYYY-MM-DD
    tipo   = request.args.get('tipo')    # mesa|domicilio|''
    estado = request.args.get('estado')  # ''|pendiente|...
    pagina = safe_int(request.args.get('pagina'), default=1, min_val=1)
    por_pag= 30

    try:
        db = get_db()
        with db.cursor() as cur:
            conds  = ["1=1"]
            params = []
            if desde:
                conds.append("DATE(created_at) >= %s"); params.append(desde)
            if hasta:
                conds.append("DATE(created_at) <= %s"); params.append(hasta)
            if tipo in ('mesa','domicilio'):
                conds.append("tipo=%s"); params.append(tipo)
            if estado in ESTADOS_VALIDOS:
                conds.append("estado=%s"); params.append(estado)

            where = ' AND '.join(conds)

            # Total para paginación
            cur.execute(f"SELECT COUNT(*) AS n FROM ordenes WHERE {where}", params)
            total = cur.fetchone()['n']

            # Página actual
            offset = (pagina-1)*por_pag
            cur.execute(
                f"""SELECT id,tipo,estado,subtotal,costo_domicilio,total,
                           direccion,nombre_cliente,items,activa,created_at
                    FROM ordenes WHERE {where}
                    ORDER BY id DESC LIMIT %s OFFSET %s""",
                params + [por_pag, offset]
            )
            rows = cur.fetchall()
        db.close()

        for r in rows:
            r['items']      = _json.loads(r['items'])
            r['created_at'] = r['created_at'].strftime('%Y-%m-%d %H:%M')
            r['total']      = int(r['total'])
            r['subtotal']   = int(r['subtotal'])
            # Ítem 69 — descifrar datos personales al leer
            if r.get('direccion'):     r['direccion']      = decrypt_field(r['direccion'])
            if r.get('nombre_cliente'):r['nombre_cliente'] = decrypt_field(r['nombre_cliente'])

        return jsonify(success=True, ordenes=rows, total=total,
                       pagina=pagina, por_pag=por_pag,
                       paginas=max(1,(total+por_pag-1)//por_pag))
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

# ── Ítem 58 — Exportar historial de órdenes a CSV ────────────────────────────
@app.route('/api/ordenes/exportar', methods=['GET'])
@login_required
def api_exportar_ordenes_csv():
    if session.get('role') not in ('admin', 'cajero'):
        return jsonify(success=False, message='Sin permisos.'), 403

    import csv, io
    from flask import Response

    desde  = request.args.get('desde', '')
    hasta  = request.args.get('hasta', '')
    tipo   = request.args.get('tipo', '')
    estado = request.args.get('estado', '')

    conds  = ['1=1']
    params = []
    if desde:
        conds.append('DATE(created_at) >= %s'); params.append(desde)
    if hasta:
        conds.append('DATE(created_at) <= %s'); params.append(hasta)
    if tipo in ('mesa', 'domicilio'):
        conds.append('tipo=%s'); params.append(tipo)
    if estado in ESTADOS_VALIDOS:
        conds.append('estado=%s'); params.append(estado)

    where = ' AND '.join(conds)

    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                f"""SELECT id, DATE_FORMAT(created_at,'%%Y-%%m-%%d') AS fecha,
                          DATE_FORMAT(created_at,'%%H:%%i') AS hora,
                          tipo, estado, nombre_cliente, direccion,
                          forma_pago, subtotal, costo_domicilio, total,
                          activa, items
                    FROM ordenes WHERE {where}
                    ORDER BY id DESC LIMIT 5000""",
                params
            )
            rows = cur.fetchall()
        db.close()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            'ID','Fecha','Hora','Tipo','Estado','Cliente','Dirección',
            'Forma Pago','Subtotal','Costo Domicilio','Total','Activa','Productos'
        ])
        for r in rows:
            # Resumir items a texto legible
            try:
                items_list = _json.loads(r['items']) if r['items'] else []
                items_txt  = ' | '.join(
                    f"{i.get('nombre','?')} x{i.get('cantidad',1)}" for i in items_list
                )
            except Exception:
                items_txt = r['items'] or ''
            writer.writerow([
                r['id'], r['fecha'], r['hora'], r['tipo'], r['estado'],
                r['nombre_cliente'] or '', r['direccion'] or '',
                r['forma_pago'], int(r['subtotal'] or 0),
                int(r['costo_domicilio'] or 0), int(r['total'] or 0),
                'Sí' if r['activa'] else 'No', items_txt
            ])

        registrar_log('ordenes', 'exportar_csv', 'ok', {'filas': len(rows)})
        return Response(
            '﻿' + output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=ordenes.csv'}
        )
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

# ── Ítem 61 — Duplicar orden existente ────────────────────────────────────────
@app.route('/api/ordenes/<int:oid>/duplicar', methods=['POST'])
@login_required
@csrf_protect
def api_duplicar_orden(oid):
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                """SELECT tipo, direccion, nombre_cliente, costo_domicilio,
                          items, subtotal, total, forma_pago
                   FROM ordenes WHERE id=%s""",
                (oid,)
            )
            orig = cur.fetchone()
        db.close()
        if not orig:
            return jsonify(success=False, message='Orden no encontrada.'), 404
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

    # Devolver datos de la orden para que el frontend la cargue en Nueva Orden
    orig['items'] = _json.loads(orig['items']) if orig['items'] else []
    # Ítem 69 — descifrar antes de devolver al frontend
    if orig.get('direccion'):     orig['direccion']      = decrypt_field(orig['direccion'])
    if orig.get('nombre_cliente'):orig['nombre_cliente'] = decrypt_field(orig['nombre_cliente'])
    orig['subtotal']         = int(orig['subtotal'] or 0)
    orig['total']            = int(orig['total'] or 0)
    orig['costo_domicilio']  = int(orig['costo_domicilio'] or 0)
    registrar_log('ordenes', 'duplicar_orden', 'ok', {'orden_origen': oid})
    return jsonify(success=True, orden=orig)

# ── CRUD Usuarios (solo admin) ────────────────────────────────────────────────
@app.route('/api/usuarios', methods=['GET'])
@login_required
def api_listar_usuarios():
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    try:
        db = get_db()
        rows = []
        with db.cursor() as cur:
            # Intentar queries de más completa a más simple
            queries = [
                "SELECT id,username,role,activo,created_at,ultimo_login,intentos_fallidos,bloqueado_hasta FROM usuarios ORDER BY id",
                "SELECT id,username,role,activo,created_at,ultimo_login FROM usuarios ORDER BY id",
                "SELECT id,username,role,activo,created_at FROM usuarios ORDER BY id",
                "SELECT id,username,role,created_at FROM usuarios ORDER BY id",
                "SELECT id,username,role FROM usuarios ORDER BY id",
            ]
            ultimo_error = ''
            for q in queries:
                try:
                    cur.execute(q)
                    rows = cur.fetchall()
                    break
                except Exception as qe:
                    ultimo_error = str(qe)
                    continue
            else:
                # Ninguna query funcionó
                db.close()
                return jsonify(success=False,
                               message=f'No se pudo leer la tabla usuarios. Error: {ultimo_error}'), 500
        db.close()

        for r in rows:
            if r.get('created_at'):
                r['created_at'] = r['created_at'].strftime('%Y-%m-%d')
            else:
                r['created_at'] = ''
            r['ultimo_login'] = (r['ultimo_login'].strftime('%Y-%m-%d %H:%M')
                                  if r.get('ultimo_login') else 'Nunca')
            r['bloqueado'] = bool(r.get('bloqueado_hasta') and
                                   r['bloqueado_hasta'] > datetime.now())
            r['intentos_fallidos'] = r.get('intentos_fallidos', 0)
            if 'activo' not in r:
                r['activo'] = 1  # asumir activo si la columna no existe
        return jsonify(success=True, usuarios=rows)
    except Exception as e:
        return jsonify(success=False, message=f'Error inesperado: {str(e)}'), 500

@app.route('/api/usuarios', methods=['POST'])
@login_required
@csrf_protect
def api_crear_usuario():
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    data     = request.get_json(silent=True) or {}
    username = sanitizar(data.get('username') or '', max_len=64)
    password = (data.get('password') or '').strip()
    role     = (data.get('role') or '').strip()
    ROLES    = ('admin','cajero','mesero','cocina','repartidor')
    if not username or not password or role not in ROLES:
        return jsonify(success=False, message='Datos inválidos.'), 400
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO usuarios (username,password_hash,role) VALUES (%s,%s,%s)",
                (username, hash_password(password), role)
            )
            nid = cur.lastrowid
        db.commit()
        db.close()
        registrar_log('usuarios', 'crear_usuario', 'ok', {'nuevo_usuario': username, 'role': role})
        return jsonify(success=True, id=nid)
    except Exception as e:
        msg = 'El nombre de usuario ya existe.' if 'Duplicate' in str(e) else str(e)
        registrar_log('usuarios', 'crear_usuario', 'error', {'username': username, 'error': msg})
        return jsonify(success=False, message=msg), 400

@app.route('/api/usuarios/<int:uid>', methods=['PUT'])
@login_required
@csrf_protect
def api_editar_usuario(uid):
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    data     = request.get_json(silent=True) or {}
    role     = (data.get('role') or '').strip()
    password = (data.get('password') or '').strip()
    ROLES    = ('admin','cajero','mesero','cocina','repartidor')
    if role not in ROLES:
        return jsonify(success=False, message='Rol inválido.'), 400
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT username, role FROM usuarios WHERE id=%s", (uid,))
            antes = cur.fetchone() or {}
            if password:
                cur.execute(
                    "UPDATE usuarios SET role=%s,password_hash=%s WHERE id=%s",
                    (role, hash_password(password), uid)
                )
            else:
                cur.execute("UPDATE usuarios SET role=%s WHERE id=%s", (role, uid))
        db.commit()
        db.close()
        cambios = {'usuario': antes.get('username', uid)}
        if antes.get('role') != role:
            cambios['rol'] = {'antes': antes.get('role'), 'despues': role}
        if password:
            cambios['password'] = 'cambiada'
        registrar_log('usuarios', 'editar_usuario', 'ok', cambios)
        return jsonify(success=True)
    except Exception as e:
        registrar_log('usuarios', 'editar_usuario', 'error', {'usuario_id': uid, 'error': str(e)})
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/usuarios/<int:uid>/toggle', methods=['POST'])
@login_required
@csrf_protect
def api_toggle_usuario(uid):
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    if uid == session['user_id']:
        return jsonify(success=False, message='No puedes deshabilitarte a ti mismo.'), 400
    try:
        db = get_db()
        with db.cursor() as cur:
            # Agregar columna activo si no existe
            try:
                cur.execute("ALTER TABLE usuarios ADD COLUMN activo TINYINT(1) NOT NULL DEFAULT 1")
                db.commit()
            except Exception:
                pass  # Ya existe, ignorar

            cur.execute("UPDATE usuarios SET activo = 1 - activo WHERE id=%s", (uid,))
            cur.execute("SELECT activo FROM usuarios WHERE id=%s", (uid,))
            nuevo = cur.fetchone()['activo']
        db.commit()
        db.close()
        accion_tog = 'habilitar_usuario' if nuevo else 'deshabilitar_usuario'
        if not nuevo:
            _sesiones_revocadas.add(uid)
        else:
            _sesiones_revocadas.discard(uid)
        cur_name = get_db()
        with cur_name.cursor() as cn:
            cn.execute("SELECT username FROM usuarios WHERE id=%s", (uid,))
            urow = cn.fetchone()
        cur_name.close()
        registrar_log('usuarios', accion_tog, 'ok', {
            'usuario_id': uid,
            'username': urow['username'] if urow else uid,
            'estado': 'habilitado' if nuevo else 'deshabilitado'
        })
        return jsonify(success=True, activo=nuevo)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/usuarios/<int:uid>/desbloquear', methods=['POST'])
@login_required
@csrf_protect
def api_desbloquear_usuario(uid):
    """Desbloquea manualmente una cuenta bloqueada por intentos fallidos."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                "UPDATE usuarios SET intentos_fallidos=0, bloqueado_hasta=NULL WHERE id=%s",
                (uid,)
            )
        db.commit()
        db.close()
        registrar_log('usuarios', 'desbloquear_usuario', 'ok', {'usuario_id': uid})
        return jsonify(success=True)
    except Exception as e:
        registrar_log('usuarios', 'desbloquear_usuario', 'error', {'usuario_id': uid, 'error': str(e)})
        return jsonify(success=False, message=str(e)), 500

# ═══════════════════════════════════════════════════════════════════════════════
#  MÓDULO CAJA + ANALYTICS — V9
# ═══════════════════════════════════════════════════════════════════════════════

# ── Vistas ───────────────────────────────────────────────────────────────────
@app.route('/dashboard/caja')
@login_required
def dashboard_caja():
    if session.get('role') not in ('admin','cajero'):
        return redirect(url_for('dashboard'))
    return render_template('dashboard.html', section='caja')

@app.route('/dashboard/analytics')
@login_required
def dashboard_analytics():
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    return render_template('dashboard.html', section='analytics')

# ── CAJA: abrir ───────────────────────────────────────────────────────────────
@app.route('/api/caja/hoy', methods=['GET'])
@login_required
def api_caja_hoy():
    # Todos los roles autenticados pueden leer el estado de caja
    # (necesario para validar antes de crear órdenes)
    # Solo admin y cajero pueden abrir/cerrar (validado en esos endpoints)
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT * FROM caja WHERE fecha=CURDATE()")
            caja = cur.fetchone()
            # Totales del día por forma de pago — incluye activas Y finalizadas
            cur.execute("""
                SELECT forma_pago, SUM(total) AS suma, COUNT(*) AS cant
                FROM ordenes
                WHERE DATE(created_at)=CURDATE()
                  AND (activa=1 OR estado='entregada')
                GROUP BY forma_pago
            """)
            pagos = cur.fetchall()
        db.close()
        if caja and caja.get('created_at'):
            caja['created_at'] = caja['created_at'].strftime('%H:%M')
        if caja and caja.get('cerrada_at') and caja['cerrada_at']:
            caja['cerrada_at'] = caja['cerrada_at'].strftime('%H:%M')
        for p in pagos:
            p['suma'] = int(p['suma'] or 0)
        return jsonify(success=True, caja=caja, pagos=pagos)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/caja/abrir', methods=['POST'])
@login_required
@csrf_protect
def api_abrir_caja():
    if session.get('role') not in ('admin','cajero'):
        return jsonify(success=False, message='Sin permisos.'), 403
    data   = request.get_json(silent=True) or {}
    monto  = safe_int(data.get('monto_apertura'), min_val=0)
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT id, estado FROM caja WHERE fecha=CURDATE() ORDER BY id DESC LIMIT 1")
            caja_hoy  = cur.fetchone()
            multiples = get_config('caja_multiples_dia', '0') == '1'

            if caja_hoy:
                if caja_hoy['estado'] == 'abierta':
                    db.close()
                    return jsonify(success=False, message='Ya hay una caja abierta hoy.'), 400
                if not multiples:
                    db.close()
                    return jsonify(success=False,
                                   message='La caja ya fue cerrada hoy. Activa "Múltiples cajas por día" en Configuración para reabrirla.'), 400
                # Multiples activado: ACTUALIZAR el registro existente en vez de insertar
                cur.execute(
                    """UPDATE caja SET estado='abierta', monto_apertura=%s,
                       cerrada_at=NULL, monto_real=NULL, diferencia=NULL,
                       nota=NULL, abierta_por=%s
                       WHERE id=%s""",
                    (monto, session['user_id'], caja_hoy['id'])
                )
            else:
                # No hay caja hoy — insertar normalmente
                cur.execute(
                    """INSERT INTO caja (fecha,monto_apertura,estado,abierta_por)
                       VALUES (CURDATE(),%s,'abierta',%s)""",
                    (monto, session['user_id'])
                )
        db.commit()
        db.close()
        registrar_log('caja', 'abrir_caja', 'ok', {'monto_apertura': monto, 'reabrir': bool(caja_hoy)})
        return jsonify(success=True)
    except Exception as e:
        registrar_log('caja', 'abrir_caja', 'error', {'error': str(e)})
        return jsonify(success=False, message=str(e)), 500

# ── CAJA: cerrar ──────────────────────────────────────────────────────────────
@app.route('/api/caja/cerrar', methods=['POST'])
@login_required
@csrf_protect
def api_cerrar_caja():
    if session.get('role') not in ('admin','cajero'):
        return jsonify(success=False, message='Sin permisos.'), 403
    data       = request.get_json(silent=True) or {}
    monto_real = safe_int(data.get('monto_real'), min_val=0)
    nota       = sanitizar(data.get('nota') or '', max_len=300)
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT * FROM caja WHERE fecha=CURDATE() AND estado='abierta'")
            caja = cur.fetchone()
            if not caja:
                return jsonify(success=False, message='No hay caja abierta hoy.'), 400
            # Calcular totales — incluye activas Y ya finalizadas del día
            cur.execute("""
                SELECT forma_pago, COALESCE(SUM(total),0) AS suma
                FROM ordenes
                WHERE DATE(created_at)=CURDATE()
                  AND (activa=1 OR estado='entregada')
                GROUP BY forma_pago
            """)
            pagos = {r['forma_pago']: int(r['suma']) for r in cur.fetchall()}
            tef  = pagos.get('efectivo',0)
            tneq = pagos.get('nequi',0)
            tdav = pagos.get('daviplata',0)
            tvta = tef + tneq + tdav
            dif  = monto_real - (int(caja['monto_apertura']) + tef)

            # Finalizar automáticamente las órdenes activas que quedaron pendientes
            cur.execute("""
                UPDATE ordenes
                SET estado='entregada', activa=0
                WHERE DATE(created_at)=CURDATE() AND activa=1
            """)
            ordenes_cerradas = cur.rowcount

            cur.execute("""
                UPDATE caja SET estado='cerrada', monto_real=%s,
                  total_efectivo=%s, total_nequi=%s, total_daviplata=%s,
                  total_ventas=%s, diferencia=%s, nota=%s,
                  cerrada_por=%s, cerrada_at=NOW()
                WHERE fecha=CURDATE()
            """, (monto_real, tef, tneq, tdav, tvta, dif, nota, session['user_id']))
        db.commit()
        db.close()
        registrar_log('caja', 'cerrar_caja', 'ok', {'total_ventas': tvta, 'diferencia': dif, 'ordenes_cerradas': ordenes_cerradas})
        alerta_dif = abs(dif) > CAJA_UMBRAL_DIFERENCIA
        return jsonify(success=True, diferencia=dif, total_ventas=tvta,
                       alerta_diferencia=alerta_dif, umbral=CAJA_UMBRAL_DIFERENCIA,
                       ordenes_cerradas=ordenes_cerradas)
    except Exception as e:
        registrar_log('caja', 'cerrar_caja', 'error', {'error': str(e)})
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/caja/historial', methods=['GET'])
@login_required
def api_historial_caja():
    if session.get('role') not in ('admin','cajero'):
        return jsonify(success=False, message='Sin permisos.'), 403
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("""
                SELECT * FROM caja ORDER BY fecha DESC LIMIT 30
            """)
            rows = cur.fetchall()
            # Ítem 40 — desglose por forma de pago por día
            for r in rows:
                fecha = r['fecha']
                cur.execute("""
                    SELECT forma_pago, COUNT(*) AS cant, COALESCE(SUM(total),0) AS suma
                    FROM ordenes
                    WHERE DATE(created_at)=%s AND activa=1
                    GROUP BY forma_pago
                """, (fecha,))
                r['desglose_pagos'] = {p['forma_pago']: {'cant': p['cant'], 'suma': int(p['suma'])} for p in cur.fetchall()}
        db.close()
        for r in rows:
            r['fecha'] = r['fecha'].strftime('%Y-%m-%d')
            if r.get('created_at'): r['created_at'] = r['created_at'].strftime('%H:%M')
            if r.get('cerrada_at') and r['cerrada_at']: r['cerrada_at'] = r['cerrada_at'].strftime('%H:%M')
            for k in ('monto_apertura','monto_real','total_efectivo','total_nequi',
                      'total_daviplata','total_ventas','diferencia'):
                if r.get(k) is not None: r[k] = int(r[k])
        return jsonify(success=True, cajas=rows)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

# ── ANALYTICS ────────────────────────────────────────────────────────────────
@app.route('/api/analytics/resumen', methods=['GET'])
@login_required
def api_analytics_resumen():
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    periodo = request.args.get('periodo','mes')  # hoy|semana|mes|año
    try:
        db = get_db()
        with db.cursor() as cur:
            # Rango de fechas
            rangos = {
                'hoy':    'DATE(created_at) = CURDATE()',
                'semana': 'DATE(created_at) >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)',
                'mes':    'DATE(created_at) >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)',
                'año':    'DATE(created_at) >= DATE_SUB(CURDATE(), INTERVAL 365 DAY)',
            }
            where = rangos.get(periodo, rangos['mes'])
            base  = f"FROM ordenes WHERE {where} AND activa=1"

            # KPIs principales
            cur.execute(f"SELECT COUNT(*) AS n, COALESCE(SUM(total),0) AS bruto, COALESCE(AVG(total),0) AS ticket FROM ordenes WHERE {where} AND activa=1")
            kpis = cur.fetchone()

            # Ventas por día (para gráfico de línea)
            cur.execute(f"""
                SELECT DATE(created_at) AS dia, COUNT(*) AS ordenes,
                       COALESCE(SUM(total),0) AS ventas
                {base} GROUP BY DATE(created_at) ORDER BY dia ASC
            """)
            ventas_dia = cur.fetchall()

            # Top 10 productos
            cur.execute(f"""
                SELECT JSON_UNQUOTE(JSON_EXTRACT(item.value,'$.nombre')) AS nombre,
                       SUM(CAST(JSON_UNQUOTE(JSON_EXTRACT(item.value,'$.cantidad')) AS UNSIGNED)) AS uds,
                       SUM(CAST(JSON_UNQUOTE(JSON_EXTRACT(item.value,'$.total_item')) AS UNSIGNED)) AS ingresos
                FROM ordenes, JSON_TABLE(items,'$[*]' COLUMNS(value JSON PATH '$')) AS item
                WHERE {where} AND activa=1
                GROUP BY nombre ORDER BY uds DESC LIMIT 10
            """)
            top_productos = cur.fetchall()

            # Distribución tipo orden
            cur.execute(f"SELECT tipo, COUNT(*) AS n, COALESCE(SUM(total),0) AS total {base} GROUP BY tipo")
            tipos = cur.fetchall()

            # Por forma de pago
            cur.execute(f"SELECT forma_pago, COUNT(*) AS n, COALESCE(SUM(total),0) AS total {base} GROUP BY forma_pago")
            pagos = cur.fetchall()

            # Horas pico
            cur.execute(f"""
                SELECT HOUR(created_at) AS hora, COUNT(*) AS n {base}
                GROUP BY hora ORDER BY hora ASC
            """)
            horas = cur.fetchall()

            # Ítem 50 — Gastos del período para calcular neto
            gastos_rangos = {
                'hoy':    'fecha = CURDATE()',
                'semana': 'fecha >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)',
                'mes':    'fecha >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)',
                'año':    'fecha >= DATE_SUB(CURDATE(), INTERVAL 365 DAY)',
            }
            cur.execute(
                f"SELECT COALESCE(SUM(monto),0) AS total FROM gastos WHERE {gastos_rangos.get(periodo, gastos_rangos['mes'])}"
            )
            total_gastos = int(cur.fetchone()['total'] or 0)

            # Ítem 50 — Gastos por categoría para desglose
            cur.execute(
                f"""SELECT categoria, COALESCE(SUM(monto),0) AS total
                    FROM gastos WHERE {gastos_rangos.get(periodo, gastos_rangos['mes'])}
                    GROUP BY categoria ORDER BY total DESC"""
            )
            gastos_cat = cur.fetchall()

            # Período anterior para comparativa
            comp_rangos = {
                'hoy':    'DATE(created_at) = DATE_SUB(CURDATE(),INTERVAL 1 DAY)',
                'semana': 'DATE(created_at) >= DATE_SUB(CURDATE(),INTERVAL 14 DAY) AND DATE(created_at) < DATE_SUB(CURDATE(),INTERVAL 7 DAY)',
                'mes':    'DATE(created_at) >= DATE_SUB(CURDATE(),INTERVAL 60 DAY) AND DATE(created_at) < DATE_SUB(CURDATE(),INTERVAL 30 DAY)',
                'año':    'DATE(created_at) >= DATE_SUB(CURDATE(),INTERVAL 730 DAY) AND DATE(created_at) < DATE_SUB(CURDATE(),INTERVAL 365 DAY)',
            }
            cur.execute(f"SELECT COALESCE(SUM(total),0) AS bruto FROM ordenes WHERE {comp_rangos.get(periodo,comp_rangos['mes'])} AND activa=1")
            anterior = cur.fetchone()

        db.close()

        # Serializar
        for r in ventas_dia:
            r['dia']    = r['dia'].strftime('%Y-%m-%d')
            r['ventas'] = int(r['ventas'])
        for r in top_productos:
            r['uds']      = int(r['uds'] or 0)
            r['ingresos'] = int(r['ingresos'] or 0)
        for r in tipos:  r['total'] = int(r['total'] or 0)
        for r in pagos:  r['total'] = int(r['total'] or 0)

        bruto_actual   = int(kpis['bruto'] or 0)
        bruto_anterior = int(anterior['bruto'] or 0)
        variacion      = round(((bruto_actual - bruto_anterior) / bruto_anterior * 100) if bruto_anterior else 0, 1)
        for r in gastos_cat:
            r['total'] = int(r['total'])

        return jsonify(
            success       = True,
            periodo       = periodo,
            kpis          = {'ordenes': int(kpis['n']), 'bruto': bruto_actual,
                             'ticket': int(kpis['ticket'] or 0),
                             'gastos': total_gastos,
                             'neto':   bruto_actual - total_gastos},
            variacion     = variacion,
            ventas_dia    = ventas_dia,
            top_productos = top_productos,
            tipos         = tipos,
            pagos         = pagos,
            horas         = horas,
            gastos_cat    = gastos_cat,
            total_gastos  = total_gastos,
        )
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

# ═══════════════════════════════════════════════════════════════════════════════
#  CHAT IA CON ÓRDENES — Solo admin, credenciales para modificaciones
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/api/chat/ia', methods=['POST'])
@login_required
@csrf_protect
def api_chat_ia():
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403

    data      = request.get_json(silent=True) or {}
    mensaje   = sanitizar(data.get('mensaje') or '', max_len=1500)
    historial = data.get('historial', [])   # [{role, content}]

    if not mensaje:
        return jsonify(success=False, message='Mensaje vacío.'), 400

    # ── Contexto compacto del negocio (hoy) ──────────────────────────────────
    ctx = {}
    try:
        db = get_db()
        with db.cursor() as cur:
            # Ventas de hoy
            cur.execute("""
                SELECT COUNT(*) n, COALESCE(SUM(total),0) ventas
                FROM ordenes WHERE DATE(created_at)=CURDATE()
                  AND (activa=1 OR estado='entregada')
            """)
            hoy = cur.fetchone()
            ctx['hoy'] = {'ordenes': int(hoy['n']), 'ventas': int(hoy['ventas'])}

            # Caja del día
            cur.execute("SELECT estado, monto_apertura, total_ventas FROM caja WHERE fecha=CURDATE() LIMIT 1")
            caja = cur.fetchone()
            ctx['caja'] = {'estado': caja['estado'], 'ventas': int(caja['total_ventas'] or 0)} if caja else None

            # Insumos con stock bajo
            cur.execute("""
                SELECT nombre, stock_actual, stock_minimo, unidad
                FROM insumos WHERE activo=1 AND stock_actual <= stock_minimo LIMIT 8
            """)
            ctx['stock_bajo'] = [{'nombre':r['nombre'],'actual':float(r['stock_actual']),'minimo':float(r['stock_minimo']),'unidad':r['unidad']} for r in cur.fetchall()]

            # Gastos del mes actual
            cur.execute("""
                SELECT categoria, COALESCE(SUM(monto),0) total
                FROM gastos WHERE YEAR(fecha)=YEAR(CURDATE()) AND MONTH(fecha)=MONTH(CURDATE())
                GROUP BY categoria
            """)
            ctx['gastos_mes'] = {r['categoria']: int(r['total']) for r in cur.fetchall()}

        db.close()
    except Exception:
        pass

    fecha_hoy = datetime.now().strftime('%d/%m/%Y %H:%M')

    system_prompt = f"""Eres el asistente inteligente del restaurante "Arepazo de Carlitos" (Girardot, Colombia).
Fecha y hora actual: {fecha_hoy}
Contexto del negocio hoy: {_json.dumps(ctx, ensure_ascii=False)}

ESQUEMA DE LA BASE DE DATOS:
- ordenes(id, tipo[mesa|domicilio], estado[pendiente|en_preparacion|lista|en_camino|entregada], forma_pago[efectivo|nequi|daviplata], total, subtotal, costo_domicilio, nombre_cliente, direccion, items JSON, activa[0|1], created_at)
- insumos(id, nombre, stock_actual, stock_minimo, unidad, costo_unitario, activo)
- productos(id, nombre, precio, categoria, descripcion, disponible)
- gastos(id, fecha, categoria[agua|luz|gas|insumos|bebidas|personal|otros], descripcion, monto, created_at)
- caja(id, fecha, estado[abierta|cerrada], monto_apertura, total_ventas, total_efectivo, total_nequi, total_daviplata, diferencia)
- usuarios(id, username, role[admin|cajero|mesero|cocina|repartidor])
- audit_log(id, username, modulo, accion, resultado, created_at)

CÓMO RESPONDER:
1. Conversación normal → responde en texto claro y directo en español.
2. Para CONSULTAR datos de la BD que no están en el contexto → responde SOLO con JSON:
   {{"tipo":"select","sql":"SELECT ...","descripcion":"lo que quieres consultar"}}
3. Para MODIFICAR datos → responde SOLO con JSON:
   {{"tipo":"mod","sql":"INSERT/UPDATE/DELETE...","descripcion":"qué cambio harás exactamente","impacto":"qué consecuencia tiene"}}

PERMISOS DE MODIFICACIÓN (solo estos):
- gastos: INSERT, UPDATE, DELETE
- insumos: UPDATE stock_actual, costo_unitario
- ordenes: UPDATE estado, forma_pago (NO anular ni crear)
- productos: UPDATE precio, disponible, descripcion

PROHIBIDO: DROP, TRUNCATE, ALTER, modificar usuarios/caja/audit_log, DELETE de órdenes/insumos/productos.

Si el usuario pide algo riesgoso o fuera del alcance, explícalo brevemente."""

    if not ANTHROPIC_API_KEY:
        return jsonify(success=False, message='ANTHROPIC_API_KEY no configurada.'), 503

    # Modo prueba: sin límites de tokens ni restricciones de tablas
    modo_prueba = get_config('chat_ia_modo_prueba', '0') == '1'
    max_tokens_cfg  = 4096 if modo_prueba else 600
    max_historial   = 30   if modo_prueba else 10

    if modo_prueba:
        system_prompt = system_prompt.replace(
            'PROHIBIDO: DROP, TRUNCATE, ALTER, modificar usuarios/caja/audit_log, DELETE de órdenes/insumos/productos.',
            'MODO PRUEBA ACTIVO — restricciones de escritura relajadas para pruebas internas. Sé cuidadoso.'
        )

    try:
        import requests as _req

        msgs = []
        for h in historial[-max_historial:]:
            if h.get('role') in ('user','assistant') and h.get('content'):
                msgs.append({'role': h['role'], 'content': str(h['content'])[:800]})
        msgs.append({'role': 'user', 'content': mensaje})

        def llamar_claude(messages, max_tokens=None):
            r = _req.post(CLAUDE_API_URL, json={
                'model': CLAUDE_MODEL,
                'max_tokens': max_tokens or max_tokens_cfg,
                'system': system_prompt,
                'messages': messages
            }, headers={
                'x-api-key': ANTHROPIC_API_KEY,
                'anthropic-version': '2023-06-01',
                'content-type': 'application/json'
            }, timeout=30)
            r.raise_for_status()
            return r.json()['content'][0]['text'].strip()

        respuesta = llamar_claude(msgs)

        # Intentar parsear como JSON estructurado
        try:
            texto_json = respuesta
            if '```' in texto_json:
                partes = texto_json.split('```')
                texto_json = partes[1] if len(partes) > 1 else partes[0]
                if texto_json.startswith('json'):
                    texto_json = texto_json[4:]
            obj = _json.loads(texto_json.strip())

            # ── SELECT: ejecutar y pedir interpretación ───────────────────────
            if obj.get('tipo') == 'select':
                sql_sel = obj.get('sql', '').strip()
                if not sql_sel.upper().startswith('SELECT'):
                    return jsonify(success=True, tipo='consulta', respuesta='Solo puedo hacer consultas SELECT.')
                try:
                    db2 = get_db()
                    with db2.cursor() as cur2:
                        cur2.execute(sql_sel)
                        filas = cur2.fetchmany(50)   # máx 50 filas
                    db2.close()
                    filas_str = _json.dumps(filas, ensure_ascii=False, default=str)[:2000]
                except Exception as db_err:
                    return jsonify(success=True, tipo='consulta',
                                   respuesta=f'No pude ejecutar la consulta: {str(db_err)}')

                # Segunda llamada: interpretar resultados
                msgs2 = msgs + [
                    {'role': 'assistant', 'content': respuesta},
                    {'role': 'user', 'content': 'Resultados: ' + filas_str + '\n\nExplica esto de forma clara y útil para el restaurante.'}
                ]
                interpretacion = llamar_claude(msgs2, max_tokens=500)
                registrar_log('chat_ia', 'consulta_sql', 'ok', {'sql': sql_sel[:100]})
                return jsonify(success=True, tipo='consulta', respuesta=interpretacion)

            # ── MODIFICACIÓN: pedir confirmación ─────────────────────────────
            elif obj.get('tipo') == 'mod':
                sql_mod = obj.get('sql', '')
                return jsonify(
                    success     = True,
                    tipo        = 'modificacion',
                    descripcion = obj.get('descripcion', ''),
                    impacto     = obj.get('impacto', ''),
                    sql         = sql_mod,
                    firma       = firmar_sql(sql_mod)
                )
        except (ValueError, KeyError):
            pass  # No es JSON → respuesta normal de texto

        return jsonify(success=True, tipo='consulta', respuesta=respuesta)

    except Exception as e:
        return jsonify(success=False, message=f'Error: {str(e)}'), 500


@app.route('/api/chat/ia/ejecutar', methods=['POST'])
@login_required
@csrf_protect
def api_chat_ia_ejecutar():
    """Ejecuta SQL firmado. Verifica credenciales y operaciones permitidas."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403

    data     = request.get_json(silent=True) or {}
    sql      = (data.get('sql') or '').strip()
    firma    = (data.get('firma') or '').strip()
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()

    if not verificar_firma_sql(sql, firma):
        registrar_log('chat_ia', 'sql_firma_invalida', 'denegado', {'sql': sql[:100]})
        return jsonify(success=False, message='Firma de seguridad inválida.'), 403

    if not username or not password:
        return jsonify(success=False, message='Credenciales requeridas.'), 400
    try:
        db_a = get_db()
        with db_a.cursor() as cur_a:
            cur_a.execute("SELECT password_hash, hash_type FROM usuarios WHERE username=%s AND activo!=0", (username,))
            u = cur_a.fetchone()
        db_a.close()
        if not u or not verificar_password(password, u['password_hash'], u.get('hash_type','sha256')):
            return jsonify(success=False, message='Credenciales incorrectas.'), 401
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

    sql_upper = sql.upper().strip()
    for p in ['DROP ','TRUNCATE ','ALTER ','GRANT ','REVOKE ','CREATE ']:
        if p in sql_upper:
            return jsonify(success=False, message=f'Operacion no permitida.'), 400

    PERMITIDO = [
        ('UPDATE', ['ORDENES','INSUMOS','PRODUCTOS','GASTOS']),
        ('INSERT INTO', ['GASTOS']),
        ('DELETE FROM', ['GASTOS']),
    ]
    autorizado = False
    for op, tablas in PERMITIDO:
        if sql_upper.startswith(op):
            for tabla in tablas:
                if tabla in sql_upper:
                    autorizado = True; break
        if autorizado: break

    if not autorizado:
        return jsonify(success=False,
                       message='Solo se permite: UPDATE en ordenes/insumos/productos/gastos, INSERT/DELETE en gastos.'), 400

    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute(sql)
            filas = cur.rowcount
        db.commit(); db.close()
        registrar_log('chat_ia', 'ejecutar_sql', 'ok', {'sql': sql[:200], 'filas': filas, 'por': username})
        if sql_upper.startswith('INSERT'):
            msg = 'Registro creado correctamente.'
        elif sql_upper.startswith('DELETE'):
            msg = f'{filas} registro(s) eliminado(s).'
        else:
            msg = f'{filas} registro(s) actualizado(s).'
        return jsonify(success=True, filas_afectadas=filas, mensaje=f'✅ {msg}')
    except Exception as e:
        registrar_log('chat_ia', 'ejecutar_sql', 'error', {'sql': sql[:200], 'error': str(e)})
        return jsonify(success=False, message=f'Error al ejecutar: {str(e)}'), 500


@app.route('/dashboard/chat-ia')
@login_required
def dashboard_chat_ia():
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    return render_template('dashboard.html', section='chat_ia')

@app.route('/api/chat-ia/historial', methods=['GET'])
@login_required
def api_chat_ia_historial():
    """Devuelve historial de conversaciones del Chat IA."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    pagina  = max(1, int(request.args.get('pagina', 1)))
    por_pag = 20
    offset  = (pagina - 1) * por_pag
    try:
        db = get_db()
        with db.cursor() as cur:
            # Sesiones únicas (agrupadas)
            cur.execute("""
                SELECT sesion_id,
                       MIN(created_at) AS inicio,
                       MAX(created_at) AS fin,
                       COUNT(*) AS mensajes,
                       username,
                       SUM(CASE WHEN tipo='modificacion' THEN 1 ELSE 0 END) AS modificaciones
                FROM chat_ia_historial
                GROUP BY sesion_id, username
                ORDER BY inicio DESC
                LIMIT %s OFFSET %s
            """, (por_pag, offset))
            sesiones = cur.fetchall()

            cur.execute("SELECT COUNT(DISTINCT sesion_id) AS n FROM chat_ia_historial")
            total = cur.fetchone()['n']

        db.close()
        for s in sesiones:
            s['inicio'] = s['inicio'].strftime('%Y-%m-%d %H:%M')
            s['fin']    = s['fin'].strftime('%H:%M')
        return jsonify(success=True, sesiones=sesiones, total=total,
                       pagina=pagina, paginas=max(1,(total+por_pag-1)//por_pag))
    except Exception as e:
        # Si la tabla no existe devolver lista vacía en vez de error 500
        if 'chat_ia_historial' in str(e) or "doesn't exist" in str(e) or 'exist' in str(e).lower():
            return jsonify(success=True, sesiones=[], total=0, pagina=1, paginas=1)
        return jsonify(success=False, message=str(e)), 500
@login_required
def api_chat_ia_sesion(sesion_id):
    """Devuelve los mensajes de una sesión específica."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    sesion_id = sanitizar(sesion_id, max_len=36)
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("""
                SELECT rol, contenido, tipo, sql_usado, created_at
                FROM chat_ia_historial
                WHERE sesion_id=%s ORDER BY id ASC
            """, (sesion_id,))
            msgs = cur.fetchall()
        db.close()
        for m in msgs:
            m['created_at'] = m['created_at'].strftime('%H:%M:%S')
        return jsonify(success=True, mensajes=msgs)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

# ═══════════════════════════════════════════════════════════════════════════════
#  MÓDULO AUDITORÍA — V12
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/dashboard/auditoria')
@login_required
def dashboard_auditoria():
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    return render_template('dashboard.html', section='auditoria')

@app.route('/api/auditoria', methods=['GET'])
@login_required
def api_auditoria():
    """Devuelve el log de auditoría con filtros y paginación."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403

    usuario  = sanitizar(request.args.get('usuario') or '', max_len=64)
    modulo   = sanitizar(request.args.get('modulo') or '', max_len=50)
    resultado= sanitizar(request.args.get('resultado') or '', max_len=20)
    desde    = request.args.get('desde')   # YYYY-MM-DD
    hasta    = request.args.get('hasta')   # YYYY-MM-DD
    pagina   = safe_int(request.args.get('pagina'), default=1, min_val=1)
    por_pag  = 50

    try:
        db = get_db()
        with db.cursor() as cur:
            # Verificar que la tabla existe antes de consultar
            cur.execute("SHOW TABLES LIKE 'audit_log'")
            if not cur.fetchone():
                db.close()
                return jsonify(success=True, logs=[], total=0, pagina=1,
                               por_pag=50, paginas=1,
                               aviso='La tabla audit_log no existe. Ejecuta migracion_v12.sql en phpMyAdmin.')

            conds  = ['1=1']
            params = []
            if usuario:
                conds.append('username LIKE %s'); params.append(f'%{usuario}%')
            if modulo:
                conds.append('modulo = %s'); params.append(modulo)
            if resultado in ('ok', 'error', 'denegado'):
                conds.append('resultado = %s'); params.append(resultado)
            if desde:
                conds.append('DATE(created_at) >= %s'); params.append(desde)
            if hasta:
                conds.append('DATE(created_at) <= %s'); params.append(hasta)

            where = ' AND '.join(conds)
            cur.execute(f'SELECT COUNT(*) AS n FROM audit_log WHERE {where}', params)
            total = cur.fetchone()['n']

            offset = (pagina - 1) * por_pag
            cur.execute(
                f"""SELECT id, usuario_id, username, rol, ip, modulo,
                           accion, detalle, resultado, created_at
                    FROM audit_log WHERE {where}
                    ORDER BY id DESC LIMIT %s OFFSET %s""",
                params + [por_pag, offset]
            )
            rows = cur.fetchall()
        db.close()

        for r in rows:
            r['created_at'] = r['created_at'].strftime('%Y-%m-%d %H:%M:%S')

        return jsonify(
            success=True, logs=rows, total=total,
            pagina=pagina, por_pag=por_pag,
            paginas=max(1, (total + por_pag - 1) // por_pag)
        )
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500


@app.route('/api/auditoria/exportar', methods=['GET'])
@login_required
def api_auditoria_exportar():
    """Exporta el log filtrado como archivo CSV."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403

    import csv, io
    from flask import Response

    usuario  = sanitizar(request.args.get('usuario') or '', max_len=64)
    modulo   = sanitizar(request.args.get('modulo') or '', max_len=50)
    resultado= sanitizar(request.args.get('resultado') or '', max_len=20)
    desde    = request.args.get('desde')
    hasta    = request.args.get('hasta')

    try:
        db = get_db()
        with db.cursor() as cur:
            conds  = ['1=1']
            params = []
            if usuario:
                conds.append('username LIKE %s'); params.append(f'%{usuario}%')
            if modulo:
                conds.append('modulo = %s'); params.append(modulo)
            if resultado in ('ok', 'error', 'denegado'):
                conds.append('resultado = %s'); params.append(resultado)
            if desde:
                conds.append('DATE(created_at) >= %s'); params.append(desde)
            if hasta:
                conds.append('DATE(created_at) <= %s'); params.append(hasta)

            where = ' AND '.join(conds)
            cur.execute(
                f"""SELECT id, created_at, username, rol, ip, modulo,
                           accion, resultado, detalle
                    FROM audit_log WHERE {where}
                    ORDER BY id DESC LIMIT 5000""",
                params
            )
            rows = cur.fetchall()
        db.close()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Fecha', 'Usuario', 'Rol', 'IP', 'Módulo', 'Acción', 'Resultado', 'Detalle'])
        for r in rows:
            writer.writerow([
                r['id'],
                r['created_at'].strftime('%Y-%m-%d %H:%M:%S'),
                r['username'], r['rol'], r['ip'],
                r['modulo'], r['accion'], r['resultado'],
                r['detalle'] or ''
            ])

        registrar_log('auditoria', 'exportar_csv', 'ok', {'filas': len(rows)})
        return Response(
            '\ufeff' + output.getvalue(),   # BOM para Excel en español
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=auditoria.csv'}
        )
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500


# ── Ítem: Configuración del sistema ──────────────────────────────────────────
@app.route('/api/configuracion', methods=['GET'])
@login_required
def api_get_configuracion():
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    defaults = {
        'caja_multiples_dia':      '0',
        'session_timeout_minutes': '30',
        'dom_precio_1':            '3000',
        'dom_precio_2':            '5000',
        'dom_precio_3':            '12000',
    }
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT clave, valor FROM configuracion")
            rows = cur.fetchall()
        db.close()
        config = {**defaults, **{r['clave']: r['valor'] for r in rows}}
        return jsonify(success=True, config=config)
    except Exception:
        # Si la tabla no existe, devolver defaults en vez de error
        return jsonify(success=True, config=defaults)

@app.route('/api/configuracion', methods=['POST'])
@login_required
@csrf_protect
def api_set_configuracion():
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    data  = request.get_json(silent=True) or {}
    clave = sanitizar(data.get('clave') or '', max_len=50)
    valor = sanitizar(data.get('valor') or '', max_len=255)
    if not clave:
        return jsonify(success=False, message='Clave requerida.'), 400
    ok = set_config(clave, valor)
    if ok:
        registrar_log('configuracion', f'cambiar_{clave}', 'ok', {'valor': valor})
    return jsonify(success=ok)

@app.route('/api/configuracion/modo-prueba', methods=['POST'])
@login_required
@csrf_protect
def api_modo_prueba_chat():
    """Activa/desactiva modo prueba del Chat IA. Solo admin, requiere contraseña."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    data    = request.get_json(silent=True) or {}
    password = (data.get('password') or '').strip()
    activar  = bool(data.get('activar', False))
    if not password:
        return jsonify(success=False, message='Contraseña requerida.'), 400
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT password_hash, hash_type FROM usuarios WHERE id=%s", (session['user_id'],))
            u = cur.fetchone()
        db.close()
        if not u or not verificar_password(password, u['password_hash'], u.get('hash_type','sha256')):
            return jsonify(success=False, message='Contraseña incorrecta.'), 401
        set_config('chat_ia_modo_prueba', '1' if activar else '0')
        registrar_log('configuracion', 'modo_prueba_chat',
                      'ok', {'activar': activar, 'usuario': session['username']})
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500
@login_required
@csrf_protect
def api_cambiar_password_config():
    """Cambiar contraseña desde Configuración verificando la contraseña actual."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    data    = request.get_json(silent=True) or {}
    actual  = (data.get('actual')  or '').strip()
    nueva   = (data.get('nueva')   or '').strip()
    repetir = (data.get('repetir') or '').strip()
    if not actual or not nueva or not repetir:
        return jsonify(success=False, message='Completa todos los campos.'), 400
    if len(nueva) < 6:
        return jsonify(success=False, message='La nueva contraseña debe tener al menos 6 caracteres.'), 400
    if nueva != repetir:
        return jsonify(success=False, message='Las contraseñas no coinciden.'), 400
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT password_hash, hash_type FROM usuarios WHERE id=%s", (session['user_id'],))
            u = cur.fetchone()
        db.close()
        if not u or not verificar_password(actual, u['password_hash'], u.get('hash_type','sha256')):
            return jsonify(success=False, message='La contraseña actual es incorrecta.'), 401
        nuevo_hash = hash_password_bcrypt(nueva)
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                "UPDATE usuarios SET password_hash=%s, hash_type='bcrypt' WHERE id=%s",
                (nuevo_hash, session['user_id'])
            )
        db.commit(); db.close()
        registrar_log('seguridad', 'cambio_password', 'ok', {'usuario_id': session['user_id']})
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

# ── Ítem 74 — Health-check endpoint ─────────────────────────────────────────
@app.route('/ping')
def ping():
    """Endpoint de monitoreo. Verifica app + BD."""
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT 1")
        db.close()
        return jsonify(status='ok', app='arepazo', db='ok'), 200
    except Exception as e:
        return jsonify(status='error', app='arepazo', db=str(e)), 500

# ── Ítem 21 — Log de navegación entre módulos ────────────────────────────────
@app.route('/api/log/navegacion', methods=['POST'])
@login_required
@csrf_protect
def api_log_navegacion():
    """El frontend llama esto al cambiar de sección para registrar navegación."""
    data   = request.get_json(silent=True) or {}
    seccion = sanitizar(data.get('seccion') or '', max_len=50)
    if seccion:
        registrar_log('navegacion', f'ver_{seccion}', 'ok', {'seccion': seccion})
    return jsonify(success=True)

# ── Páginas de error personalizadas ─────────────────────────────────────────────
@app.errorhandler(404)
def error_404(e):
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify(success=False, message='Recurso no encontrado.'), 404
    return render_template('error.html', codigo=404,
                           titulo='Página no encontrada',
                           mensaje='La dirección que buscas no existe o fue movida.'), 404

@app.errorhandler(500)
def error_500(e):
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify(success=False, message='Error interno del servidor.'), 500
    return render_template('error.html', codigo=500,
                           titulo='Error interno',
                           mensaje='Algo salió mal. Intenta de nuevo en un momento.'), 500

# ═══════════════════════════════════════════════════════════════════════════════
#  MÓDULO GASTOS — V14  (ítem 31)
# ═══════════════════════════════════════════════════════════════════════════════

CATEGORIAS_GASTO = ('arriendo','servicios','salarios','empaques','insumos','otros')

@app.route('/dashboard/gastos')
@login_required
def dashboard_gastos():
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    return render_template('dashboard.html', section='gastos')

# Categorías fijas del módulo de gastos
CATEGORIAS_FIJAS = ['agua', 'luz', 'gas', 'insumos', 'bebidas', 'personal', 'otros']
CATEGORIAS_LABEL = {
    'agua':     ('💧', 'Agua'),
    'luz':      ('💡', 'Luz'),
    'gas':      ('🔥', 'Gas'),
    'insumos':  ('🥬', 'Insumos'),
    'bebidas':  ('🥤', 'Bebidas'),
    'personal': ('👤', 'Personal'),
    'otros':    ('➕', 'Otros'),
}

@app.route('/api/gastos/mes', methods=['GET'])
@login_required
def api_gastos_mes():
    """Devuelve gastos y ingresos de un mes. mes=YYYY-MM (default: mes actual)"""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    mes = sanitizar(request.args.get('mes', datetime.now().strftime('%Y-%m')), max_len=7)
    try:
        anio, m = int(mes[:4]), int(mes[5:7])
    except Exception:
        anio, m = datetime.now().year, datetime.now().month
    try:
        db = get_db()
        with db.cursor() as cur:
            # Gastos del mes por categoría (un registro por categoría)
            cur.execute("""
                SELECT categoria, COALESCE(SUM(monto),0) AS monto
                FROM gastos
                WHERE YEAR(fecha)=%s AND MONTH(fecha)=%s
                GROUP BY categoria
            """, (anio, m))
            filas = {r['categoria']: int(r['monto']) for r in cur.fetchall()}

            # Ingresos del mes desde órdenes
            cur.execute("""
                SELECT COALESCE(SUM(total),0) AS total
                FROM ordenes
                WHERE YEAR(created_at)=%s AND MONTH(created_at)=%s
                  AND (activa=1 OR estado='entregada')
            """, (anio, m))
            ingresos = int(cur.fetchone()['total'] or 0)
        db.close()

        gastos = {cat: filas.get(cat, 0) for cat in CATEGORIAS_FIJAS}
        total_gastos = sum(gastos.values())
        return jsonify(success=True, mes=f'{anio}-{m:02d}',
                       gastos=gastos, total_gastos=total_gastos,
                       ingresos=ingresos, beneficio=ingresos - total_gastos)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/gastos/mes', methods=['POST'])
@login_required
@csrf_protect
def api_guardar_gastos_mes():
    """Guarda o actualiza los gastos de un mes (un monto por categoría)."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    data = request.get_json(silent=True) or {}
    mes  = sanitizar(data.get('mes', datetime.now().strftime('%Y-%m')), max_len=7)
    try:
        anio, m = int(mes[:4]), int(mes[5:7])
        fecha_mes = f'{anio}-{m:02d}-01'
    except Exception:
        return jsonify(success=False, message='Mes inválido.'), 400

    try:
        db = get_db()
        with db.cursor() as cur:
            for cat in CATEGORIAS_FIJAS:
                monto = safe_int(data.get(cat, 0), min_val=0)
                # Borrar registro anterior del mes para esta categoría y reemplazar
                cur.execute("""
                    DELETE FROM gastos
                    WHERE YEAR(fecha)=%s AND MONTH(fecha)=%s AND categoria=%s
                """, (anio, m, cat))
                if monto > 0:
                    cur.execute("""
                        INSERT INTO gastos (fecha, categoria, descripcion, monto, created_by)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (fecha_mes, cat, cat.capitalize(), monto, session['user_id']))
        db.commit()
        db.close()
        total_guardado = sum(int(data.get(cat,0) or 0) for cat in CATEGORIAS_FIJAS)
        registrar_log('gastos', 'guardar_mes', 'ok', {'mes': mes, 'total_gastos': total_guardado,
                       'detalle': {cat: int(data.get(cat,0) or 0) for cat in CATEGORIAS_FIJAS}})
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

# ═══════════════════════════════════════════════════════════════════════════════
#  ÍTEM 79 — CÓDIGOS DE EMERGENCIA
#  Recuperación de acceso sin email ni TOTP.
#  El admin genera 10 códigos de un solo uso, los descarga/imprime,
#  y puede usar cualquiera desde /recuperar si pierde la contraseña.
# ═══════════════════════════════════════════════════════════════════════════════

def _hash_codigo(codigo: str) -> str:
    """SHA-256 del código en texto plano (no necesita bcrypt: son tokens aleatorios largos)."""
    return hashlib.sha256(codigo.encode('utf-8')).hexdigest()

def _generar_codigo() -> str:
    """Genera un código de emergencia legible: XXXX-XXXX-XXXX (16 chars hex en grupos de 4)."""
    raw = secrets.token_hex(6).upper()  # 12 chars hex
    return f"{raw[0:4]}-{raw[4:8]}-{raw[8:12]}"

@app.route('/api/emergencia/generar', methods=['POST'])
@login_required
@csrf_protect
def api_generar_codigos_emergencia():
    """Genera 10 códigos nuevos, invalida los anteriores y devuelve los nuevos EN TEXTO PLANO una sola vez."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Solo el admin puede generar códigos de emergencia.'), 403
    uid = session['user_id']
    try:
        codigos_plain = [_generar_codigo() for _ in range(10)]
        db = get_db()
        with db.cursor() as cur:
            # Invalidar códigos anteriores de este usuario
            cur.execute("DELETE FROM codigos_emergencia WHERE usuario_id=%s", (uid,))
            # Insertar los nuevos hasheados
            for c in codigos_plain:
                cur.execute(
                    "INSERT INTO codigos_emergencia (usuario_id, codigo_hash) VALUES (%s,%s)",
                    (uid, _hash_codigo(c))
                )
        db.commit()
        db.close()
        registrar_log('seguridad', 'generar_codigos_emergencia', 'ok',
                      {'usuario_id': uid, 'cantidad': 10})
        return jsonify(success=True, codigos=codigos_plain)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/emergencia/estado', methods=['GET'])
@login_required
def api_estado_codigos_emergencia():
    """Devuelve cuántos códigos disponibles le quedan al admin."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    uid = session['user_id']
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS total, SUM(usado) AS usados FROM codigos_emergencia WHERE usuario_id=%s",
                (uid,)
            )
            row = cur.fetchone()
        db.close()
        total     = int(row['total'] or 0)
        usados    = int(row['usados'] or 0)
        disponibles = total - usados
        return jsonify(success=True, total=total, usados=usados, disponibles=disponibles)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

# ── Página pública de recuperación ───────────────────────────────────────────
@app.route('/recuperar', methods=['GET'])
def recuperar_page():
    """Página pública para recuperar acceso con código de emergencia."""
    return render_template('recuperar.html')

@app.route('/recuperar', methods=['POST'])
@limiter.limit('5 per 15 minutes', error_message='Demasiados intentos. Espera 15 minutos.')
def recuperar_post():
    """Verifica username + código de emergencia. Si es válido, inicia sesión y marca el código como usado."""
    data     = request.get_json(silent=True) or request.form
    username = sanitizar(data.get('username') or '', max_len=64)
    codigo   = sanitizar(data.get('codigo') or '', max_len=20).upper().strip()

    if not username or not codigo:
        return jsonify(success=False, message='Completa todos los campos.'), 400

    codigo_hash = _hash_codigo(codigo)

    try:
        db = get_db()
        with db.cursor() as cur:
            # Buscar usuario
            cur.execute(
                "SELECT id, username, role FROM usuarios WHERE username=%s AND activo!=0 LIMIT 1",
                (username,)
            )
            user = cur.fetchone()
            if not user:
                db.close()
                registrar_log('seguridad', 'recuperacion_fallida', 'error',
                              {'username': username, 'motivo': 'usuario no encontrado'})
                return jsonify(success=False, message='Usuario o código incorrecto.'), 401

            # Solo admin puede usar códigos de emergencia
            if user['role'] != 'admin':
                db.close()
                return jsonify(success=False, message='Los códigos de emergencia son solo para administradores.'), 403

            # Buscar código válido no usado
            cur.execute(
                """SELECT id FROM codigos_emergencia
                   WHERE usuario_id=%s AND codigo_hash=%s AND usado=0
                   LIMIT 1""",
                (user['id'], codigo_hash)
            )
            cod_row = cur.fetchone()
            if not cod_row:
                db.close()
                registrar_log('seguridad', 'recuperacion_fallida', 'error',
                              {'username': username, 'motivo': 'código inválido o ya usado'})
                return jsonify(success=False, message='Usuario o código incorrecto.'), 401

            # Marcar código como usado
            cur.execute(
                "UPDATE codigos_emergencia SET usado=1, usado_at=NOW() WHERE id=%s",
                (cod_row['id'],)
            )
            # Actualizar último login (ignorar si la columna no existe)
            try:
                cur.execute("UPDATE usuarios SET ultimo_login=NOW() WHERE id=%s", (user['id'],))
            except Exception:
                pass
        db.commit()
        db.close()

        # Iniciar sesión con flag de cambio obligatorio
        session.permanent = True
        session['user_id']          = user['id']
        session['username']         = user['username']
        session['role']             = user['role']
        session['must_change_password'] = True   # Fuerza el cambio antes de entrar
        registrar_log('seguridad', 'recuperacion_exitosa', 'ok',
                      {'usuario_id': user['id'], 'username': username})
        return jsonify(success=True, redirect=url_for('cambiar_password_page'),
                       aviso='Código utilizado. Debes crear una nueva contraseña para continuar.')
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

        return jsonify(success=False, message=str(e)), 500

# ═══════════════════════════════════════════════════════════════════════════════
#  ÍTEM 78 — TOTP (Google Authenticator)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/api/totp/verificar-login', methods=['POST'])
@limiter.limit('10 per 5 minutes')
def api_totp_verificar_login():
    """Segunda etapa del login: verifica el código TOTP."""
    if 'totp_pending_id' not in session:
        return jsonify(success=False, message='No hay login pendiente.'), 400

    data   = request.get_json(silent=True) or {}
    codigo = str(data.get('codigo') or '').strip().replace(' ', '')

    try:
        uid = session['totp_pending_id']
        db  = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT totp_secret FROM usuarios WHERE id=%s", (uid,))
            row = cur.fetchone()
        db.close()
        if not row or not row.get('totp_secret'):
            return jsonify(success=False, message='TOTP no configurado.'), 400

        import pyotp
        totp = pyotp.TOTP(row['totp_secret'])
        if not totp.verify(codigo, valid_window=1):
            registrar_log('login', 'totp_fallido', 'error', {'usuario_id': uid})
            return jsonify(success=False, message='Código incorrecto. Verifica la hora de tu dispositivo.'), 401

        # Código correcto → completar la sesión
        recordar = session.get('totp_pending_recordar', False)
        session.permanent = True
        if recordar:
            from flask import current_app
            current_app.permanent_session_lifetime = timedelta(days=30)
        session['user_id']  = uid
        session['username'] = session.pop('totp_pending_username')
        session['role']     = session.pop('totp_pending_role')
        session['recordar'] = recordar
        session.pop('totp_pending_id', None)
        session.pop('totp_pending_recordar', None)

        # Actualizar último login
        try:
            db_ul = get_db()
            with db_ul.cursor() as cur_ul:
                cur_ul.execute("UPDATE usuarios SET ultimo_login=NOW() WHERE id=%s", (uid,))
            db_ul.commit(); db_ul.close()
        except Exception:
            pass

        registrar_log('login', 'login_ok_totp', 'ok', {'role': session['role']})
        rol = session['role']
        destinos = {'cocina':'cocina_view', 'repartidor':'repartidor_view'}
        return jsonify(success=True, redirect=url_for(destinos.get(rol, 'dashboard')))
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/totp/generar', methods=['POST'])
@login_required
@csrf_protect
def api_totp_generar():
    """Genera QR. Si ya tiene secret lo reutiliza para conservar el vínculo con la app."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    try:
        import pyotp, qrcode, io, base64
        # Verificar si ya tiene un secret guardado (vínculo anterior)
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT totp_secret FROM usuarios WHERE id=%s", (session['user_id'],))
            row = cur.fetchone()
        db.close()
        existente = row.get('totp_secret') if row else None
        # Reutilizar el secret existente o generar uno nuevo
        secreto  = existente if existente else pyotp.random_base32()
        es_nuevo = not existente
        uri      = pyotp.totp.TOTP(secreto).provisioning_uri(
                       name=session['username'], issuer_name='Arepazo de Carlitos')
        img  = qrcode.make(uri)
        buf  = io.BytesIO()
        img.save(buf, format='PNG')
        qr_b64 = base64.b64encode(buf.getvalue()).decode()
        session['totp_secret_temp'] = secreto
        return jsonify(success=True, qr=qr_b64, secreto=secreto, es_nuevo=es_nuevo)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/totp/activar', methods=['POST'])
@login_required
@csrf_protect
def api_totp_activar():
    """Verifica el código y activa TOTP para el admin."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    data    = request.get_json(silent=True) or {}
    codigo  = str(data.get('codigo') or '').strip()
    secreto = session.get('totp_secret_temp')
    if not secreto:
        return jsonify(success=False, message='Genera primero el QR.'), 400
    try:
        import pyotp
        if not pyotp.TOTP(secreto).verify(codigo, valid_window=1):
            return jsonify(success=False, message='Código incorrecto. Escanea el QR y reintenta.'), 401
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                "UPDATE usuarios SET totp_secret=%s, totp_activo=1 WHERE id=%s",
                (secreto, session['user_id'])
            )
        db.commit(); db.close()
        session.pop('totp_secret_temp', None)
        registrar_log('seguridad', 'totp_activado', 'ok', {'usuario_id': session['user_id']})
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/totp/desactivar', methods=['POST'])
@login_required
@csrf_protect
def api_totp_desactivar():
    """Desactiva TOTP tras verificar el código actual."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    data   = request.get_json(silent=True) or {}
    codigo = str(data.get('codigo') or '').strip()
    try:
        import pyotp
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT totp_secret FROM usuarios WHERE id=%s", (session['user_id'],))
            row = cur.fetchone()
        db.close()
        if not row or not row.get('totp_secret'):
            return jsonify(success=False, message='TOTP no está activo.'), 400
        if not pyotp.TOTP(row['totp_secret']).verify(codigo, valid_window=1):
            return jsonify(success=False, message='Código incorrecto.'), 401
        db = get_db()
        with db.cursor() as cur:
            # Solo desactiva el flag — conserva el secret para no perder el vínculo
            cur.execute(
                "UPDATE usuarios SET totp_activo=0 WHERE id=%s",
                (session['user_id'],)
            )
        db.commit(); db.close()
        registrar_log('seguridad', 'totp_desactivado', 'ok', {'usuario_id': session['user_id']})
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/totp/estado', methods=['GET'])
@login_required
def api_totp_estado():
    """Devuelve si el usuario tiene TOTP activo."""
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT totp_activo, totp_secret FROM usuarios WHERE id=%s",
                (session['user_id'],)
            )
            row = cur.fetchone()
        db.close()
        # Verificar tanto el flag como que existe el secret
        activo = False
        if row:
            val = row.get('totp_activo')
            sec = row.get('totp_secret')
            activo = bool(int(val or 0) == 1 and sec)
        return jsonify(success=True, activo=activo)
    except Exception as e:
        return jsonify(success=True, activo=False)





@app.route('/api/stats-publicos', methods=['GET'])
def api_stats_publicos():
    """Stats en tiempo real para la homepage — sin autenticación."""
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) n FROM productos WHERE disponible=1")
            total_productos = cur.fetchone()['n']
            cur.execute("SELECT COUNT(*) n FROM ordenes WHERE activa=0 AND estado='entregada'")
            total_ordenes = cur.fetchone()['n']
            cur.execute("""SELECT COUNT(*) n FROM ordenes
                          WHERE estado='entregada'
                          AND YEAR(created_at)=YEAR(CURDATE())
                          AND MONTH(created_at)=MONTH(CURDATE())""")
            ordenes_mes = cur.fetchone()['n']
        db.close()
        return jsonify(success=True, total_productos=total_productos,
                       total_ordenes=total_ordenes, ordenes_mes=ordenes_mes)
    except Exception:
        return jsonify(success=True, total_productos=14,
                       total_ordenes=0, ordenes_mes=0)

@app.route('/api/whatsapp-config', methods=['GET'])
def api_whatsapp_config():
    """Devuelve número y mensaje de WhatsApp para la homepage."""
    numero  = get_config('whatsapp_numero',  '3003830842')
    mensaje = get_config('whatsapp_mensaje',
                         '¡Hola Arepazo de Carlitos! Quiero reservar un cumpleaños 🎂')
    return jsonify(success=True, numero=numero, mensaje=mensaje)

# ═══════════════════════════════════════════════════════════════════════════════
#  MÓDULO REPORTES — Claude analiza datos reales y genera reportes descargables
# ═══════════════════════════════════════════════════════════════════════════════

REPORTES_CONFIG = {
    'dia': {
        'titulo': 'Resumen del día',
        'icono': '📊',
        'descripcion': 'Ventas, órdenes, formas de pago y caja de hoy'
    },
    'semana': {
        'titulo': 'Ventas por semana',
        'icono': '📅',
        'descripcion': 'Comparativa diaria de los últimos 7 días'
    },
    'productos': {
        'titulo': 'Productos más vendidos',
        'icono': '🏆',
        'descripcion': 'Ranking de productos con ingresos generados'
    },
    'gastos': {
        'titulo': 'Gastos vs Ingresos',
        'icono': '💰',
        'descripcion': 'Análisis financiero del mes con beneficio real'
    },
    'stock': {
        'titulo': 'Estado del stock',
        'icono': '📦',
        'descripcion': 'Agotados, stock bajo y próximos a vencer'
    },
    'domicilios': {
        'titulo': 'Análisis de domicilios',
        'icono': '🛵',
        'descripcion': 'Volumen, valores y tendencias de domicilios'
    },
    'horas': {
        'titulo': 'Horas pico',
        'icono': '⏰',
        'descripcion': 'Actividad por hora — cuándo más y menos se vende'
    },
    'caja': {
        'titulo': 'Comportamiento de caja',
        'icono': '🏦',
        'descripcion': 'Historial de diferencias y tendencias de caja'
    },
}

@app.route('/dashboard/reportes')
@login_required
def dashboard_reportes():
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    return render_template('dashboard.html', section='reportes')

@app.route('/api/reportes/generar', methods=['POST'])
@login_required
@csrf_protect
def api_generar_reporte():
    """Recopila datos de la BD y pide a Claude que genere el reporte."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    if not ANTHROPIC_API_KEY:
        return jsonify(success=False, message='ANTHROPIC_API_KEY no configurada.'), 503

    data       = request.get_json(silent=True) or {}
    tipo       = sanitizar(data.get('tipo', ''), max_len=20)
    personaliz = sanitizar(data.get('personalizado', ''), max_len=500)

    if tipo not in REPORTES_CONFIG and tipo != 'personalizado':
        return jsonify(success=False, message='Tipo de reporte inválido.'), 400

    # ── Recopilar datos según el tipo ─────────────────────────────────────────
    ctx = {}
    try:
        db = get_db()
        with db.cursor() as cur:
            fecha_hoy = datetime.now().strftime('%Y-%m-%d')
            mes_actual = datetime.now().strftime('%Y-%m')

            if tipo == 'dia':
                cur.execute("""
                    SELECT estado, forma_pago, COUNT(*) n, COALESCE(SUM(total),0) total
                    FROM ordenes WHERE DATE(created_at)=CURDATE()
                    AND (activa=1 OR estado='entregada')
                    GROUP BY estado, forma_pago
                """)
                ctx['ordenes_hoy'] = cur.fetchall()
                cur.execute("SELECT * FROM caja WHERE fecha=CURDATE() LIMIT 1")
                ctx['caja_hoy'] = cur.fetchone()

            elif tipo == 'semana':
                cur.execute("""
                    SELECT DATE(created_at) fecha,
                           COUNT(*) ordenes,
                           COALESCE(SUM(total),0) ventas,
                           COALESCE(SUM(CASE WHEN tipo='domicilio' THEN 1 ELSE 0 END),0) domicilios
                    FROM ordenes
                    WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
                    AND (activa=1 OR estado='entregada')
                    GROUP BY DATE(created_at) ORDER BY fecha
                """)
                rows = cur.fetchall()
                for r in rows:
                    r['fecha'] = r['fecha'].strftime('%d/%m')
                ctx['por_dia'] = rows

            elif tipo == 'productos':
                cur.execute("""
                    SELECT JSON_UNQUOTE(JSON_EXTRACT(items, CONCAT('$[', idx, '].nombre'))) nombre,
                           SUM(JSON_UNQUOTE(JSON_EXTRACT(items, CONCAT('$[', idx, '].cantidad')))) cant,
                           SUM(JSON_UNQUOTE(JSON_EXTRACT(items, CONCAT('$[', idx, '].precio')))*
                               JSON_UNQUOTE(JSON_EXTRACT(items, CONCAT('$[', idx, '].cantidad')))) ingresos
                    FROM ordenes
                    JOIN (SELECT 0 idx UNION SELECT 1 UNION SELECT 2 UNION SELECT 3
                          UNION SELECT 4 UNION SELECT 5 UNION SELECT 6 UNION SELECT 7) nums
                    WHERE (activa=1 OR estado='entregada')
                    AND MONTH(created_at)=MONTH(CURDATE())
                    AND JSON_EXTRACT(items, CONCAT('$[', idx, '].nombre')) IS NOT NULL
                    GROUP BY nombre ORDER BY cant DESC LIMIT 15
                """)
                ctx['productos'] = cur.fetchall()

            elif tipo == 'gastos':
                cur.execute("""
                    SELECT categoria, COALESCE(SUM(monto),0) total
                    FROM gastos WHERE YEAR(fecha)=YEAR(CURDATE()) AND MONTH(fecha)=MONTH(CURDATE())
                    GROUP BY categoria ORDER BY total DESC
                """)
                ctx['gastos'] = cur.fetchall()
                cur.execute("""
                    SELECT COALESCE(SUM(total),0) ingresos
                    FROM ordenes WHERE YEAR(created_at)=YEAR(CURDATE())
                    AND MONTH(created_at)=MONTH(CURDATE())
                    AND (activa=1 OR estado='entregada')
                """)
                ctx['ingresos_mes'] = int(cur.fetchone()['ingresos'] or 0)

            elif tipo == 'stock':
                cur.execute("""
                    SELECT nombre, stock_actual, stock_minimo, unidad, categoria,
                           fecha_vencimiento,
                           DATEDIFF(fecha_vencimiento, CURDATE()) dias_vence
                    FROM insumos WHERE activo=1
                    AND (stock_actual <= stock_minimo
                         OR (fecha_vencimiento IS NOT NULL AND DATEDIFF(fecha_vencimiento,CURDATE()) <= 15))
                    ORDER BY dias_vence ASC, stock_actual ASC LIMIT 30
                """)
                rows = cur.fetchall()
                for r in rows:
                    if r.get('fecha_vencimiento'):
                        r['fecha_vencimiento'] = r['fecha_vencimiento'].strftime('%d/%m/%Y')
                    r['stock_actual'] = float(r['stock_actual'])
                    r['stock_minimo'] = float(r['stock_minimo'])
                ctx['criticos'] = rows

            elif tipo == 'domicilios':
                cur.execute("""
                    SELECT DATE(created_at) fecha,
                           COUNT(*) n,
                           COALESCE(SUM(total),0) total,
                           COALESCE(AVG(costo_domicilio),0) avg_domicilio
                    FROM ordenes
                    WHERE tipo='domicilio'
                    AND created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
                    GROUP BY DATE(created_at) ORDER BY fecha DESC
                """)
                rows = cur.fetchall()
                for r in rows:
                    r['fecha'] = r['fecha'].strftime('%d/%m')
                ctx['domicilios'] = rows

            elif tipo == 'horas':
                cur.execute("""
                    SELECT HOUR(created_at) hora,
                           COUNT(*) ordenes,
                           COALESCE(SUM(total),0) ventas
                    FROM ordenes
                    WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
                    AND (activa=1 OR estado='entregada')
                    GROUP BY HOUR(created_at) ORDER BY hora
                """)
                ctx['por_hora'] = cur.fetchall()

            elif tipo == 'caja':
                cur.execute("""
                    SELECT fecha, estado, monto_apertura, total_ventas,
                           total_efectivo, total_nequi, total_daviplata, diferencia
                    FROM caja ORDER BY fecha DESC LIMIT 30
                """)
                rows = cur.fetchall()
                for r in rows:
                    r['fecha'] = r['fecha'].strftime('%d/%m/%Y')
                ctx['historial_caja'] = rows

        db.close()
    except Exception as e:
        return jsonify(success=False, message=f'Error al obtener datos: {str(e)}'), 500

    # ── Prompt compacto para Claude ───────────────────────────────────────────
    fecha_hoy = datetime.now().strftime('%d/%m/%Y')
    cfg = REPORTES_CONFIG.get(tipo, {'titulo': 'Reporte personalizado'})

    if tipo == 'personalizado':
        instruccion = personaliz or 'Genera un resumen general del negocio.'
    else:
        instruccion = f'Genera el reporte: {cfg["titulo"]}. {cfg["descripcion"]}.'

    prompt = f"""Eres analista de datos de "Arepazo de Carlitos", restaurante en Girardot, Colombia.
Fecha: {fecha_hoy}

DATOS:
{_json.dumps(ctx, ensure_ascii=False, default=str)[:3000]}

INSTRUCCIÓN: {instruccion}

Genera un reporte profesional en español con:
- Título claro
- Hallazgos principales (bullet points)
- Números concretos
- 1-2 recomendaciones accionables
- Conclusión breve

Formato legible, sin markdown excesivo. Máximo 400 palabras."""

    try:
        import requests as _req
        r = _req.post(CLAUDE_API_URL, json={
            'model': CLAUDE_MODEL,
            'max_tokens': 1000,
            'messages': [{'role': 'user', 'content': prompt}]
        }, headers={
            'x-api-key': ANTHROPIC_API_KEY,
            'anthropic-version': '2023-06-01',
            'content-type': 'application/json'
        }, timeout=45)
        r.raise_for_status()
        reporte = r.json()['content'][0]['text'].strip()
        titulo  = cfg.get('titulo', 'Reporte personalizado') if tipo != 'personalizado' else 'Reporte personalizado'
        registrar_log('reportes', f'generar_{tipo}', 'ok', {'tipo': tipo})
        return jsonify(success=True, reporte=reporte, titulo=titulo,
                       tipo=tipo, fecha=fecha_hoy)
    except Exception as e:
        return jsonify(success=False, message=f'Error al generar reporte: {str(e)}'), 500

# ═══════════════════════════════════════════════════════════════════════════════
#  MÓDULO PROMOCIONES — Stock bajo / vencimiento → Claude → homepage
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/dashboard/promociones')
@login_required
def dashboard_promociones():
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    return render_template('dashboard.html', section='promociones')

@app.route('/api/promociones', methods=['GET'])
def api_listar_promociones():
    """Público: devuelve promociones activas para la homepage."""
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("""
                SELECT id, nombre, descripcion, descuento_pct, precio_promo,
                       vigencia_hasta, producto_id
                FROM promociones WHERE activa=1
                ORDER BY created_at DESC
            """)
            rows = cur.fetchall()
        db.close()
        for r in rows:
            if r.get('vigencia_hasta'):
                r['vigencia_hasta'] = r['vigencia_hasta'].strftime('%d/%m/%Y')
        return jsonify(success=True, promociones=rows)
    except Exception as e:
        return jsonify(success=True, promociones=[])

@app.route('/api/promociones/generar', methods=['POST'])
@login_required
@csrf_protect
def api_generar_promociones():
    """Admin: Claude analiza stock crítico y sugiere promociones."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    if not ANTHROPIC_API_KEY:
        return jsonify(success=False, message='ANTHROPIC_API_KEY no configurada.'), 503

    try:
        db = get_db()
        with db.cursor() as cur:
            # Solo insumos críticos: stock bajo O vencen en ≤10 días
            cur.execute("""
                SELECT i.id, i.nombre, i.stock_actual, i.stock_minimo, i.unidad,
                       i.fecha_vencimiento,
                       DATEDIFF(i.fecha_vencimiento, CURDATE()) AS dias_vence
                FROM insumos i
                WHERE i.activo=1
                  AND (i.stock_actual <= i.stock_minimo
                       OR (i.fecha_vencimiento IS NOT NULL
                           AND DATEDIFF(i.fecha_vencimiento, CURDATE()) <= 10
                           AND DATEDIFF(i.fecha_vencimiento, CURDATE()) >= 0))
                ORDER BY dias_vence ASC, i.stock_actual ASC
                LIMIT 15
            """)
            criticos = cur.fetchall()

            if not criticos:
                db.close()
                return jsonify(success=True, sugerencias=[],
                               mensaje='No hay insumos críticos en este momento.')

            # Productos que usan esos insumos
            ids = [str(c['id']) for c in criticos]
            cur.execute(f"""
                SELECT DISTINCT p.id, p.nombre, p.precio
                FROM productos p
                JOIN recetas r ON r.producto_id=p.id
                WHERE r.insumo_id IN ({','.join(ids)}) AND p.disponible=1
            """)
            productos = cur.fetchall()
        db.close()

        # Preparar contexto compacto
        fecha_hoy = datetime.now().strftime('%d/%m/%Y')
        lista_criticos = []
        for c in criticos:
            fv = c['fecha_vencimiento']
            fv_str = fv.strftime('%d/%m/%Y') if fv else None
            lista_criticos.append({
                'nombre': c['nombre'],
                'stock': float(c['stock_actual']),
                'minimo': float(c['stock_minimo']),
                'unidad': c['unidad'],
                'vence_en': int(c['dias_vence']) if c['dias_vence'] is not None else None,
                'vence': fv_str
            })
        lista_productos = [{'id':p['id'],'nombre':p['nombre'],'precio':int(p['precio'])} for p in productos]

        prompt = f"""Eres asesor de un restaurante colombiano. Hoy es {fecha_hoy}.

INSUMOS CRÍTICOS (bajo stock o próximos a vencer):
{_json.dumps(lista_criticos, ensure_ascii=False)}

PRODUCTOS QUE LOS USAN:
{_json.dumps(lista_productos, ensure_ascii=False)}

Sugiere 2-4 promociones para usar estos insumos y reducir pérdidas.
Responde SOLO con JSON (sin texto extra):
[{{"producto_id":0,"nombre":"nombre de la promo","descripcion":"descripcion corta max 80 chars","razon":"por qué esta promo (max 100 chars)","descuento_pct":15,"precio_promo":12000,"vigencia_dias":3}}]

Si no hay suficiente info para sugerir, devuelve []."""

        import requests as _req
        r = _req.post(CLAUDE_API_URL, json={
            'model': CLAUDE_MODEL,
            'max_tokens': 800,
            'messages': [{'role':'user','content': prompt}]
        }, headers={
            'x-api-key': ANTHROPIC_API_KEY,
            'anthropic-version': '2023-06-01',
            'content-type': 'application/json'
        }, timeout=30)
        r.raise_for_status()
        texto = r.json()['content'][0]['text'].strip()

        # Limpiar markdown si viene
        if '```' in texto:
            partes = texto.split('```')
            texto = partes[1] if len(partes) > 1 else partes[0]
            if texto.startswith('json'):
                texto = texto[4:]

        sugerencias = _json.loads(texto.strip())
        registrar_log('promociones', 'generar', 'ok',
                      {'insumos_criticos': len(criticos), 'sugerencias': len(sugerencias)})
        return jsonify(success=True, sugerencias=sugerencias,
                       insumos_criticos=len(criticos))
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/promociones/guardar', methods=['POST'])
@login_required
@csrf_protect
def api_guardar_promociones():
    """Admin: guarda las promociones seleccionadas."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    data = request.get_json(silent=True) or {}
    promos = data.get('promociones', [])
    if not promos:
        return jsonify(success=False, message='Sin promociones.'), 400
    try:
        db = get_db()
        with db.cursor() as cur:
            for p in promos:
                vigencia = None
                dias = int(p.get('vigencia_dias') or 0)
                if dias > 0:
                    from datetime import timedelta
                    vigencia = (datetime.now() + timedelta(days=dias)).strftime('%Y-%m-%d')
                cur.execute("""
                    INSERT INTO promociones
                    (nombre, descripcion, razon, producto_id, descuento_pct,
                     precio_promo, vigencia_hasta, activa, creada_por)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,1,%s)
                """, (
                    sanitizar(p.get('nombre',''), max_len=200),
                    sanitizar(p.get('descripcion',''), max_len=400),
                    sanitizar(p.get('razon',''), max_len=300),
                    p.get('producto_id') or None,
                    min(80, max(0, int(p.get('descuento_pct') or 0))),
                    int(p.get('precio_promo') or 0),
                    vigencia,
                    session['user_id']
                ))
        db.commit(); db.close()
        registrar_log('promociones', 'guardar', 'ok', {'cantidad': len(promos)})
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/promociones/<int:pid>/toggle', methods=['POST'])
@login_required
@csrf_protect
def api_toggle_promocion(pid):
    """Admin: activa o desactiva una promoción."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("UPDATE promociones SET activa=1-activa WHERE id=%s", (pid,))
            cur.execute("SELECT activa FROM promociones WHERE id=%s", (pid,))
            nuevo = cur.fetchone()['activa']
        db.commit(); db.close()
        return jsonify(success=True, activa=nuevo)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/promociones/<int:pid>', methods=['DELETE'])
@login_required
@csrf_protect
def api_eliminar_promocion(pid):
    """Admin: elimina una promoción."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("DELETE FROM promociones WHERE id=%s", (pid,))
        db.commit(); db.close()
        return jsonify(success=True)
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

# ═══════════════════════════════════════════════════════════════════════════════
#  MÓDULO PRECIOS DE INSUMOS — Ítem 32
#  Usa Claude con web_search para consultar precios actuales de insumos
#  en el mercado colombiano.
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/dashboard/precios-insumos')
@login_required
def dashboard_precios_insumos():
    if session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
    return render_template('dashboard.html', section='precios_insumos')

@app.route('/api/precios-insumos/consultar', methods=['POST'])
@login_required
@csrf_protect
def api_consultar_precios():
    """Consulta precios actuales de insumos usando Claude con web search."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    data    = request.get_json(silent=True) or {}
    insumos = data.get('insumos', [])
    ciudad  = sanitizar(data.get('ciudad', 'Girardot, Cundinamarca'), max_len=80)
    if not insumos:
        return jsonify(success=False, message='Indica al menos un insumo.'), 400
    if len(insumos) > 15:
        return jsonify(success=False, message='Maximo 15 insumos por consulta.'), 400
    lista_str = ', '.join([sanitizar(i, max_len=60) for i in insumos[:15]])
    fecha_hoy = datetime.now().strftime('%d/%m/%Y')
    prompt = f"""Eres un asistente especializado en precios de alimentos e insumos para restaurantes colombianos.

Necesito los precios actuales (semana del {fecha_hoy}) de los siguientes insumos en {ciudad}, Colombia:
{lista_str}

Busca precios en supermercados, plazas de mercado y proveedores mayoristas de la region.

Responde UNICAMENTE con un JSON valido con esta estructura exacta (sin texto adicional, sin markdown):
{{
  "fecha_consulta": "{fecha_hoy}",
  "ciudad": "{ciudad}",
  "insumos": [
    {{
      "nombre": "nombre del insumo",
      "precio_min": 0,
      "precio_max": 0,
      "unidad": "kg/litro/unidad/etc",
      "fuente": "fuente consultada",
      "variacion": "subio/bajo/estable",
      "nota": "observacion relevante"
    }}
  ],
  "resumen": "observaciones generales del mercado esta semana"
}}"""

    api_key = os.environ.get('ANTHROPIC_API_KEY', '')
    if not api_key:
        return jsonify(success=False, message='ANTHROPIC_API_KEY no configurada en .env'), 500
    try:
        r = requests.post(
            'https://api.anthropic.com/v1/messages',
            headers={
                'x-api-key':         api_key,
                'anthropic-version': '2023-06-01',
                'content-type':      'application/json',
            },
            json={
                'model':      'claude-opus-4-5',
                'max_tokens': 2000,
                'tools': [{'type': 'web_search_20250305', 'name': 'web_search'}],
                'messages': [{'role': 'user', 'content': prompt}]
            },
            timeout=60
        )
        r.raise_for_status()
        data_resp = r.json()
        texto = ''
        for bloque in data_resp.get('content', []):
            if bloque.get('type') == 'text':
                texto += bloque.get('text', '')
        texto = texto.strip()
        if '```' in texto:
            partes = texto.split('```')
            texto  = partes[1] if len(partes) > 1 else partes[0]
            if texto.startswith('json'):
                texto = texto[4:]
        texto = texto.strip()
        resultado = _json.loads(texto)
        registrar_log('precios_insumos', 'consulta', 'ok', {'insumos': lista_str})
        return jsonify(success=True, resultado=resultado)
    except Exception as e:
        registrar_log('precios_insumos', 'consulta', 'error', {'error': str(e)})
        return jsonify(success=False, message=f'Error: {str(e)}'), 500

# ═══════════════════════════════════════════════════════════════════════════════
#  ARCHIVO DE RECUPERACIÓN
#  Genera un .txt descargable con un token único.
#  Para usarlo: subir el archivo en /recuperar → valida el token → login forzado.
# ═══════════════════════════════════════════════════════════════════════════════

def _hash_recovery(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()

@app.route('/api/recovery-file/generar', methods=['POST'])
@login_required
@csrf_protect
def api_generar_recovery_file():
    """Genera un archivo de recuperación para el admin."""
    if session.get('role') != 'admin':
        return jsonify(success=False, message='Sin permisos.'), 403
    try:
        from flask import Response
        token = secrets.token_hex(32)   # 64 chars hex — imposible de adivinar
        hashed = _hash_recovery(token)
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                "UPDATE usuarios SET recovery_hash=%s, recovery_creado=NOW() WHERE id=%s",
                (hashed, session['user_id'])
            )
        db.commit(); db.close()
        registrar_log('seguridad', 'generar_recovery_file', 'ok',
                      {'usuario_id': session['user_id']})
        # Construir el contenido del archivo
        fecha = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        contenido = f"""# ═══════════════════════════════════════════════════════
# AREPAZO DE CARLITOS — Archivo de recuperación de acceso
# ═══════════════════════════════════════════════════════
#
# ⚠️  GUARDA ESTE ARCHIVO EN UN LUGAR SEGURO Y OFFLINE
#     (USB, disco duro externo, impreso)
# ⚠️  NO lo compartas con nadie
# ⚠️  Es de UN SOLO USO — genera uno nuevo después de usarlo
#
# Generado: {fecha}
# ═══════════════════════════════════════════════════════

USUARIO={session['username']}
TOKEN={token}

# Instrucciones:
# 1. Ve a http://tudominio/recuperar
# 2. Selecciona "Usar archivo de recuperación"
# 3. Sube este archivo
# 4. El sistema te dará acceso y pedirá nueva contraseña
"""
        return Response(
            contenido,
            mimetype='text/plain',
            headers={
                'Content-Disposition': f'attachment; filename=arepazo_recovery_{session["username"]}.txt'
            }
        )
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

@app.route('/api/recovery-file/usar', methods=['POST'])
@limiter.limit('5 per 15 minutes')
def api_usar_recovery_file():
    """Valida el archivo de recuperación y da acceso con cambio de contraseña forzado."""
    # Recibir como form-data (archivo subido) o JSON con token
    token    = None
    username = None
    if 'archivo' in request.files:
        contenido = request.files['archivo'].read().decode('utf-8', errors='ignore')
        for line in contenido.splitlines():
            line = line.strip()
            if line.startswith('USUARIO='):
                username = sanitizar(line.split('=',1)[1].strip(), max_len=64)
            elif line.startswith('TOKEN='):
                token = line.split('=',1)[1].strip()
    else:
        data     = request.get_json(silent=True) or {}
        token    = (data.get('token') or '').strip()
        username = sanitizar(data.get('username') or '', max_len=64)

    if not token or not username:
        return jsonify(success=False, message='Archivo inválido o incompleto.'), 400
    if len(token) != 64:
        return jsonify(success=False, message='Token con formato incorrecto.'), 400

    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                """SELECT id, username, role, recovery_hash
                   FROM usuarios WHERE username=%s AND activo!=0 LIMIT 1""",
                (username,)
            )
            user = cur.fetchone()
        db.close()

        if not user or not user.get('recovery_hash'):
            registrar_log('seguridad', 'recovery_file_fallido', 'error',
                          {'username': username, 'motivo': 'usuario no encontrado o sin archivo'})
            return jsonify(success=False, message='Archivo incorrecto o no válido.'), 401

        if not _hmac.compare_digest(_hash_recovery(token), user['recovery_hash']):
            registrar_log('seguridad', 'recovery_file_fallido', 'error',
                          {'username': username, 'motivo': 'token no coincide'})
            return jsonify(success=False, message='Archivo incorrecto o no válido.'), 401

        # Válido — invalidar el token (un solo uso) y dar sesión con cambio forzado
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                "UPDATE usuarios SET recovery_hash=NULL, recovery_creado=NULL WHERE id=%s",
                (user['id'],)
            )
        db.commit(); db.close()

        session.permanent = True
        session['user_id']               = user['id']
        session['username']              = user['username']
        session['role']                  = user['role']
        session['must_change_password']  = True
        registrar_log('seguridad', 'recovery_file_exitoso', 'ok',
                      {'usuario_id': user['id'], 'username': username})
        return jsonify(success=True,
                       redirect=url_for('cambiar_password_page'),
                       aviso='Archivo válido. Debes crear una nueva contraseña.')
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

# ── Cambio de contraseña forzado (después de recuperación) ───────────────────
@app.route('/cambiar-password', methods=['GET'])
def cambiar_password_page():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    if not session.get('must_change_password'):
        return redirect(url_for('dashboard'))
    return render_template('cambiar_password.html')

@app.route('/api/cambiar-password', methods=['POST'])
def api_cambiar_password():
    if 'user_id' not in session:
        return jsonify(success=False, message='Sin sesión.'), 401
    if not session.get('must_change_password'):
        return jsonify(success=False, message='No se requiere cambio de contraseña.'), 400
    data      = request.get_json(silent=True) or {}
    nueva     = data.get('nueva', '').strip()
    confirmar = data.get('confirmar', '').strip()
    if not nueva or len(nueva) < 6:
        return jsonify(success=False, message='La contraseña debe tener al menos 6 caracteres.'), 400
    if nueva != confirmar:
        return jsonify(success=False, message='Las contraseñas no coinciden.'), 400
    try:
        nuevo_hash = hash_password_bcrypt(nueva)
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                "UPDATE usuarios SET password_hash=%s, hash_type='bcrypt' WHERE id=%s",
                (nuevo_hash, session['user_id'])
            )
        db.commit()
        db.close()
        session.pop('must_change_password', None)
        registrar_log('seguridad', 'cambio_password_forzado', 'ok',
                      {'usuario_id': session['user_id']})
        return jsonify(success=True, redirect=url_for('dashboard'))
    except Exception as e:
        return jsonify(success=False, message=str(e)), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
