// Navbar scroll effect
const navbar = document.getElementById('navbar');
window.addEventListener('scroll', () => {
  if (window.scrollY > 50) {
    navbar.style.background = 'rgba(26, 16, 8, 1)';
    navbar.style.boxShadow = '0 4px 20px rgba(0,0,0,0.5)';
  } else {
    navbar.style.background = 'rgba(26, 16, 8, 0.95)';
    navbar.style.boxShadow = 'none';
  }
});

// Hamburger menu
const hamburger = document.getElementById('hamburger');
hamburger.addEventListener('click', () => {
  const links = document.querySelector('.nav-links');
  links.style.display = links.style.display === 'flex' ? 'none' : 'flex';
  links.style.flexDirection = 'column';
  links.style.position = 'absolute';
  links.style.top = '70px';
  links.style.left = '0'; links.style.right = '0';
  links.style.background = 'rgba(26,16,8,0.98)';
  links.style.padding = '24px';
  links.style.gap = '20px';
});

// Counter animation
function animateCounters() {
  const counters = document.querySelectorAll('.counter-number');
  counters.forEach(counter => {
    const target = parseInt(counter.getAttribute('data-target'));
    const duration = 2000;
    const step = target / (duration / 16);
    let current = 0;
    const timer = setInterval(() => {
      current += step;
      if (current >= target) { current = target; clearInterval(timer); }
      counter.textContent = Math.floor(current);
    }, 16);
  });
}

// Trigger counter when visible
const countersSection = document.querySelector('.counters');
let counted = false;
const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting && !counted) {
      counted = true;
      animateCounters();
    }
  });
}, { threshold: 0.3 });

if (countersSection) observer.observe(countersSection);

// Fade-in on scroll
const fadeEls = document.querySelectorAll('.menu-card, .service-card, .stat-card, .schedule-item');
const fadeObs = new IntersectionObserver((entries) => {
  entries.forEach((entry, i) => {
    if (entry.isIntersecting) {
      setTimeout(() => {
        entry.target.style.opacity = '1';
        entry.target.style.transform = 'translateY(0)';
      }, i * 60);
      fadeObs.unobserve(entry.target);
    }
  });
}, { threshold: 0.1 });

fadeEls.forEach(el => {
  el.style.opacity = '0';
  el.style.transform = 'translateY(20px)';
  el.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
  fadeObs.observe(el);
});


// Highlight today's schedule
(function() {
  const dayMap = {
    0: 'domingo',
    1: 'lunes',
    2: 'martes',
    3: 'miercoles',
    4: 'jueves',
    5: 'viernes',
    6: 'sabado'
  };
  const today = dayMap[new Date().getDay()];
  const items = document.querySelectorAll('.schedule-item[data-day]');
  items.forEach(item => {
    if (item.getAttribute('data-day') === today) {
      item.classList.add('today');
    }
  });
})();


// Mapa de domicilios interactivo
(function() {
  const panel = document.getElementById('info-panel');
  const comunas = document.querySelectorAll('.comuna');
  const tarifaItems = document.querySelectorAll('.tarifa-item[data-ref]');

  const costos = {
    '1': { nombre: 'Comuna 1 – Centro', costo: '$3.000', nota: 'Zona más cercana al negocio. Entrega rápida ~15 min.', color: '#c8963e' },
    '2': { nombre: 'Comuna 2 – Sur', costo: '$5.000', nota: 'Zona sur de Girardot. Entrega aproximada ~25 min.', color: '#3a8c5c' },
    '3': { nombre: 'Comuna 3 – Occidente', costo: '$6.000', nota: 'Zona occidental. Entrega aproximada ~30 min.', color: '#c0392b' },
    '4': { nombre: 'Comuna 4 – Norte', costo: '$5.000', nota: 'Zona norte. Entrega aproximada ~25 min.', color: '#27ae60' },
    '5': { nombre: 'Comuna 5 – Oriente', costo: '$7.000', nota: 'Zona más lejana del casco urbano. ~35 min.', color: '#8e44ad' },
  };

  function mostrarInfo(data) {
    panel.innerHTML = `
      <div class="info-active">
        <span class="ia-label">Zona seleccionada</span>
        <span class="ia-nombre">${data.nombre}</span>
        <span class="ia-costo">${data.costo}</span>
        <span class="ia-label">Costo domicilio</span>
        <p class="ia-nota"><i class="fas fa-clock" style="color:#c8963e;margin-right:5px"></i>${data.nota}</p>
      </div>`;
  }

  comunas.forEach(c => {
    c.addEventListener('click', function() {
      comunas.forEach(x => x.classList.remove('activa'));
      this.classList.add('activa');
      const id = this.getAttribute('data-comuna');
      if (costos[id]) mostrarInfo(costos[id]);
    });
    c.addEventListener('mouseenter', function() {
      const id = this.getAttribute('data-comuna');
      if (costos[id]) mostrarInfo(costos[id]);
    });
    c.addEventListener('mouseleave', function() {
      const activa = document.querySelector('.comuna.activa');
      if (activa) {
        const id = activa.getAttribute('data-comuna');
        if (costos[id]) mostrarInfo(costos[id]);
      } else {
        panel.innerHTML = `<div class="info-default"><i class="fas fa-motorcycle"></i><p>Selecciona una <strong>zona en el mapa</strong> para conocer el costo del domicilio</p></div>`;
      }
    });
  });

  // Click on tarifa list highlights the map
  tarifaItems.forEach(item => {
    item.addEventListener('click', function() {
      const ref = this.getAttribute('data-ref');
      comunas.forEach(x => x.classList.remove('activa'));
      const target = document.querySelector(`[data-comuna="${ref}"]`);
      if (target) {
        target.classList.add('activa');
        if (costos[ref]) mostrarInfo(costos[ref]);
        target.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    });
  });
})();

/* ═══════════════════════════════════════════════════════════
   LOGIN MODAL
   ═══════════════════════════════════════════════════════════ */
(function () {
  const overlay   = document.getElementById('loginOverlay');
  const btnOpen   = document.getElementById('btnLoginNav');
  const btnClose  = document.getElementById('loginClose');
  const alertEl   = document.getElementById('loginAlert');
  const userInput = document.getElementById('loginUser');
  const passInput = document.getElementById('loginPass');
  const passToggle= document.getElementById('passToggle');
  const btnSubmit = document.getElementById('btnLoginSubmit');

  if (!overlay) return; // Seguridad: sólo en páginas que tengan el modal

  function openModal() {
    overlay.classList.add('open');
    document.body.style.overflow = 'hidden';
    setTimeout(() => userInput && userInput.focus(), 80);
  }

  function closeModal() {
    overlay.classList.remove('open');
    document.body.style.overflow = '';
    if (alertEl) alertEl.style.display = 'none';
  }

  btnOpen  && btnOpen.addEventListener('click', openModal);
  btnClose && btnClose.addEventListener('click', closeModal);

  // Cerrar al hacer clic en el fondo
  overlay.addEventListener('click', e => { if (e.target === overlay) closeModal(); });

  // Cerrar con Escape
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

  // Toggle contraseña
  if (passToggle && passInput) {
    passToggle.addEventListener('click', () => {
      passInput.type = passInput.type === 'password' ? 'text' : 'password';
      passToggle.querySelector('i').className =
        passInput.type === 'password' ? 'fas fa-eye' : 'fas fa-eye-slash';
    });
  }

  // Submit del login
  async function doLogin() {
    const username = userInput.value.trim();
    const password = passInput.value.trim();
    alertEl.style.display = 'none';

    if (!username || !password) {
      showAlert('Completa todos los campos.');
      return;
    }

    const btnText    = btnSubmit.querySelector('.btn-text');
    const btnSpinner = btnSubmit.querySelector('.btn-spinner');
    btnSubmit.disabled = true;
    if (btnText)    btnText.textContent = 'Verificando…';
    if (btnSpinner) btnSpinner.hidden = false;

    try {
      const res = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          password,
          recordar: document.getElementById('loginRecordar')?.checked || false
        }),
      });
      const data = await res.json();

      if (data.totp_required) {
        // Mostrar campo de código TOTP
        mostrarStepTOTP();
        return;
      }

      if (data.success) {
        window.location.href = data.redirect;
      } else {
        showAlert(data.message || 'Error al iniciar sesión.');
        btnSubmit.disabled = false;
        if (btnText)    btnText.textContent = 'Ingresar';
        if (btnSpinner) btnSpinner.hidden = true;
      }
    } catch {
      showAlert('Error de red. Intenta de nuevo.');
      btnSubmit.disabled = false;
      if (btnText)    btnText.textContent = 'Ingresar';
      if (btnSpinner) btnSpinner.hidden = true;
    }
  }

  function showAlert(msg) {
    alertEl.textContent = msg;
    alertEl.style.display = 'block';
  }

  btnSubmit && btnSubmit.addEventListener('click', doLogin);
  passInput && passInput.addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });

  // ── Paso 2: Código TOTP ──────────────────────────────────────────────────
  function mostrarStepTOTP() {
    const modal = document.querySelector('.login-modal');
    if (!modal) return;
    modal.innerHTML = `
      <div style="text-align:center;margin-bottom:20px">
        <div style="width:56px;height:56px;border-radius:50%;background:linear-gradient(135deg,#1565c0,#42a5f5);
                    display:flex;align-items:center;justify-content:center;margin:0 auto 12px;font-size:22px">🔐</div>
        <h2 style="font-family:'Playfair Display',serif;font-size:20px;color:#f5e6c8">Verificación en dos pasos</h2>
        <p style="color:#9a7a52;font-size:13px;margin-top:4px">Abre Google Authenticator e ingresa el código</p>
      </div>
      <div id="totp-err" style="display:none;background:#5c1a1a;border:1px solid #8b3030;color:#ffaaaa;
           padding:10px 14px;border-radius:8px;font-size:13px;margin-bottom:14px"></div>
      <div style="display:flex;gap:10px;justify-content:center;margin-bottom:20px">
        <input type="text" id="modal-totp-code" maxlength="6" placeholder="000000"
          style="width:160px;background:#1a1008;border:1px solid #3a2810;border-radius:10px;
                 padding:14px;color:#f5e6c8;font-size:28px;text-align:center;letter-spacing:10px;
                 font-family:monospace;outline:none"
          oninput="this.value=this.value.replace(/\\D/g,'').slice(0,6)"
          onkeydown="if(event.key==='Enter') doTOTP()"/>
      </div>
      <button onclick="doTOTP()" id="btn-totp"
        style="width:100%;padding:14px;border-radius:10px;border:none;font-size:15px;font-weight:700;
               cursor:pointer;background:linear-gradient(135deg,#c8963e,#e8b96a);color:#1a1008">
        Verificar
      </button>
      <div style="text-align:center;margin-top:14px">
        <a href="/recuperar" style="font-size:12px;color:#9a7a52;text-decoration:none">
          No tienes acceso a la app → usa un código de emergencia
        </a>
      </div>`;
    setTimeout(() => document.getElementById('modal-totp-code')?.focus(), 100);
  }

  async function doTOTP() {
    const codigo = document.getElementById('modal-totp-code')?.value.trim();
    const btn    = document.getElementById('btn-totp');
    const errEl  = document.getElementById('totp-err');
    if (!codigo || codigo.length !== 6) {
      errEl.textContent = 'Ingresa el código de 6 dígitos.';
      errEl.style.display = 'block'; return;
    }
    btn.disabled = true; btn.textContent = 'Verificando...';
    errEl.style.display = 'none';
    try {
      const res  = await fetch('/api/totp/verificar-login', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({codigo})
      });
      const data = await res.json();
      if (data.success) {
        window.location.href = data.redirect;
      } else {
        errEl.textContent   = data.message || 'Código incorrecto.';
        errEl.style.display = 'block';
        btn.disabled = false; btn.textContent = 'Verificar';
      }
    } catch {
      errEl.textContent   = 'Error de conexión.';
      errEl.style.display = 'block';
      btn.disabled = false; btn.textContent = 'Verificar';
    }
  }
  window.doTOTP = doTOTP;
})();
