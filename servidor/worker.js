/* ======================================================================
   AROMA PROPIO — API (Cloudflare Worker + D1)
   Cuentas de clientes, favoritos, pedidos y stock vendido.
   El catálogo (productos y precios) sigue en datos.json en GitHub Pages.

   Necesita:
     - Base D1 conectada con el nombre de variable:  DB
     - Secret:   JWT_SECRET       (texto largo al azar)
     - Secret:   ADMIN_PASSWORD   (contraseña del panel del dueño)
     - Variable: ALLOWED_ORIGIN   (ej: https://mafero171189x2.github.io)
     - Variable (opcional): CATALOGO_URL
         (ej: https://mafero171189x2.github.io/Aroma-Propio/datos.json)
         Si está, el servidor verifica precios y stock contra ese archivo.
     - Variable (opcional): PBKDF2_ITER  (por defecto 100000)
   ====================================================================== */

const ESTADOS = ['pendiente', 'pagado', 'preparacion', 'enviado', 'entregado', 'cancelado'];
const DIA = 86400000;
const TOKEN_CLI_MS = 30 * DIA;
const TOKEN_ADM_MS = 12 * 3600000;

/* ---------- utilidades ---------- */
const enc = new TextEncoder();
const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64uTxt = s => b64u(enc.encode(s));
const deB64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const hex = buf => [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, '0')).join('');
const deHex = h => Uint8Array.from(h.match(/../g) || [], x => parseInt(x, 16));
const aleatorio = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const txt = (v, max) => String(v == null ? '' : v).trim().slice(0, max);
const emailOk = e => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e) && e.length <= 120;

class Fallo extends Error {
  constructor(status, mensaje, extra = {}) { super(mensaje); this.status = status; this.extra = extra; }
}

function corsHeaders(req, env) {
  const permitidos = String(env.ALLOWED_ORIGIN || '*').split(',').map(s => s.trim().replace(/\/+$/, '')).filter(Boolean);
  const origen = req.headers.get('Origin') || '';
  let permitido = '*';
  if (!permitidos.includes('*')) permitido = permitidos.includes(origen) ? origen : permitidos[0];
  return {
    'Access-Control-Allow-Origin': permitido,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}
const json = (obj, status, cors) => new Response(JSON.stringify(obj), {
  status: status || 200,
  headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...cors }
});

async function leerJson(req) {
  const largo = Number(req.headers.get('Content-Length') || 0);
  if (largo > 200000) throw new Fallo(413, 'El pedido es demasiado grande.');
  try { const j = await req.json(); return j && typeof j === 'object' ? j : {}; }
  catch (e) { throw new Fallo(400, 'Los datos enviados no son válidos.'); }
}

/* ---------- contraseñas y tokens ---------- */
async function derivar(pass, saltHex, iter) {
  const clave = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: deHex(saltHex), iterations: iter }, clave, 256);
  return hex(bits);
}
function iguales(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
const iteraciones = env => Math.min(100000, Math.max(1000, parseInt(env.PBKDF2_ITER, 10) || 100000));

async function llaveHmac(env) {
  if (!env.JWT_SECRET || String(env.JWT_SECRET).length < 16) throw new Fallo(500, 'Falta configurar JWT_SECRET en el servidor.');
  return crypto.subtle.importKey('raw', enc.encode(env.JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
async function firmar(env, payload, vidaMs) {
  const cuerpo = b64uTxt(JSON.stringify({ ...payload, exp: Date.now() + vidaMs }));
  const sig = await crypto.subtle.sign('HMAC', await llaveHmac(env), enc.encode(cuerpo));
  return cuerpo + '.' + b64u(sig);
}
async function verificar(env, token) {
  const [cuerpo, sig] = String(token || '').split('.');
  if (!cuerpo || !sig) return null;
  try {
    const ok = await crypto.subtle.verify('HMAC', await llaveHmac(env), deB64u(sig), enc.encode(cuerpo));
    if (!ok) return null;
    const p = JSON.parse(new TextDecoder().decode(deB64u(cuerpo)));
    return p && p.exp > Date.now() ? p : null;
  } catch (e) { if (e instanceof Fallo) throw e; return null; }
}
const bearer = req => (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');

async function exigirCliente(req, env) {
  const p = await verificar(env, bearer(req));
  if (!p || p.rol !== 'cli') throw new Fallo(401, 'Tu sesión venció. Volvé a ingresar.');
  const u = await env.DB.prepare('SELECT * FROM usuarios WHERE id = ?1').bind(p.sub).first();
  if (!u) throw new Fallo(401, 'Tu sesión venció. Volvé a ingresar.');
  return u;
}
async function exigirAdmin(req, env) {
  const p = await verificar(env, bearer(req));
  if (!p || p.rol !== 'adm') throw new Fallo(401, 'La sesión del panel venció. Volvé a ingresar.');
}

/* ---------- límite de intentos ---------- */
async function bloqueado(env, clave, max, ventana) {
  const r = await env.DB.prepare('SELECT n, ultimo FROM intentos WHERE clave = ?1').bind(clave).first();
  return !!r && Date.now() - r.ultimo <= ventana && r.n >= max;
}
async function sumarIntento(env, clave, ventana) {
  await env.DB.prepare(
    'INSERT INTO intentos (clave, n, ultimo) VALUES (?1, 1, ?2) ' +
    'ON CONFLICT(clave) DO UPDATE SET n = CASE WHEN ?2 - ultimo > ?3 THEN 1 ELSE n + 1 END, ultimo = ?2'
  ).bind(clave, Date.now(), ventana).run();
}
const limpiarIntentos = (env, clave) => env.DB.prepare('DELETE FROM intentos WHERE clave = ?1').bind(clave).run();
const ipDe = req => req.headers.get('CF-Connecting-IP') || 'sin-ip';

/* ---------- usuarios ---------- */
const usuarioPublico = u => ({
  id: u.id, email: u.email, nombre: u.nombre, telefono: u.telefono, direccion: u.direccion,
  entreCalles: u.entre_calles, ciudad: u.ciudad, codigoPostal: u.codigo_postal, provincia: u.provincia
});
async function favoritosDe(env, id) {
  const r = await env.DB.prepare('SELECT producto_id FROM favoritos WHERE usuario_id = ?1 ORDER BY creado').bind(id).all();
  return (r.results || []).map(x => x.producto_id);
}
const idProducto = v => (/^[\w-]{1,64}$/.test(String(v)) ? String(v) : null);

async function registro(req, env) {
  const b = await leerJson(req), ip = ipDe(req), clave = 'reg|' + ip;
  if (await bloqueado(env, clave, 10, 3600000)) throw new Fallo(429, 'Se crearon muchas cuentas desde esta conexión. Probá más tarde.');
  const nombre = txt(b.nombre, 60), email = txt(b.email, 120).toLowerCase(), telefono = txt(b.telefono, 30), pass = String(b.password || '');
  if (!nombre) throw new Fallo(400, 'Escribí tu nombre.');
  if (!emailOk(email)) throw new Fallo(400, 'Revisá el email: parece incompleto.');
  if (telefono.length < 6) throw new Fallo(400, 'Escribí un teléfono válido.');
  if (pass.length < 6 || pass.length > 100) throw new Fallo(400, 'La contraseña necesita entre 6 y 100 caracteres.');
  const ya = await env.DB.prepare('SELECT id FROM usuarios WHERE email = ?1').bind(email).first();
  if (ya) throw new Fallo(409, 'Ya hay una cuenta con ese email. Ingresá con tu contraseña.');
  const id = aleatorio(12), salt = aleatorio(16), iter = iteraciones(env);
  const hash = await derivar(pass, salt, iter);
  try {
    await env.DB.prepare('INSERT INTO usuarios (id, email, nombre, telefono, salt, hash, iter, creado) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)')
      .bind(id, email, nombre, telefono, salt, hash, iter, Date.now()).run();
  } catch (e) { throw new Fallo(409, 'Ya hay una cuenta con ese email. Ingresá con tu contraseña.'); }
  await sumarIntento(env, clave, 3600000);
  const u = await env.DB.prepare('SELECT * FROM usuarios WHERE id = ?1').bind(id).first();
  return { token: await firmar(env, { sub: id, rol: 'cli' }, TOKEN_CLI_MS), usuario: usuarioPublico(u), favoritos: [] };
}

async function login(req, env) {
  const b = await leerJson(req), email = txt(b.email, 120).toLowerCase(), pass = String(b.password || '');
  const clave = 'login|' + email + '|' + ipDe(req);
  if (await bloqueado(env, clave, 5, 300000)) throw new Fallo(429, 'Demasiados intentos. Esperá unos minutos y probá de nuevo.');
  const u = email ? await env.DB.prepare('SELECT * FROM usuarios WHERE email = ?1').bind(email).first() : null;
  /* si el email no existe igual se calcula un hash, así no se nota la diferencia de tiempo */
  const hash = await derivar(pass, u ? u.salt : aleatorio(16), u ? u.iter : iteraciones(env));
  if (!u || !iguales(hash, u.hash)) {
    await sumarIntento(env, clave, 300000);
    throw new Fallo(401, 'El email o la contraseña no son correctos.');
  }
  await limpiarIntentos(env, clave);
  return { token: await firmar(env, { sub: u.id, rol: 'cli' }, TOKEN_CLI_MS), usuario: usuarioPublico(u), favoritos: await favoritosDe(env, u.id) };
}

async function actualizarYo(req, env, u) {
  const b = await leerJson(req);
  const nombre = txt(b.nombre, 60) || u.nombre;
  await env.DB.prepare('UPDATE usuarios SET nombre = ?2, telefono = ?3, direccion = ?4, entre_calles = ?5, ciudad = ?6, codigo_postal = ?7, provincia = ?8 WHERE id = ?1')
    .bind(u.id, nombre, txt(b.telefono, 30), txt(b.direccion, 120), txt(b.entreCalles, 120), txt(b.ciudad, 80), txt(b.codigoPostal, 12), txt(b.provincia, 60)).run();
  const n = await env.DB.prepare('SELECT * FROM usuarios WHERE id = ?1').bind(u.id).first();
  return { usuario: usuarioPublico(n) };
}

async function cambiarPassword(req, env, u) {
  const b = await leerJson(req), clave = 'pass|' + u.id;
  if (await bloqueado(env, clave, 5, 300000)) throw new Fallo(429, 'Demasiados intentos. Esperá unos minutos.');
  const actual = await derivar(String(b.actual || ''), u.salt, u.iter);
  if (!iguales(actual, u.hash)) { await sumarIntento(env, clave, 300000); throw new Fallo(403, 'La contraseña actual no es correcta.'); }
  const nueva = String(b.nueva || '');
  if (nueva.length < 6 || nueva.length > 100) throw new Fallo(400, 'La contraseña nueva necesita entre 6 y 100 caracteres.');
  const salt = aleatorio(16), iter = iteraciones(env);
  await env.DB.prepare('UPDATE usuarios SET salt = ?2, hash = ?3, iter = ?4 WHERE id = ?1').bind(u.id, salt, await derivar(nueva, salt, iter), iter).run();
  await limpiarIntentos(env, clave);
  return { ok: true };
}

/* ---------- favoritos ---------- */
async function sincronizarFavoritos(req, env, u) {
  const b = await leerJson(req);
  const ids = [...new Set((Array.isArray(b.ids) ? b.ids : []).slice(0, 200).map(idProducto).filter(Boolean))];
  if (ids.length) {
    await env.DB.batch(ids.map(id => env.DB.prepare('INSERT OR IGNORE INTO favoritos (usuario_id, producto_id, creado) VALUES (?1, ?2, ?3)').bind(u.id, id, Date.now())));
  }
  return { favoritos: await favoritosDe(env, u.id) };
}

/* ---------- catálogo publicado (para verificar precios y stock) ---------- */
let cacheCat = { t: 0, url: '', mapa: null };
async function catalogo(env) {
  const url = txt(env.CATALOGO_URL, 300);
  if (!url) return null;
  if (cacheCat.url === url && Date.now() - cacheCat.t < 30000) return cacheCat.mapa;
  let mapa = null;
  try {
    const r = await fetch(url, { cf: { cacheTtl: 30, cacheEverything: true } });
    if (r.ok) {
      const j = await r.json();
      if (j && Array.isArray(j.productos)) mapa = Object.fromEntries(j.productos.map(p => [String(p.id), p]));
    }
  } catch (e) { mapa = null; }
  cacheCat = { t: Date.now(), url, mapa };
  return mapa;
}
const precioCatalogo = p => (p.enOferta && Number(p.porcentajeDescuento) > 0 ? Math.round(p.precio * (1 - p.porcentajeDescuento / 100)) : Number(p.precio));

async function vendidos(env) {
  const r = await env.DB.prepare(
    "SELECT pi.producto_id AS id, SUM(pi.cant) AS n FROM pedido_items pi JOIN pedidos p ON p.id = pi.pedido_id WHERE p.estado != 'cancelado' GROUP BY pi.producto_id"
  ).all();
  return Object.fromEntries((r.results || []).map(x => [x.id, x.n]));
}

/* ---------- pedidos ---------- */
function armarPedido(row) {
  let d = {};
  try { d = JSON.parse(row.datos); } catch (e) {}
  return {
    id: row.id, numero: row.numero, fecha: new Date(row.creado).toISOString(), clienteId: row.usuario_id, clienteEmail: d.clienteEmail || '',
    cliente: d.cliente || {}, notas: d.notas || '', items: d.items || [], subtotal: d.subtotal || 0, envio: d.envio || 0, zona: d.zona || '',
    total: row.total, estado: row.estado, esRetiro: !!d.esRetiro, stockDevuelto: row.estado === 'cancelado'
  };
}
const numeroNuevo = () => {
  const f = new Date().toISOString().slice(2, 10).replace(/-/g, '');
  const letras = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let s = ''; for (const b of crypto.getRandomValues(new Uint8Array(4))) s += letras[b % letras.length];
  return 'AP-' + f + '-' + s;
};

async function crearPedido(req, env, u) {
  const b = await leerJson(req);
  const esRetiro = !!b.esRetiro;
  if (!Array.isArray(b.items) || !b.items.length || b.items.length > 50) throw new Fallo(400, 'El carrito está vacío.');

  /* junto los renglones repetidos y valido cada uno */
  const porId = new Map();
  for (const it of b.items) {
    const id = idProducto(it && it.id), cant = Math.floor(Number(it && it.cant)), precio = Math.round(Number(it && it.precio));
    if (!id || !(cant >= 1 && cant <= 99) || !(precio >= 0 && precio <= 100000000)) throw new Fallo(400, 'Hay un producto con datos inválidos en el carrito.');
    const ya = porId.get(id);
    if (ya) { if (ya.precio !== precio) throw new Fallo(400, 'Hay un producto repetido con distinto precio.'); ya.cant += cant; }
    else porId.set(id, { id, nombre: txt(it.nombre, 140) || id, precio, cant });
  }
  const items = [...porId.values()];
  if (items.some(i => i.cant > 99)) throw new Fallo(400, 'Cantidad demasiado grande.');

  const c = b.cliente || {};
  const cliente = {
    nombre: txt(c.nombre, 60), telefono: txt(c.telefono, 30),
    direccion: esRetiro ? '' : txt(c.direccion, 120), entreCalles: esRetiro ? '' : txt(c.entreCalles, 120),
    ciudad: esRetiro ? '' : txt(c.ciudad, 80), provincia: esRetiro ? '' : txt(c.provincia, 60), codigoPostal: esRetiro ? '' : txt(c.codigoPostal, 12)
  };
  if (!cliente.nombre || !cliente.telefono) throw new Fallo(400, 'Completá tu nombre y teléfono.');
  if (!esRetiro && !(cliente.direccion && cliente.ciudad && cliente.provincia && cliente.codigoPostal)) throw new Fallo(400, 'Completá la dirección de envío.');
  const envio = esRetiro ? 0 : Math.round(Number(b.envio));
  if (!(envio >= 0 && envio <= 5000000)) throw new Fallo(400, 'El costo de envío no es válido.');

  /* verificación contra el catálogo publicado */
  const cat = await catalogo(env);
  if (cat) {
    for (const i of items) {
      const p = cat[i.id];
      if (!p || p.activo === false) throw new Fallo(409, `“${i.nombre}” ya no está disponible.`, { codigo: 'no-disponible', id: i.id });
      if (precioCatalogo(p) !== i.precio) throw new Fallo(409, 'Los precios cambiaron. Recargá la página y volvé a armar el carrito.', { codigo: 'precios' });
    }
  }

  const subtotal = items.reduce((a, i) => a + i.precio * i.cant, 0), total = subtotal + envio;
  const id = aleatorio(12), ahora = Date.now();
  const datos = JSON.stringify({ cliente, clienteEmail: u.email, notas: txt(b.notas, 500), items, subtotal, envio, zona: esRetiro ? 'Retiro en el local' : txt(b.zona, 60), esRetiro });

  let numero = '', insertado = false;
  for (let k = 0; k < 5 && !insertado; k++) {
    numero = numeroNuevo();
    const sentencias = [env.DB.prepare('INSERT INTO pedidos (id, numero, usuario_id, estado, datos, total, creado) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)').bind(id, numero, u.id, 'pendiente', datos, total, ahora)];
    for (const i of items) {
      const p = cat && cat[i.id];
      if (p) {
        sentencias.push(env.DB.prepare(
          "INSERT INTO pedido_items (pedido_id, producto_id, cant) SELECT ?1, ?2, ?3 WHERE COALESCE((SELECT SUM(pi.cant) FROM pedido_items pi JOIN pedidos pe ON pe.id = pi.pedido_id WHERE pi.producto_id = ?2 AND pe.estado != 'cancelado'), 0) + ?3 <= ?4"
        ).bind(id, i.id, i.cant, Math.max(0, Math.floor(Number(p.stock) || 0))));
      } else {
        sentencias.push(env.DB.prepare('INSERT INTO pedido_items (pedido_id, producto_id, cant) VALUES (?1, ?2, ?3)').bind(id, i.id, i.cant));
      }
    }
    try { await env.DB.batch(sentencias); insertado = true; }
    catch (e) { if (!/UNIQUE.*numero|pedidos\.numero/i.test(String(e && e.message))) throw e; }
  }
  if (!insertado) throw new Fallo(500, 'No se pudo generar el número de pedido. Probá de nuevo.');

  const guardados = await env.DB.prepare('SELECT COUNT(*) AS n FROM pedido_items WHERE pedido_id = ?1').bind(id).first();
  if (guardados.n !== items.length) {
    /* no alcanzó el stock para algún producto: deshago el pedido */
    await env.DB.batch([env.DB.prepare('DELETE FROM pedido_items WHERE pedido_id = ?1').bind(id), env.DB.prepare('DELETE FROM pedidos WHERE id = ?1').bind(id)]);
    const vend = await vendidos(env), faltan = [];
    for (const i of items) { const p = cat[i.id]; const disp = Math.max(0, Math.floor(Number(p.stock) || 0) - (vend[i.id] || 0)); if (disp < i.cant) faltan.push({ id: i.id, nombre: i.nombre, disponible: disp }); }
    const f = faltan[0];
    throw new Fallo(409, f ? `De “${f.nombre}” ${f.disponible > 0 ? 'quedan solo ' + f.disponible : 'no queda stock'}. Actualizamos tu carrito.` : 'No hay stock suficiente. Actualizamos tu carrito.', { codigo: 'stock', faltan });
  }

  /* guardo los datos de entrega en la cuenta para la próxima compra */
  const pisar = (nuevo, viejo) => nuevo || viejo;
  await env.DB.prepare('UPDATE usuarios SET nombre = ?2, telefono = ?3, direccion = ?4, entre_calles = ?5, ciudad = ?6, codigo_postal = ?7, provincia = ?8 WHERE id = ?1')
    .bind(u.id, pisar(cliente.nombre, u.nombre), pisar(cliente.telefono, u.telefono), pisar(cliente.direccion, u.direccion), pisar(cliente.entreCalles, u.entre_calles), pisar(cliente.ciudad, u.ciudad), pisar(cliente.codigoPostal, u.codigo_postal), pisar(cliente.provincia, u.provincia)).run();
  const fila = await env.DB.prepare('SELECT * FROM pedidos WHERE id = ?1').bind(id).first();
  const nu = await env.DB.prepare('SELECT * FROM usuarios WHERE id = ?1').bind(u.id).first();
  return { pedido: armarPedido(fila), usuario: usuarioPublico(nu) };
}

async function cancelarPedido(env, u, id) {
  const fila = await env.DB.prepare('SELECT * FROM pedidos WHERE id = ?1 AND usuario_id = ?2').bind(id, u.id).first();
  if (!fila) throw new Fallo(404, 'No encontramos ese pedido.');
  if (fila.estado !== 'pendiente' && fila.estado !== 'cancelado') throw new Fallo(409, 'Este pedido ya está en proceso. Escribinos por WhatsApp para cancelarlo.');
  if (fila.estado === 'pendiente') await env.DB.prepare("UPDATE pedidos SET estado = 'cancelado' WHERE id = ?1").bind(id).run();
  const n = await env.DB.prepare('SELECT * FROM pedidos WHERE id = ?1').bind(id).first();
  return { pedido: armarPedido(n) };
}

/* ---------- panel del dueño ---------- */
async function adminLogin(req, env) {
  const b = await leerJson(req), clave = 'admin|' + ipDe(req);
  if (!env.ADMIN_PASSWORD) throw new Fallo(500, 'Falta configurar ADMIN_PASSWORD en el servidor.');
  if (await bloqueado(env, clave, 5, 300000)) throw new Fallo(429, 'Demasiados intentos. Esperá unos minutos y probá de nuevo.');
  const a = hex(await crypto.subtle.digest('SHA-256', enc.encode(String(b.password || '')))), z = hex(await crypto.subtle.digest('SHA-256', enc.encode(String(env.ADMIN_PASSWORD))));
  if (!iguales(a, z)) { await sumarIntento(env, clave, 300000); throw new Fallo(401, 'Contraseña incorrecta.'); }
  await limpiarIntentos(env, clave);
  return { token: await firmar(env, { rol: 'adm' }, TOKEN_ADM_MS) };
}

async function adminCambiarEstado(req, env, id) {
  const b = await leerJson(req), estado = String(b.estado || '');
  if (!ESTADOS.includes(estado)) throw new Fallo(400, 'Estado inválido.');
  const fila = await env.DB.prepare('SELECT * FROM pedidos WHERE id = ?1').bind(id).first();
  if (!fila) throw new Fallo(404, 'No encontramos ese pedido.');
  if (fila.estado === 'cancelado' && estado !== 'cancelado') {
    const cat = await catalogo(env);
    if (cat) {
      const vend = await vendidos(env), datos = JSON.parse(fila.datos);
      for (const i of datos.items) {
        const p = cat[i.id]; if (!p) continue;
        if ((vend[i.id] || 0) + i.cant > Math.max(0, Math.floor(Number(p.stock) || 0))) throw new Fallo(409, `No hay stock suficiente de ${i.nombre} para reactivar el pedido.`);
      }
    }
  }
  await env.DB.prepare('UPDATE pedidos SET estado = ?2 WHERE id = ?1').bind(id, estado).run();
  const n = await env.DB.prepare('SELECT * FROM pedidos WHERE id = ?1').bind(id).first();
  return { pedido: armarPedido(n) };
}

async function adminBorrarPedido(env, id) {
  const fila = await env.DB.prepare('SELECT estado FROM pedidos WHERE id = ?1').bind(id).first();
  if (!fila) throw new Fallo(404, 'No encontramos ese pedido.');
  if (fila.estado !== 'cancelado') throw new Fallo(409, 'Solo se pueden eliminar pedidos cancelados.');
  await env.DB.batch([env.DB.prepare('DELETE FROM pedido_items WHERE pedido_id = ?1').bind(id), env.DB.prepare('DELETE FROM pedidos WHERE id = ?1').bind(id)]);
  return { ok: true };
}

/* ---------- ruteo ---------- */
async function ruteo(req, env, url) {
  const m = req.method, ruta = url.pathname.replace(/\/+$/, '') || '/';
  let x;

  if (ruta === '/' || ruta === '/api') return { ok: true, servicio: 'Aroma Propio API' };
  if (ruta === '/api/salud' && m === 'GET') {
    await env.DB.prepare('SELECT 1').first();
    return { ok: true, catalogo: !!(await catalogo(env)) };
  }
  if (ruta === '/api/stock' && m === 'GET') return { vendidos: await vendidos(env) };

  if (ruta === '/api/registro' && m === 'POST') return registro(req, env);
  if (ruta === '/api/login' && m === 'POST') return login(req, env);
  if (ruta === '/api/admin/login' && m === 'POST') return adminLogin(req, env);

  if (ruta.startsWith('/api/admin/')) {
    await exigirAdmin(req, env);
    if (ruta === '/api/admin/pedidos' && m === 'GET') {
      const r = await env.DB.prepare('SELECT * FROM pedidos ORDER BY creado DESC LIMIT 500').all();
      return { pedidos: (r.results || []).map(armarPedido) };
    }
    if ((x = ruta.match(/^\/api\/admin\/pedidos\/([\w-]+)$/))) {
      if (m === 'PUT') return adminCambiarEstado(req, env, x[1]);
      if (m === 'DELETE') return adminBorrarPedido(env, x[1]);
    }
    throw new Fallo(404, 'No existe.');
  }

  if (ruta.startsWith('/api/')) {
    const u = await exigirCliente(req, env);
    if (ruta === '/api/yo' && m === 'GET') return { usuario: usuarioPublico(u), favoritos: await favoritosDe(env, u.id) };
    if (ruta === '/api/yo' && m === 'PUT') return actualizarYo(req, env, u);
    if (ruta === '/api/yo/password' && m === 'POST') return cambiarPassword(req, env, u);
    if (ruta === '/api/favoritos/sync' && m === 'POST') return sincronizarFavoritos(req, env, u);
    if ((x = ruta.match(/^\/api\/favoritos\/([\w-]{1,64})$/))) {
      if (m === 'PUT') { await env.DB.prepare('INSERT OR IGNORE INTO favoritos (usuario_id, producto_id, creado) VALUES (?1, ?2, ?3)').bind(u.id, x[1], Date.now()).run(); return { ok: true }; }
      if (m === 'DELETE') { await env.DB.prepare('DELETE FROM favoritos WHERE usuario_id = ?1 AND producto_id = ?2').bind(u.id, x[1]).run(); return { ok: true }; }
    }
    if (ruta === '/api/pedidos' && m === 'GET') {
      const r = await env.DB.prepare('SELECT * FROM pedidos WHERE usuario_id = ?1 ORDER BY creado DESC LIMIT 100').bind(u.id).all();
      return { pedidos: (r.results || []).map(armarPedido) };
    }
    if (ruta === '/api/pedidos' && m === 'POST') {
      if (await bloqueado(env, 'ped|' + u.id, 20, 3600000)) throw new Fallo(429, 'Hiciste muchos pedidos seguidos. Esperá un rato.');
      const r = await crearPedido(req, env, u);
      await sumarIntento(env, 'ped|' + u.id, 3600000);
      return r;
    }
    if ((x = ruta.match(/^\/api\/pedidos\/([\w-]+)\/cancelar$/)) && m === 'POST') return cancelarPedido(env, u, x[1]);
  }
  throw new Fallo(404, 'No existe.');
}

export default {
  async fetch(req, env) {
    const cors = corsHeaders(req, env);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    try {
      const r = await ruteo(req, env, new URL(req.url));
      return json(r, 200, cors);
    } catch (e) {
      if (e instanceof Fallo) return json({ error: e.message, ...e.extra }, e.status, cors);
      console.error(e && e.stack ? e.stack : e);
      return json({ error: 'Error interno del servidor. Probá de nuevo en un momento.' }, 500, cors);
    }
  }
};
