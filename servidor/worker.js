var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// worker.js
var ESTADOS = ["pendiente", "pagado", "preparacion", "enviado", "entregado", "cancelado"];
var DIA = 864e5;
var TOKEN_CLI_MS = 30 * DIA;
var TOKEN_ADM_MS = 12 * 36e5;
var ESQUEMA = [
  "CREATE TABLE IF NOT EXISTS usuarios (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, nombre TEXT NOT NULL, telefono TEXT NOT NULL DEFAULT '', direccion TEXT NOT NULL DEFAULT '', entre_calles TEXT NOT NULL DEFAULT '', ciudad TEXT NOT NULL DEFAULT '', codigo_postal TEXT NOT NULL DEFAULT '', provincia TEXT NOT NULL DEFAULT '', salt TEXT NOT NULL, hash TEXT NOT NULL, iter INTEGER NOT NULL, creado INTEGER NOT NULL)",
  "CREATE TABLE IF NOT EXISTS favoritos (usuario_id TEXT NOT NULL, producto_id TEXT NOT NULL, creado INTEGER NOT NULL, PRIMARY KEY (usuario_id, producto_id))",
  "CREATE TABLE IF NOT EXISTS pedidos (id TEXT PRIMARY KEY, numero TEXT NOT NULL UNIQUE, usuario_id TEXT NOT NULL, estado TEXT NOT NULL DEFAULT 'pendiente', datos TEXT NOT NULL, total INTEGER NOT NULL, creado INTEGER NOT NULL)",
  "CREATE INDEX IF NOT EXISTS idx_pedidos_usuario ON pedidos (usuario_id, creado DESC)",
  "CREATE INDEX IF NOT EXISTS idx_pedidos_creado ON pedidos (creado DESC)",
  "CREATE TABLE IF NOT EXISTS pedido_items (pedido_id TEXT NOT NULL, producto_id TEXT NOT NULL, cant INTEGER NOT NULL, PRIMARY KEY (pedido_id, producto_id))",
  "CREATE INDEX IF NOT EXISTS idx_items_producto ON pedido_items (producto_id)",
  "CREATE TABLE IF NOT EXISTS intentos (clave TEXT PRIMARY KEY, n INTEGER NOT NULL, ultimo INTEGER NOT NULL)",
  "CREATE TABLE IF NOT EXISTS tienda (id INTEGER PRIMARY KEY CHECK (id = 1), datos TEXT NOT NULL, version INTEGER NOT NULL, actualizado INTEGER NOT NULL)",
  "CREATE TABLE IF NOT EXISTS imagenes (id TEXT PRIMARY KEY, tipo TEXT NOT NULL, data TEXT NOT NULL, creado INTEGER NOT NULL)"
];
var esquemasListos = /* @__PURE__ */ new WeakSet();
async function asegurarEsquema(env) {
  if (!env.DB) throw new Fallo(500, "Falta conectar la base de datos (binding DB) al servidor.");
  if (esquemasListos.has(env.DB)) return;
  await env.DB.batch(ESQUEMA.map((q) => env.DB.prepare(q)));
  esquemasListos.add(env.DB);
}
__name(asegurarEsquema, "asegurarEsquema");
var enc = new TextEncoder();
var b64u = /* @__PURE__ */ __name((buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""), "b64u");
var b64uTxt = /* @__PURE__ */ __name((s) => b64u(enc.encode(s)), "b64uTxt");
var deB64u = /* @__PURE__ */ __name((s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)), "deB64u");
var hex = /* @__PURE__ */ __name((buf) => [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, "0")).join(""), "hex");
var deHex = /* @__PURE__ */ __name((h) => Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16)), "deHex");
var aleatorio = /* @__PURE__ */ __name((n) => hex(crypto.getRandomValues(new Uint8Array(n))), "aleatorio");
var txt = /* @__PURE__ */ __name((v, max) => String(v == null ? "" : v).trim().slice(0, max), "txt");
var emailOk = /* @__PURE__ */ __name((e) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e) && e.length <= 120, "emailOk");
var Fallo = class extends Error {
  static {
    __name(this, "Fallo");
  }
  constructor(status, mensaje, extra = {}) {
    super(mensaje);
    this.status = status;
    this.extra = extra;
  }
};
function corsHeaders(req, env) {
  const permitidos = String(env.ALLOWED_ORIGIN || "*").split(",").map((s) => s.trim().replace(/\/+$/, "")).filter(Boolean);
  const origen = req.headers.get("Origin") || "";
  let permitido = "*";
  if (!permitidos.includes("*")) permitido = permitidos.includes(origen) ? origen : permitidos[0];
  return {
    "Access-Control-Allow-Origin": permitido,
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}
__name(corsHeaders, "corsHeaders");
var json = /* @__PURE__ */ __name((obj, status, cors) => new Response(JSON.stringify(obj), {
  status: status || 200,
  headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...cors }
}), "json");
async function leerJson(req, tope = 2e5) {
  const largo = Number(req.headers.get("Content-Length") || 0);
  if (largo > tope) throw new Fallo(413, "Lo que intent\xE1s guardar es demasiado grande.");
  try {
    const j = await req.json();
    return j && typeof j === "object" ? j : {};
  } catch (e) {
    throw new Fallo(400, "Los datos enviados no son v\xE1lidos.");
  }
}
__name(leerJson, "leerJson");
async function derivar(pass, saltHex, iter) {
  const clave = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: deHex(saltHex), iterations: iter }, clave, 256);
  return hex(bits);
}
__name(derivar, "derivar");
function iguales(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
__name(iguales, "iguales");
var iteraciones = /* @__PURE__ */ __name((env) => Math.min(1e5, Math.max(1e3, parseInt(env.PBKDF2_ITER, 10) || 1e5)), "iteraciones");
async function llaveHmac(env) {
  if (!env.JWT_SECRET || String(env.JWT_SECRET).length < 16) throw new Fallo(500, "Falta configurar JWT_SECRET en el servidor.");
  return crypto.subtle.importKey("raw", enc.encode(env.JWT_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
__name(llaveHmac, "llaveHmac");
async function firmar(env, payload, vidaMs) {
  const cuerpo = b64uTxt(JSON.stringify({ ...payload, exp: Date.now() + vidaMs }));
  const sig = await crypto.subtle.sign("HMAC", await llaveHmac(env), enc.encode(cuerpo));
  return cuerpo + "." + b64u(sig);
}
__name(firmar, "firmar");
async function verificar(env, token) {
  const [cuerpo, sig] = String(token || "").split(".");
  if (!cuerpo || !sig) return null;
  try {
    const ok = await crypto.subtle.verify("HMAC", await llaveHmac(env), deB64u(sig), enc.encode(cuerpo));
    if (!ok) return null;
    const p = JSON.parse(new TextDecoder().decode(deB64u(cuerpo)));
    return p && p.exp > Date.now() ? p : null;
  } catch (e) {
    if (e instanceof Fallo) throw e;
    return null;
  }
}
__name(verificar, "verificar");
var bearer = /* @__PURE__ */ __name((req) => (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, ""), "bearer");
async function exigirCliente(req, env) {
  const p = await verificar(env, bearer(req));
  if (!p || p.rol !== "cli") throw new Fallo(401, "Tu sesi\xF3n venci\xF3. Volv\xE9 a ingresar.");
  const u = await env.DB.prepare("SELECT * FROM usuarios WHERE id = ?1").bind(p.sub).first();
  if (!u) throw new Fallo(401, "Tu sesi\xF3n venci\xF3. Volv\xE9 a ingresar.");
  return u;
}
__name(exigirCliente, "exigirCliente");
async function exigirAdmin(req, env) {
  const p = await verificar(env, bearer(req));
  if (!p || p.rol !== "adm") throw new Fallo(401, "La sesi\xF3n del panel venci\xF3. Volv\xE9 a ingresar.");
}
__name(exigirAdmin, "exigirAdmin");
async function bloqueado(env, clave, max, ventana) {
  const r = await env.DB.prepare("SELECT n, ultimo FROM intentos WHERE clave = ?1").bind(clave).first();
  return !!r && Date.now() - r.ultimo <= ventana && r.n >= max;
}
__name(bloqueado, "bloqueado");
async function sumarIntento(env, clave, ventana) {
  await env.DB.prepare(
    "INSERT INTO intentos (clave, n, ultimo) VALUES (?1, 1, ?2) ON CONFLICT(clave) DO UPDATE SET n = CASE WHEN ?2 - ultimo > ?3 THEN 1 ELSE n + 1 END, ultimo = ?2"
  ).bind(clave, Date.now(), ventana).run();
}
__name(sumarIntento, "sumarIntento");
var limpiarIntentos = /* @__PURE__ */ __name((env, clave) => env.DB.prepare("DELETE FROM intentos WHERE clave = ?1").bind(clave).run(), "limpiarIntentos");
var ipDe = /* @__PURE__ */ __name((req) => req.headers.get("CF-Connecting-IP") || "sin-ip", "ipDe");
var usuarioPublico = /* @__PURE__ */ __name((u) => ({
  id: u.id,
  email: u.email,
  nombre: u.nombre,
  telefono: u.telefono,
  direccion: u.direccion,
  entreCalles: u.entre_calles,
  ciudad: u.ciudad,
  codigoPostal: u.codigo_postal,
  provincia: u.provincia
}), "usuarioPublico");
async function favoritosDe(env, id) {
  const r = await env.DB.prepare("SELECT producto_id FROM favoritos WHERE usuario_id = ?1 ORDER BY creado").bind(id).all();
  return (r.results || []).map((x) => x.producto_id);
}
__name(favoritosDe, "favoritosDe");
var idProducto = /* @__PURE__ */ __name((v) => /^[\w-]{1,64}$/.test(String(v)) ? String(v) : null, "idProducto");
async function registro(req, env) {
  const b = await leerJson(req), ip = ipDe(req), clave = "reg|" + ip;
  if (await bloqueado(env, clave, 10, 36e5)) throw new Fallo(429, "Se crearon muchas cuentas desde esta conexi\xF3n. Prob\xE1 m\xE1s tarde.");
  const nombre = txt(b.nombre, 60), email = txt(b.email, 120).toLowerCase(), telefono = txt(b.telefono, 30), pass = String(b.password || "");
  if (!nombre) throw new Fallo(400, "Escrib\xED tu nombre.");
  if (!emailOk(email)) throw new Fallo(400, "Revis\xE1 el email: parece incompleto.");
  if (telefono.length < 6) throw new Fallo(400, "Escrib\xED un tel\xE9fono v\xE1lido.");
  if (pass.length < 6 || pass.length > 100) throw new Fallo(400, "La contrase\xF1a necesita entre 6 y 100 caracteres.");
  const ya = await env.DB.prepare("SELECT id FROM usuarios WHERE email = ?1").bind(email).first();
  if (ya) throw new Fallo(409, "Ya hay una cuenta con ese email. Ingres\xE1 con tu contrase\xF1a.");
  const id = aleatorio(12), salt = aleatorio(16), iter = iteraciones(env);
  const hash = await derivar(pass, salt, iter);
  try {
    await env.DB.prepare("INSERT INTO usuarios (id, email, nombre, telefono, salt, hash, iter, creado) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)").bind(id, email, nombre, telefono, salt, hash, iter, Date.now()).run();
  } catch (e) {
    throw new Fallo(409, "Ya hay una cuenta con ese email. Ingres\xE1 con tu contrase\xF1a.");
  }
  await sumarIntento(env, clave, 36e5);
  const u = await env.DB.prepare("SELECT * FROM usuarios WHERE id = ?1").bind(id).first();
  return { token: await firmar(env, { sub: id, rol: "cli" }, TOKEN_CLI_MS), usuario: usuarioPublico(u), favoritos: [] };
}
__name(registro, "registro");
async function login(req, env) {
  const b = await leerJson(req), email = txt(b.email, 120).toLowerCase(), pass = String(b.password || "");
  const clave = "login|" + email + "|" + ipDe(req);
  if (await bloqueado(env, clave, 5, 3e5)) throw new Fallo(429, "Demasiados intentos. Esper\xE1 unos minutos y prob\xE1 de nuevo.");
  const u = email ? await env.DB.prepare("SELECT * FROM usuarios WHERE email = ?1").bind(email).first() : null;
  const hash = await derivar(pass, u ? u.salt : aleatorio(16), u ? u.iter : iteraciones(env));
  if (!u || !iguales(hash, u.hash)) {
    await sumarIntento(env, clave, 3e5);
    throw new Fallo(401, "El email o la contrase\xF1a no son correctos.");
  }
  await limpiarIntentos(env, clave);
  return { token: await firmar(env, { sub: u.id, rol: "cli" }, TOKEN_CLI_MS), usuario: usuarioPublico(u), favoritos: await favoritosDe(env, u.id) };
}
__name(login, "login");
async function actualizarYo(req, env, u) {
  const b = await leerJson(req);
  const nombre = txt(b.nombre, 60) || u.nombre;
  await env.DB.prepare("UPDATE usuarios SET nombre = ?2, telefono = ?3, direccion = ?4, entre_calles = ?5, ciudad = ?6, codigo_postal = ?7, provincia = ?8 WHERE id = ?1").bind(u.id, nombre, txt(b.telefono, 30), txt(b.direccion, 120), txt(b.entreCalles, 120), txt(b.ciudad, 80), txt(b.codigoPostal, 12), txt(b.provincia, 60)).run();
  const n = await env.DB.prepare("SELECT * FROM usuarios WHERE id = ?1").bind(u.id).first();
  return { usuario: usuarioPublico(n) };
}
__name(actualizarYo, "actualizarYo");
async function cambiarPassword(req, env, u) {
  const b = await leerJson(req), clave = "pass|" + u.id;
  if (await bloqueado(env, clave, 5, 3e5)) throw new Fallo(429, "Demasiados intentos. Esper\xE1 unos minutos.");
  const actual = await derivar(String(b.actual || ""), u.salt, u.iter);
  if (!iguales(actual, u.hash)) {
    await sumarIntento(env, clave, 3e5);
    throw new Fallo(403, "La contrase\xF1a actual no es correcta.");
  }
  const nueva = String(b.nueva || "");
  if (nueva.length < 6 || nueva.length > 100) throw new Fallo(400, "La contrase\xF1a nueva necesita entre 6 y 100 caracteres.");
  const salt = aleatorio(16), iter = iteraciones(env);
  await env.DB.prepare("UPDATE usuarios SET salt = ?2, hash = ?3, iter = ?4 WHERE id = ?1").bind(u.id, salt, await derivar(nueva, salt, iter), iter).run();
  await limpiarIntentos(env, clave);
  return { ok: true };
}
__name(cambiarPassword, "cambiarPassword");
async function sincronizarFavoritos(req, env, u) {
  const b = await leerJson(req);
  const ids = [...new Set((Array.isArray(b.ids) ? b.ids : []).slice(0, 200).map(idProducto).filter(Boolean))];
  if (ids.length) {
    await env.DB.batch(ids.map((id) => env.DB.prepare("INSERT OR IGNORE INTO favoritos (usuario_id, producto_id, creado) VALUES (?1, ?2, ?3)").bind(u.id, id, Date.now())));
  }
  return { favoritos: await favoritosDe(env, u.id) };
}
__name(sincronizarFavoritos, "sincronizarFavoritos");
async function catalogo(env) {
  const f = await env.DB.prepare("SELECT datos FROM tienda WHERE id = 1").first();
  if (!f) return null;
  try {
    const d = JSON.parse(f.datos);
    return { mapa: Object.fromEntries((d.productos || []).map((p) => [String(p.id), Number(p.precio) > 0 ? p : { ...p, precio: Number((d.config || {}).precioGeneral) || 0 }])), envios: d.envios || {}, config: d.config || {} };
  } catch (e) {
    return null;
  }
}
__name(catalogo, "catalogo");
var precioCatalogo = /* @__PURE__ */ __name((p) => p.enOferta && Number(p.porcentajeDescuento) > 0 ? Math.round(p.precio * (1 - p.porcentajeDescuento / 100)) : Number(p.precio), "precioCatalogo");
async function vendidos(env) {
  const r = await env.DB.prepare(
    "SELECT pi.producto_id AS id, SUM(pi.cant) AS n FROM pedido_items pi JOIN pedidos p ON p.id = pi.pedido_id WHERE p.estado != 'cancelado' GROUP BY pi.producto_id"
  ).all();
  return Object.fromEntries((r.results || []).map((x) => [x.id, x.n]));
}
__name(vendidos, "vendidos");
function armarPedido(row) {
  let d = {};
  try {
    d = JSON.parse(row.datos);
  } catch (e) {
  }
  return {
    id: row.id,
    numero: row.numero,
    fecha: new Date(row.creado).toISOString(),
    clienteId: row.usuario_id,
    clienteEmail: d.clienteEmail || "",
    cliente: d.cliente || {},
    notas: d.notas || "",
    items: d.items || [],
    subtotal: d.subtotal || 0,
    envio: d.envio || 0,
    zona: d.zona || "",
    total: row.total,
    estado: row.estado,
    esRetiro: !!d.esRetiro,
    stockDevuelto: row.estado === "cancelado"
  };
}
__name(armarPedido, "armarPedido");
var numeroNuevo = /* @__PURE__ */ __name(() => {
  const f = (/* @__PURE__ */ new Date()).toISOString().slice(2, 10).replace(/-/g, "");
  const letras = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let s = "";
  for (const b of crypto.getRandomValues(new Uint8Array(4))) s += letras[b % letras.length];
  return "AP-" + f + "-" + s;
}, "numeroNuevo");
async function crearPedido(req, env, u) {
  const b = await leerJson(req);
  const esRetiro = !!b.esRetiro;
  if (!Array.isArray(b.items) || !b.items.length || b.items.length > 50) throw new Fallo(400, "El carrito est\xE1 vac\xEDo.");
  const porId = /* @__PURE__ */ new Map();
  for (const it of b.items) {
    const id2 = idProducto(it && it.id), cant = Math.floor(Number(it && it.cant)), precio = Math.round(Number(it && it.precio));
    if (!id2 || !(cant >= 1 && cant <= 99) || !(precio >= 0 && precio <= 1e8)) throw new Fallo(400, "Hay un producto con datos inv\xE1lidos en el carrito.");
    const ya = porId.get(id2);
    if (ya) {
      if (ya.precio !== precio) throw new Fallo(400, "Hay un producto repetido con distinto precio.");
      ya.cant += cant;
    } else porId.set(id2, { id: id2, nombre: txt(it.nombre, 140) || id2, precio, cant });
  }
  const items = [...porId.values()];
  if (items.some((i) => i.cant > 99)) throw new Fallo(400, "Cantidad demasiado grande.");
  const c = b.cliente || {};
  const cliente = {
    nombre: txt(c.nombre, 60),
    telefono: txt(c.telefono, 30),
    direccion: esRetiro ? "" : txt(c.direccion, 120),
    entreCalles: esRetiro ? "" : txt(c.entreCalles, 120),
    ciudad: esRetiro ? "" : txt(c.ciudad, 80),
    provincia: esRetiro ? "" : txt(c.provincia, 60),
    codigoPostal: esRetiro ? "" : txt(c.codigoPostal, 12)
  };
  if (!cliente.nombre || !cliente.telefono) throw new Fallo(400, "Complet\xE1 tu nombre y tel\xE9fono.");
  if (!esRetiro && !(cliente.direccion && cliente.ciudad && cliente.provincia && cliente.codigoPostal)) throw new Fallo(400, "Complet\xE1 la direcci\xF3n de env\xEDo.");
  const envio = esRetiro ? 0 : Math.round(Number(b.envio));
  let zonaNombre = esRetiro ? "Retiro en el local" : txt(b.zona, 60);
  if (!(envio >= 0 && envio <= 5e6)) throw new Fallo(400, "El costo de env\xEDo no es v\xE1lido.");
  const cat = await catalogo(env);
  if (cat) {
    for (const i of items) {
      const p = cat.mapa[i.id];
      if (!p || p.activo === false) throw new Fallo(409, `\u201C${i.nombre}\u201D ya no est\xE1 disponible.`, { codigo: "no-disponible", id: i.id });
      if (precioCatalogo(p) !== i.precio) throw new Fallo(409, "Los precios cambiaron. Recarg\xE1 la p\xE1gina y volv\xE9 a armar el carrito.", { codigo: "precios" });
    }
    if (esRetiro && !cat.config.retiroLocal) throw new Fallo(400, "El retiro en el local no est\xE1 habilitado.");
    if (!esRetiro) {
      const z = (cat.envios.zonas || []).find((x) => x.id === (cat.envios.provincias || {})[cliente.provincia]);
      if (!z && cat.envios.gratisTodo === false) throw new Fallo(400, "No hay tarifa de env\xEDo cargada para tu provincia. Consultanos por WhatsApp.");
      const sub0 = items.reduce((a, i) => a + i.precio * i.cant, 0), arts = items.reduce((a, i) => a + i.cant, 0), min = Number(cat.config.envioGratisDesde) || 0;
      const esperado = cat.envios.gratisTodo !== false || min > 0 && sub0 >= min ? 0 : Math.round(Number(z.precio) + Math.max(0, arts - 1) * (Number(cat.envios.adicional) || 0));
      if (esperado !== envio) throw new Fallo(409, "El costo de env\xEDo cambi\xF3. Recarg\xE1 la p\xE1gina y volv\xE9 a armar el carrito.", { codigo: "precios" });
      zonaNombre = txt(z ? z.nombre : 'Envio gratis', 60);
    }
  }
  const subtotal = items.reduce((a, i) => a + i.precio * i.cant, 0), total = subtotal + envio;
  const id = aleatorio(12), ahora = Date.now();
  const datos = JSON.stringify({ cliente, clienteEmail: u.email, notas: txt(b.notas, 500), items, subtotal, envio, zona: zonaNombre, esRetiro });
  let numero = "", insertado = false;
  for (let k = 0; k < 5 && !insertado; k++) {
    numero = numeroNuevo();
    const sentencias = [env.DB.prepare("INSERT INTO pedidos (id, numero, usuario_id, estado, datos, total, creado) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)").bind(id, numero, u.id, "pendiente", datos, total, ahora)];
    for (const i of items) {
      const p = cat && cat.mapa[i.id];
      if (p) {
        sentencias.push(env.DB.prepare(
          "INSERT INTO pedido_items (pedido_id, producto_id, cant) SELECT ?1, ?2, ?3 WHERE COALESCE((SELECT SUM(pi.cant) FROM pedido_items pi JOIN pedidos pe ON pe.id = pi.pedido_id WHERE pi.producto_id = ?2 AND pe.estado != 'cancelado'), 0) + ?3 <= ?4"
        ).bind(id, i.id, i.cant, cat.config.sinControlStock !== false ? 1e9 : Math.max(0, Math.floor(Number(p.stock) || 0))));
      } else {
        sentencias.push(env.DB.prepare("INSERT INTO pedido_items (pedido_id, producto_id, cant) VALUES (?1, ?2, ?3)").bind(id, i.id, i.cant));
      }
    }
    try {
      await env.DB.batch(sentencias);
      insertado = true;
    } catch (e) {
      if (!/UNIQUE.*numero|pedidos\.numero/i.test(String(e && e.message))) throw e;
    }
  }
  if (!insertado) throw new Fallo(500, "No se pudo generar el n\xFAmero de pedido. Prob\xE1 de nuevo.");
  const guardados = await env.DB.prepare("SELECT COUNT(*) AS n FROM pedido_items WHERE pedido_id = ?1").bind(id).first();
  if (guardados.n !== items.length) {
    await env.DB.batch([env.DB.prepare("DELETE FROM pedido_items WHERE pedido_id = ?1").bind(id), env.DB.prepare("DELETE FROM pedidos WHERE id = ?1").bind(id)]);
    const vend = await vendidos(env), faltan = [];
    for (const i of items) {
      const p = cat.mapa[i.id];
      const disp = Math.max(0, Math.floor(Number(p.stock) || 0) - (vend[i.id] || 0));
      if (disp < i.cant) faltan.push({ id: i.id, nombre: i.nombre, disponible: disp });
    }
    const f = faltan[0];
    throw new Fallo(409, f ? `De \u201C${f.nombre}\u201D ${f.disponible > 0 ? "quedan solo " + f.disponible : "no queda stock"}. Actualizamos tu carrito.` : "No hay stock suficiente. Actualizamos tu carrito.", { codigo: "stock", faltan });
  }
  const pisar = /* @__PURE__ */ __name((nuevo, viejo) => nuevo || viejo, "pisar");
  await env.DB.prepare("UPDATE usuarios SET nombre = ?2, telefono = ?3, direccion = ?4, entre_calles = ?5, ciudad = ?6, codigo_postal = ?7, provincia = ?8 WHERE id = ?1").bind(u.id, pisar(cliente.nombre, u.nombre), pisar(cliente.telefono, u.telefono), pisar(cliente.direccion, u.direccion), pisar(cliente.entreCalles, u.entre_calles), pisar(cliente.ciudad, u.ciudad), pisar(cliente.codigoPostal, u.codigo_postal), pisar(cliente.provincia, u.provincia)).run();
  const fila = await env.DB.prepare("SELECT * FROM pedidos WHERE id = ?1").bind(id).first();
  const nu = await env.DB.prepare("SELECT * FROM usuarios WHERE id = ?1").bind(u.id).first();
  return { pedido: armarPedido(fila), usuario: usuarioPublico(nu) };
}
__name(crearPedido, "crearPedido");
async function cancelarPedido(env, u, id) {
  const fila = await env.DB.prepare("SELECT * FROM pedidos WHERE id = ?1 AND usuario_id = ?2").bind(id, u.id).first();
  if (!fila) throw new Fallo(404, "No encontramos ese pedido.");
  if (fila.estado !== "pendiente" && fila.estado !== "cancelado") throw new Fallo(409, "Este pedido ya est\xE1 en proceso. Escribinos por WhatsApp para cancelarlo.");
  if (fila.estado === "pendiente") await env.DB.prepare("UPDATE pedidos SET estado = 'cancelado' WHERE id = ?1").bind(id).run();
  const n = await env.DB.prepare("SELECT * FROM pedidos WHERE id = ?1").bind(id).first();
  return { pedido: armarPedido(n) };
}
__name(cancelarPedido, "cancelarPedido");
async function adminLogin(req, env) {
  const b = await leerJson(req), clave = "admin|" + ipDe(req);
  if (!env.ADMIN_PASSWORD) throw new Fallo(500, "Falta configurar ADMIN_PASSWORD en el servidor.");
  if (await bloqueado(env, clave, 5, 3e5)) throw new Fallo(429, "Demasiados intentos. Esper\xE1 unos minutos y prob\xE1 de nuevo.");
  const a = hex(await crypto.subtle.digest("SHA-256", enc.encode(String(b.password || "")))), z = hex(await crypto.subtle.digest("SHA-256", enc.encode(String(env.ADMIN_PASSWORD))));
  if (!iguales(a, z)) {
    await sumarIntento(env, clave, 3e5);
    throw new Fallo(401, "Contrase\xF1a incorrecta.");
  }
  await limpiarIntentos(env, clave);
  return { token: await firmar(env, { rol: "adm" }, TOKEN_ADM_MS) };
}
__name(adminLogin, "adminLogin");
async function adminCambiarEstado(req, env, id) {
  const b = await leerJson(req), estado = String(b.estado || "");
  if (!ESTADOS.includes(estado)) throw new Fallo(400, "Estado inv\xE1lido.");
  const fila = await env.DB.prepare("SELECT * FROM pedidos WHERE id = ?1").bind(id).first();
  if (!fila) throw new Fallo(404, "No encontramos ese pedido.");
  if (fila.estado === "cancelado" && estado !== "cancelado") {
    const cat = await catalogo(env);
    if (cat) {
      const vend = await vendidos(env), datos = JSON.parse(fila.datos);
      for (const i of datos.items) {
        const p = cat.mapa[i.id];
        if (!p || cat.config.sinControlStock !== false) continue;
        if ((vend[i.id] || 0) + i.cant > Math.max(0, Math.floor(Number(p.stock) || 0))) throw new Fallo(409, `No hay stock suficiente de ${i.nombre} para reactivar el pedido.`);
      }
    }
  }
  await env.DB.prepare("UPDATE pedidos SET estado = ?2 WHERE id = ?1").bind(id, estado).run();
  const n = await env.DB.prepare("SELECT * FROM pedidos WHERE id = ?1").bind(id).first();
  return { pedido: armarPedido(n) };
}
__name(adminCambiarEstado, "adminCambiarEstado");
async function adminBorrarPedido(env, id) {
  const fila = await env.DB.prepare("SELECT estado FROM pedidos WHERE id = ?1").bind(id).first();
  if (!fila) throw new Fallo(404, "No encontramos ese pedido.");
  if (fila.estado !== "cancelado") throw new Fallo(409, "Solo se pueden eliminar pedidos cancelados.");
  await env.DB.batch([env.DB.prepare("DELETE FROM pedido_items WHERE pedido_id = ?1").bind(id), env.DB.prepare("DELETE FROM pedidos WHERE id = ?1").bind(id)]);
  return { ok: true };
}
__name(adminBorrarPedido, "adminBorrarPedido");
var RE_IMG = /^(?:https?:\/\/[^\/]+)?\/api\/img\/([0-9a-f]{24})$/;
async function normalizarImagen(u, nuevas) {
  u = String(u || "");
  let m = u.match(RE_IMG);
  if (m) return "/api/img/" + m[1];
  m = u.match(/^data:(image\/(?:jpeg|png|webp|gif));base64,([A-Za-z0-9+\/=]+)$/);
  if (m) {
    if (u.length > 15e5) throw new Fallo(413, "Una de las fotos es demasiado grande. Prob\xE1 con una m\xE1s chica.");
    const id = hex(await crypto.subtle.digest("SHA-256", enc.encode(u))).slice(0, 24);
    nuevas.set(id, { tipo: m[1], data: m[2] });
    return "/api/img/" + id;
  }
  return /^https?:\/\/\S+$/i.test(u) && u.length <= 500 ? u : "";
}
__name(normalizarImagen, "normalizarImagen");
async function leerTienda(env) {
  const f = await env.DB.prepare("SELECT version, datos FROM tienda WHERE id = 1").first();
  if (!f) return { version: 0, datos: null };
  return { version: f.version, datos: JSON.parse(f.datos) };
}
__name(leerTienda, "leerTienda");
async function versionTienda(env) {
  const f = await env.DB.prepare("SELECT version FROM tienda WHERE id = 1").first();
  return { version: f ? f.version : 0 };
}
__name(versionTienda, "versionTienda");
async function guardarTienda(req, env) {
  const b = await leerJson(req, 8e6), version = Number(b.version), d = b.datos;
  if (!Number.isInteger(version) || version < 0) throw new Fallo(400, "Falta la versi\xF3n del cat\xE1logo.");
  if (!d || typeof d !== "object" || !Array.isArray(d.productos) || !Array.isArray(d.categorias) || !d.config || typeof d.config !== "object" || !d.envios || typeof d.envios !== "object") throw new Fallo(400, "El cat\xE1logo enviado no es v\xE1lido.");
  if (d.productos.length > 400 || d.categorias.length > 60) throw new Fallo(413, "El cat\xE1logo es demasiado grande.");
  const vistos = /* @__PURE__ */ new Set();
  for (const p of d.productos) {
    if (!p || typeof p !== "object" || !idProducto(p.id) || vistos.has(String(p.id))) throw new Fallo(400, "Hay un producto con datos inv\xE1lidos.");
    vistos.add(String(p.id));
  }
  const nuevas = /* @__PURE__ */ new Map();
  const limpio = { categorias: d.categorias, productos: d.productos, config: d.config, envios: d.envios };
  for (const p of limpio.productos) p.imagenes = (await Promise.all((Array.isArray(p.imagenes) ? p.imagenes : []).slice(0, 6).map((u) => normalizarImagen(u, nuevas)))).filter(Boolean);
  limpio.config.bannerUrl = await normalizarImagen(limpio.config.bannerUrl, nuevas);
  const texto = JSON.stringify(limpio);
  if (texto.length > 15e5) throw new Fallo(413, "El cat\xE1logo es demasiado grande.");
  if (nuevas.size) {
    await env.DB.batch([...nuevas].map(([id, im]) => env.DB.prepare("INSERT OR IGNORE INTO imagenes (id, tipo, data, creado) VALUES (?1, ?2, ?3, ?4)").bind(id, im.tipo, im.data, Date.now())));
  }
  const fila = await env.DB.prepare("SELECT version FROM tienda WHERE id = 1").first();
  const choque = new Fallo(409, "El cat\xE1logo se cambi\xF3 desde otro dispositivo.", { codigo: "version" });
  let nueva;
  if (!fila) {
    if (version !== 0) throw choque;
    try {
      await env.DB.prepare("INSERT INTO tienda (id, datos, version, actualizado) VALUES (1, ?1, 1, ?2)").bind(texto, Date.now()).run();
    } catch (e) {
      throw choque;
    }
    nueva = 1;
  } else {
    if (fila.version !== version) throw choque;
    const r = await env.DB.prepare("UPDATE tienda SET datos = ?1, version = version + 1, actualizado = ?2 WHERE id = 1 AND version = ?3").bind(texto, Date.now(), version).run();
    if (!r.meta || r.meta.changes !== 1) throw choque;
    nueva = version + 1;
  }
  const usadas = new Set([...texto.matchAll(/\/api\/img\/([0-9a-f]{24})/g)].map((m) => m[1]));
  const todas = await env.DB.prepare("SELECT id FROM imagenes").all();
  const sobran = (todas.results || []).map((x) => x.id).filter((id) => !usadas.has(id));
  for (let k = 0; k < sobran.length; k += 50) {
    await env.DB.batch(sobran.slice(k, k + 50).map((id) => env.DB.prepare("DELETE FROM imagenes WHERE id = ?1").bind(id)));
  }
  return { version: nueva, datos: limpio };
}
__name(guardarTienda, "guardarTienda");
async function verImagen(env, id) {
  const f = await env.DB.prepare("SELECT tipo, data FROM imagenes WHERE id = ?1").bind(id).first();
  if (!f) throw new Fallo(404, "No existe la imagen.");
  return new Response(Uint8Array.from(atob(f.data), (c) => c.charCodeAt(0)), {
    headers: { "Content-Type": f.tipo, "Cache-Control": "public, max-age=31536000, immutable", "X-Content-Type-Options": "nosniff", "Cross-Origin-Resource-Policy": "cross-origin" }
  });
}
__name(verImagen, "verImagen");
async function ruteo(req, env, url) {
  const m = req.method, ruta = url.pathname.replace(/\/+$/, "") || "/";
  let x;
  if (ruta === "/" || ruta === "/api") return { ok: true, servicio: "Aroma Propio API" };
  if (ruta === "/api/salud" && m === "GET") {
    await env.DB.prepare("SELECT 1").first();
    return { ok: true, catalogo: !!await catalogo(env) };
  }
  if (ruta === "/api/stock" && m === "GET") return { vendidos: await vendidos(env) };
  if (ruta === "/api/tienda" && m === "GET") return leerTienda(env);
  if (ruta === "/api/tienda/version" && m === "GET") return versionTienda(env);
  if ((x = ruta.match(/^\/api\/img\/([0-9a-f]{24})$/)) && m === "GET") return verImagen(env, x[1]);
  if (ruta === "/api/registro" && m === "POST") return registro(req, env);
  if (ruta === "/api/login" && m === "POST") return login(req, env);
  if (ruta === "/api/admin/login" && m === "POST") return adminLogin(req, env);
  if (ruta.startsWith("/api/admin/")) {
    await exigirAdmin(req, env);
    if (ruta === "/api/admin/tienda" && m === "PUT") return guardarTienda(req, env);
    if (ruta === "/api/admin/pedidos" && m === "GET") {
      const r = await env.DB.prepare("SELECT * FROM pedidos ORDER BY creado DESC LIMIT 500").all();
      return { pedidos: (r.results || []).map(armarPedido) };
    }
    if (x = ruta.match(/^\/api\/admin\/pedidos\/([\w-]+)$/)) {
      if (m === "PUT") return adminCambiarEstado(req, env, x[1]);
      if (m === "DELETE") return adminBorrarPedido(env, x[1]);
    }
    throw new Fallo(404, "No existe.");
  }
  if (ruta.startsWith("/api/")) {
    const u = await exigirCliente(req, env);
    if (ruta === "/api/yo" && m === "GET") return { usuario: usuarioPublico(u), favoritos: await favoritosDe(env, u.id) };
    if (ruta === "/api/yo" && m === "PUT") return actualizarYo(req, env, u);
    if (ruta === "/api/yo/password" && m === "POST") return cambiarPassword(req, env, u);
    if (ruta === "/api/favoritos/sync" && m === "POST") return sincronizarFavoritos(req, env, u);
    if (x = ruta.match(/^\/api\/favoritos\/([\w-]{1,64})$/)) {
      if (m === "PUT") {
        await env.DB.prepare("INSERT OR IGNORE INTO favoritos (usuario_id, producto_id, creado) VALUES (?1, ?2, ?3)").bind(u.id, x[1], Date.now()).run();
        return { ok: true };
      }
      if (m === "DELETE") {
        await env.DB.prepare("DELETE FROM favoritos WHERE usuario_id = ?1 AND producto_id = ?2").bind(u.id, x[1]).run();
        return { ok: true };
      }
    }
    if (ruta === "/api/pedidos" && m === "GET") {
      const r = await env.DB.prepare("SELECT * FROM pedidos WHERE usuario_id = ?1 ORDER BY creado DESC LIMIT 100").bind(u.id).all();
      return { pedidos: (r.results || []).map(armarPedido) };
    }
    if (ruta === "/api/pedidos" && m === "POST") {
      if (await bloqueado(env, "ped|" + u.id, 20, 36e5)) throw new Fallo(429, "Hiciste muchos pedidos seguidos. Esper\xE1 un rato.");
      const r = await crearPedido(req, env, u);
      await sumarIntento(env, "ped|" + u.id, 36e5);
      return r;
    }
    if ((x = ruta.match(/^\/api\/pedidos\/([\w-]+)\/cancelar$/)) && m === "POST") return cancelarPedido(env, u, x[1]);
  }
  throw new Fallo(404, "No existe.");
}
__name(ruteo, "ruteo");
var worker_default = {
  async fetch(req, env) {
    const cors = corsHeaders(req, env);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    try {
      await asegurarEsquema(env);
      const r = await ruteo(req, env, new URL(req.url));
      if (r instanceof Response) {
        const h = new Headers(r.headers);
        for (const [k, v] of Object.entries(cors)) h.set(k, v);
        return new Response(r.body, { status: r.status, headers: h });
      }
      return json(r, 200, cors);
    } catch (e) {
      if (e instanceof Fallo) return json({ error: e.message, ...e.extra }, e.status, cors);
      console.error(e && e.stack ? e.stack : e);
      return json({ error: "Error interno del servidor. Prob\xE1 de nuevo en un momento." }, 500, cors);
    }
  }
};
export {
  worker_default as default
};
//# sourceMappingURL=worker.js.map
