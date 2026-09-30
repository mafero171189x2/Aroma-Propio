-- Aroma Propio: tablas de la base D1
-- Pegalo completo en Cloudflare: Storage y bases de datos > D1 > tu base > Consola > Execute

CREATE TABLE IF NOT EXISTS usuarios (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  nombre TEXT NOT NULL,
  telefono TEXT NOT NULL DEFAULT '',
  direccion TEXT NOT NULL DEFAULT '',
  entre_calles TEXT NOT NULL DEFAULT '',
  ciudad TEXT NOT NULL DEFAULT '',
  codigo_postal TEXT NOT NULL DEFAULT '',
  provincia TEXT NOT NULL DEFAULT '',
  salt TEXT NOT NULL,
  hash TEXT NOT NULL,
  iter INTEGER NOT NULL,
  creado INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS favoritos (
  usuario_id TEXT NOT NULL,
  producto_id TEXT NOT NULL,
  creado INTEGER NOT NULL,
  PRIMARY KEY (usuario_id, producto_id)
);

CREATE TABLE IF NOT EXISTS pedidos (
  id TEXT PRIMARY KEY,
  numero TEXT NOT NULL UNIQUE,
  usuario_id TEXT NOT NULL,
  estado TEXT NOT NULL DEFAULT 'pendiente',
  datos TEXT NOT NULL,
  total INTEGER NOT NULL,
  creado INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pedidos_usuario ON pedidos (usuario_id, creado DESC);
CREATE INDEX IF NOT EXISTS idx_pedidos_creado ON pedidos (creado DESC);

CREATE TABLE IF NOT EXISTS pedido_items (
  pedido_id TEXT NOT NULL,
  producto_id TEXT NOT NULL,
  cant INTEGER NOT NULL,
  PRIMARY KEY (pedido_id, producto_id)
);

CREATE INDEX IF NOT EXISTS idx_items_producto ON pedido_items (producto_id);

CREATE TABLE IF NOT EXISTS intentos (
  clave TEXT PRIMARY KEY,
  n INTEGER NOT NULL,
  ultimo INTEGER NOT NULL
);
