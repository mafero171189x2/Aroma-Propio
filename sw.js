/* Aroma Propio: recibe los avisos push de nuevos pedidos. */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

self.addEventListener('push', e => {
  e.waitUntil(self.registration.showNotification('Nuevo pedido en Aroma Propio', {
    body: 'Entró un pedido nuevo. Tocá para verlo.',
    icon: 'fotos/001.jpg', badge: 'fotos/001.jpg', tag: 'pedido-nuevo', renotify: true,
    vibrate: [200, 100, 200, 100, 400], requireInteraction: true, data: { url: './#/admin/pedidos' }
  }));
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  const destino = new URL((e.notification.data && e.notification.data.url) || './', self.registration.scope).href;
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(lista => {
    for (const c of lista) if (c.url.startsWith(self.registration.scope) && 'focus' in c) { c.navigate(destino); return c.focus(); }
    return self.clients.openWindow(destino);
  }));
});
