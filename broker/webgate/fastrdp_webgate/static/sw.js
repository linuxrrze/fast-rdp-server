// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
// fastrdp-webgate service worker: shows approval notifications (Web Push) and opens the
// approval page when one is clicked. Nothing is cached; no fetch handler.
"use strict";

self.addEventListener("push", (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    data = {};
  }
  const options = {
    body: String(data.body || ""),
    icon: "static/icon-192.png",
    badge: "static/icon-192.png",
    data: { url: typeof data.url === "string" ? data.url : null },
    requireInteraction: !!data.url,
  };
  if (data.tag) options.tag = String(data.tag); // a later message replaces this one
  event.waitUntil(self.registration.showNotification(String(data.title || "fastrdp"), options));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const raw = event.notification.data && event.notification.data.url;
  if (!raw) return;
  // only pages of this webgate (the approval page), never another site
  const url = new URL(raw, self.registration.scope).href;
  if (!url.startsWith(self.registration.scope)) return;
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((list) => {
      for (const c of list) {
        if (c.url === url && "focus" in c) return c.focus();
      }
      return self.clients.openWindow(url);
    })
  );
});
