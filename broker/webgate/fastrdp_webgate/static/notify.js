// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Marcel Ritter <marcel@linux-ng.de>
// Opt-in page <prefix>/notify: turns on Web Push in this browser. Registers the service
// worker, asks for permission, subscribes with the webgate's VAPID key and POSTs the
// subscription (with the page's CSRF token) to <prefix>/notify/webpush.
"use strict";

(function () {
  const box = document.getElementById("webpush");
  if (!box) return;
  const status = document.getElementById("wp-status");
  const button = document.getElementById("wp-on");
  const label = document.getElementById("wp-label");
  const d = box.dataset;
  const say = (text) => { status.textContent = text; };

  const ios = /iPad|iPhone|iPod/.test(navigator.userAgent) ||
    (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
  const standalone = window.navigator.standalone === true ||
    window.matchMedia("(display-mode: standalone)").matches;

  if (!("serviceWorker" in navigator) || !("PushManager" in window) || !("Notification" in window)) {
    say(ios && !standalone
      ? "On iPhone and iPad: tap Share, then “Add to Home Screen”, open fastrdp from the " +
        "home screen and come back to this page there (iOS 16.4 or later)."
      : "This browser cannot receive push notifications. Use the ntfy app instead, if offered.");
    return;
  }

  function keyBytes(b64) {
    const s = (b64 + "=".repeat((4 - (b64.length % 4)) % 4)).replace(/-/g, "+").replace(/_/g, "/");
    return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  }

  function b64u(buf) {
    let s = "";
    new Uint8Array(buf).forEach((b) => { s += String.fromCharCode(b); });
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function known(sub) {
    // the page lists the first 16 hex digits of SHA-256 of each stored endpoint
    const h = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(sub.endpoint));
    const hex = Array.from(new Uint8Array(h).slice(0, 8), (b) => b.toString(16).padStart(2, "0")).join("");
    return (d.endpoints || "").split(" ").includes(hex);
  }

  async function register(sub) {
    const body = new URLSearchParams({
      csrf: d.csrf,
      endpoint: sub.endpoint,
      p256dh: b64u(sub.getKey("p256dh")),
      auth: b64u(sub.getKey("auth")),
      label: label.value,
    });
    const r = await fetch(d.post, { method: "POST", body: body, credentials: "same-origin" });
    if (!r.ok) throw new Error((await r.text()) || "HTTP " + r.status);
  }

  async function init() {
    const reg = await navigator.serviceWorker.register(d.sw, { scope: d.scope });
    const sub = await reg.pushManager.getSubscription();
    if (sub && (await known(sub))) {
      say("Notifications are on in this browser.");
      return;
    }
    if (Notification.permission === "denied") {
      say("Notifications are blocked for this site. Allow them in the browser's site settings first.");
      return;
    }
    say(ios && !standalone
      ? "On iPhone and iPad, open this page from the fastrdp icon on the home screen " +
        "(Share, “Add to Home Screen”) to turn notifications on."
      : "Notifications are off in this browser.");
    button.hidden = false;
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        if ((await Notification.requestPermission()) !== "granted") {
          say("Permission was not given.");
          return;
        }
        let s = await reg.pushManager.getSubscription();
        if (s && s.options && s.options.applicationServerKey &&
            b64u(s.options.applicationServerKey) !== d.key) {
          await s.unsubscribe(); // made with another server key
          s = null;
        }
        s = s || await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes(d.key) });
        await register(s);
        window.location.reload();
      } catch (e) {
        say("Could not turn notifications on: " + e.message);
      } finally {
        button.disabled = false;
      }
    });
  }

  init().catch((e) => say("Could not set up notifications: " + e.message));
})();
