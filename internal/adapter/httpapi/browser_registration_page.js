(() => {
  "use strict";
  const intentPath = /^\/register\/v1\/[A-Za-z0-9_-]{43}$/;
  const uuid7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

  // Signed out: remember this request in the tab and start Console sign-in.
  // Console returns here after sign-in only for an exact, fresh intent path.
  const signin = document.getElementById("registration-signin");
  if (signin) {
    const path = signin.dataset.path;
    if (!intentPath.test(path) || path !== window.location.pathname) return;
    try {
      window.sessionStorage.setItem("meshtransit.registration.return",
        JSON.stringify({ path, at: Date.now() }));
    } catch {
      return;
    }
    window.location.replace("/");
    return;
  }

  const form = document.getElementById("registration-form");
  const button = document.getElementById("registration-confirm");
  const status = document.getElementById("registration-status");
  if (!form || !button || !status) return;
  let started = false;
  const approve = async (event) => {
    event.preventDefault();
    if (started) return;
    const action = form.getAttribute("action");
    const selected = form.querySelector('input[name="network"]:checked');
    if (!selected) {
      status.textContent = "Choose a Network first.";
      return;
    }
    const workspace = selected.getAttribute("data-workspace");
    if (!intentPath.test(action) || action !== window.location.pathname ||
        !uuid7.test(workspace || "") || !uuid7.test(selected.value)) {
      button.disabled = true;
      status.textContent = "Restart login from Mesh Client.";
      return;
    }
    started = true;
    button.disabled = true;
    form.setAttribute("aria-busy", "true");
    status.textContent = "Approving device. Please wait.";
    const controller = new AbortController();
    const abort = () => controller.abort();
    const timer = setTimeout(abort, 15000);
    window.addEventListener("pagehide", abort, { once: true });
    try {
      // The landing page may have been open longer than the short CSRF lease.
      // Read a fresh proof from the same intent immediately before the POST;
      // the server still rechecks every authority boundary.
      const fresh = await fetch(window.location.href, {
        method: "GET", mode: "same-origin", credentials: "same-origin",
        redirect: "error", cache: "no-store", referrerPolicy: "no-referrer",
        signal: controller.signal,
      });
      if (fresh.status !== 200 || fresh.redirected || fresh.type !== "basic" ||
          fresh.headers.get("content-type") !== "text/html; charset=utf-8") {
        throw new Error("fresh proof unavailable");
      }
      const page = new DOMParser().parseFromString(await fresh.text(), "text/html");
      const refreshed = page.getElementById("registration-form");
      const proof = refreshed?.querySelector('input[name="csrf"]');
      const currentNetworks = refreshed?.querySelectorAll('input[name="network"]');
      if (refreshed?.getAttribute("action") !== action || !proof?.value || proof.value.length > 1024 ||
          !Array.from(currentNetworks || []).some((choice) =>
            choice.value === selected.value && choice.getAttribute("data-workspace") === workspace)) {
        throw new Error("registration authority changed");
      }
      const response = await fetch(action, {
        method: "POST", mode: "same-origin", credentials: "same-origin",
        redirect: "error", cache: "no-store", referrerPolicy: "no-referrer",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ csrf: proof.value, workspace, network: selected.value }).toString(),
        signal: controller.signal,
      });
      if (response.status !== 200 || response.redirected || response.type !== "basic" ||
          response.headers.get("content-type") !== "text/html; charset=utf-8") {
        throw new Error("approval unavailable");
      }
      if (response.body) await response.body.cancel();
      window.location.reload();
    } catch {
      status.textContent = "Approval could not be confirmed. Reload this page or restart login from Mesh Client.";
    } finally {
      clearTimeout(timer);
      controller.abort();
      window.removeEventListener("pagehide", abort);
      form.setAttribute("aria-busy", "false");
    }
  };
  form.addEventListener("submit", approve);
  button.addEventListener("click", approve);
})();
