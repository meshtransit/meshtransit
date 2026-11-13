(() => {
  "use strict";
  const intentPath = /^\/register\/v1\/[A-Za-z0-9_-]{43}$/;
  const uuid7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

  // A Workspace pick reloads the page and keeps the focus on the select:
  // read once, removed at once, honoured only for this page (see below).
  const focusKey = "meshtransit.registration.focus";
  let keptFocus = null;
  // Set once the page is leaving for another Workspace: no approval starts.
  // A load the person stopped (Esc) leaves the page usable again.
  let navigating = false;
  window.onpageshow = () => { navigating = false; };
  document.addEventListener?.("keydown", (event) => { if (event.key === "Escape") navigating = false; });
  try {
    const kept = window.sessionStorage?.getItem?.(focusKey);
    if (kept) {
      window.sessionStorage.removeItem(focusKey);
      keptFocus = JSON.parse(kept);
    }
  } catch {
    keptFocus = null;
  }

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

  // The browser may be signed in with the wrong account. End this browser's
  // Session, then start sign-in again from Console, where the identity
  // provider shows its account chooser. The request returns here as above.
  const switcher = document.getElementById("registration-switch");
  if (switcher) {
    const note = document.getElementById("registration-switch-status");
    let switching = false;
    switcher.addEventListener("click", async () => {
      const path = window.location.pathname;
      if (switching || navigating || !intentPath.test(path)) return;
      switching = true;
      switcher.disabled = true;
      if (note) note.textContent = "Signing out of this browser.";
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 15000);
      // Sent the way Console sends them: Core admits session calls in cors
      // mode only. The relative path keeps them on this origin.
      const post = (destination, extra) => fetch(destination, {
        method: "POST", credentials: "same-origin",
        redirect: "error", cache: "no-store", referrerPolicy: "no-referrer",
        headers: { Accept: "application/json", "Content-Type": "application/json",
          "X-MeshTransit-Session": "v1", ...extra },
        body: "{}", signal: controller.signal,
      });
      try {
        const prepared = await post("/auth/v1/session/prepare", {});
        if (prepared.status !== 200 || prepared.redirected || prepared.type !== "basic") {
          throw new Error("proof unavailable");
        }
        const proof = (await prepared.json())?.csrf_token;
        if (typeof proof !== "string" || proof.length > 256 || !/^mtscsrf1\.[A-Za-z0-9._-]+$/.test(proof)) {
          throw new Error("proof unavailable");
        }
        const ended = await post("/auth/v1/session/logout", { "X-MeshTransit-CSRF": proof });
        if (ended.status !== 204 || ended.redirected || ended.type !== "basic") {
          throw new Error("sign-out unavailable");
        }
        window.sessionStorage.setItem("meshtransit.registration.return",
          JSON.stringify({ path, at: Date.now() }));
        window.location.replace("/");
      } catch {
        switching = false;
        switcher.disabled = false;
        if (note) note.textContent = "Could not sign out. Sign out in Mesh Console, then reopen the link from Mesh Client.";
      } finally {
        clearTimeout(timer);
      }
    });
  }

  // "Use that account": this computer already is the person's Device in
  // that Network under another account in the app (duplicate-device §7).
  // A fresh proof is read first, as for approval; the result replaces the
  // card, since the ended sign-in has no page to reload.
  const joinStatus = document.getElementById("registration-join-status");
  for (const joinForm of document.querySelectorAll("form.sibling__form")) {
    let joining = false;
    joinForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (joining || navigating) return;
      const action = joinForm.getAttribute("action");
      const device = joinForm.getAttribute("data-join") || "";
      const joinButton = joinForm.querySelector("button");
      if (!intentPath.test(action) || action !== window.location.pathname || !uuid7.test(device)) {
        if (joinStatus) joinStatus.textContent = "Restart login from MeshTransit.";
        return;
      }
      joining = true;
      if (joinButton) joinButton.disabled = true;
      if (joinStatus) joinStatus.textContent = "Switching to that account. Please wait.";
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 15000);
      try {
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
        const refreshed = page.querySelector(`form.sibling__form[data-join="${device}"]`);
        const proof = refreshed?.querySelector('input[name="csrf"]');
        if (refreshed?.getAttribute("action") !== action || !proof?.value || proof.value.length > 1024) {
          throw new Error("registration authority changed");
        }
        const response = await fetch(action, {
          method: "POST", mode: "same-origin", credentials: "same-origin",
          redirect: "error", cache: "no-store", referrerPolicy: "no-referrer",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ csrf: proof.value, join: device }).toString(),
          signal: controller.signal,
        });
        if (response.status !== 200 || response.redirected || response.type !== "basic" ||
            response.headers.get("content-type") !== "text/html; charset=utf-8") {
          throw new Error("join unavailable");
        }
        const result = new DOMParser().parseFromString(await response.text(), "text/html")
          .getElementById("registration-joined");
        const card = joinForm.closest("section.card");
        if (!result || !card) throw new Error("join unavailable");
        card.replaceWith(document.importNode(result, true));
      } catch {
        joining = false;
        if (joinButton) joinButton.disabled = false;
        if (joinStatus) {
          joinStatus.textContent = "Could not switch accounts. Reload this page or restart login from MeshTransit.";
        }
      } finally {
        clearTimeout(timer);
      }
    });
  }

  // Workspace: choosing one shows its Networks. A pick with the pointer
  // loads them at once; with the keyboard, Enter or leaving the select does,
  // so arrowing (or a screen reader reading options) never reloads the page
  // midway. Only a Workspace other than the one shown reloads. The focus
  // comes back to the select. replace(): Back leaves the page rather than
  // walking through Workspaces. The button stays only without script.
  const workspaceSelect = document.getElementById("workspace-select");
  if (workspaceSelect) {
    const workspaceGo = document.getElementById("workspace-go");
    if (workspaceGo) workspaceGo.hidden = true;
    const shown = workspaceSelect.value;
    // A pointer pick: a pointerdown with no key pressed since (a click in an
    // open list reaches the select as no pointerdown, so it is kept a while).
    let pointerAt = -Infinity;
    const open = (focus) => {
      const path = window.location.pathname;
      const chosen = workspaceSelect.value;
      const approving = document.getElementById("registration-form")?.getAttribute("aria-busy") === "true";
      if (navigating || approving || chosen === shown || !intentPath.test(path) || !uuid7.test(chosen)) return;
      navigating = true;
      try {
        window.sessionStorage.setItem(focusKey, JSON.stringify({ path, workspace: chosen, focus, at: Date.now() }));
      } catch {
        // The focus just stays where the browser puts it.
      }
      window.location.replace(`${path}?workspace=${chosen}`);
    };
    workspaceSelect.addEventListener("pointerdown", () => { pointerAt = Date.now(); });
    workspaceSelect.addEventListener("keydown", (event) => {
      pointerAt = -Infinity;
      // After the browser commits an option the list may still show.
      if (event.key === "Enter") setTimeout(() => open("workspace"), 0);
    });
    workspaceSelect.addEventListener("change", () => {
      if (Date.now() - pointerAt < 60000) open("workspace");
    });
    // Leaving for the rest of the page, not for another window or tab.
    workspaceSelect.addEventListener("blur", () => {
      setTimeout(() => { if (document.hasFocus?.()) open("networks"); }, 0);
    });
    if (keptFocus && keptFocus.path === window.location.pathname && keptFocus.workspace === shown &&
        Date.now() - keptFocus.at < 10000) {
      const list = document.getElementById("network-list");
      const radio = keptFocus.focus === "networks"
        ? list?.querySelector("input:checked") ?? list?.querySelector("input")
        : null;
      (radio ?? workspaceSelect).focus();
    }
  }

  // Networks: the first ten, then Show more; a search box once there are
  // more than ten. Without a search, the chosen one stays in view.
  const networkList = document.getElementById("network-list");
  if (networkList) {
    const filter = document.getElementById("network-filter");
    const more = document.getElementById("network-more");
    const none = document.getElementById("network-none");
    const rows = Array.from(networkList.querySelectorAll("li"));
    const firstRows = 10;
    let expanded = rows.length <= firstRows;
    const show = () => {
      const query = (filter ? filter.value : "").trim().toLocaleLowerCase();
      let shown = 0;
      for (const row of rows) {
        const chosen = Boolean(row.querySelector("input:checked"));
        const matches = !query || (row.textContent || "").toLocaleLowerCase().includes(query);
        const visible = matches && (Boolean(query) || expanded || shown < firstRows || chosen);
        row.hidden = !visible;
        if (visible) shown += 1;
      }
      if (none) none.hidden = shown !== 0;
      if (more) more.hidden = expanded || Boolean(query);
    };
    if (filter && rows.length > firstRows) {
      filter.hidden = false;
      filter.addEventListener("input", show);
    }
    if (more) {
      more.addEventListener("click", () => {
        expanded = true;
        show();
        // The button is gone: keep the keyboard where the list went on.
        rows[firstRows]?.querySelector("input")?.focus();
      });
    }
    show();
    // The button names the Network chosen.
    const connect = document.getElementById("registration-confirm");
    if (connect) {
      const label = () => {
        const chosen = networkList.querySelector("input:checked");
        const name = chosen?.closest("label")?.querySelector(".choice__name")?.textContent;
        connect.textContent = name ? `Connect to ${name}` : "Connect device";
      };
      networkList.addEventListener("change", label);
      label();
    }
  }

  const form = document.getElementById("registration-form");
  const button = document.getElementById("registration-confirm");
  const status = document.getElementById("registration-status");
  if (!form || !button || !status) return;
  let started = false;
  const approve = async (event) => {
    event.preventDefault();
    if (navigating) {
      status.textContent = "Loading that Workspace's Networks.";
      return;
    }
    if (started) return;
    const action = form.getAttribute("action");
    const selected = form.querySelector('input[name="network"]:checked');
    if (!selected) {
      status.textContent = "Choose a Network first.";
      return;
    }
    const workspace = selected.getAttribute("data-workspace");
    // A computer that already is the person's Device in another Network
    // moves only when they tick the box (sign-in-moves-machine §7).
    const moveBox = form.querySelector('input[name="move"]');
    const ownNetwork = form.getAttribute("data-move-network") || "";
    const moving = Boolean(moveBox && ownNetwork && selected.value !== ownNetwork);
    if (moving && !moveBox.checked) {
      status.textContent = "Tick the box to move this computer to the Network you chose.";
      moveBox.focus();
      return;
    }
    if (moving && !uuid7.test(moveBox.value)) {
      button.disabled = true;
      status.textContent = "Restart login from MeshTransit.";
      return;
    }
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
      const currentMove = refreshed?.querySelector('input[name="move"]');
      if (moving && (currentMove?.value !== moveBox.value ||
          refreshed?.getAttribute("data-move-network") !== ownNetwork)) {
        throw new Error("the computer changed");
      }
      if (refreshed?.getAttribute("action") !== action || !proof?.value || proof.value.length > 1024 ||
          !Array.from(currentNetworks || []).some((choice) =>
            choice.value === selected.value && choice.getAttribute("data-workspace") === workspace)) {
        throw new Error("registration authority changed");
      }
      const response = await fetch(action, {
        method: "POST", mode: "same-origin", credentials: "same-origin",
        redirect: "error", cache: "no-store", referrerPolicy: "no-referrer",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(moving
          ? { csrf: proof.value, workspace, network: selected.value, move: moveBox.value }
          : { csrf: proof.value, workspace, network: selected.value }).toString(),
        signal: controller.signal,
      });
      if (response.status === 409) {
        // The page asks again: the move confirmation, or this computer is
        // already in that Network under another account.
        const retry = new DOMParser().parseFromString(await response.text(), "text/html");
        throw new Error(retry.getElementById("registration-conflict") ? "already here" : "move not confirmed");
      }
      if (response.status !== 200 || response.redirected || response.type !== "basic" ||
          response.headers.get("content-type") !== "text/html; charset=utf-8") {
        throw new Error("approval unavailable");
      }
      if (response.body) await response.body.cancel();
      window.location.reload();
    } catch (error) {
      const reason = error instanceof Error ? error.message : "";
      status.textContent = reason === "move not confirmed"
        ? "Tick the box to move this computer to the Network you chose."
        : reason === "already here"
          ? "This computer is already in that Network under another account. Reload this page to use that account."
          : "Approval could not be confirmed. Reload this page or restart login from MeshTransit.";
      started = false;
      button.disabled = false;
    } finally {
      clearTimeout(timer);
      controller.abort();
      window.removeEventListener("pagehide", abort);
      form.setAttribute("aria-busy", "false");
    }
  };
  // The move confirmation shows only once another Network than the
  // computer's own is chosen; choosing its own again clears it.
  const moveLabel = document.getElementById("registration-move");
  const ownNetwork = form.getAttribute("data-move-network") || "";
  if (moveLabel && ownNetwork) {
    const showMove = () => {
      const chosen = form.querySelector('input[name="network"]:checked');
      const elsewhere = Boolean(chosen && chosen.value !== ownNetwork);
      moveLabel.hidden = !elsewhere;
      if (!elsewhere) {
        const box = moveLabel.querySelector('input[name="move"]');
        if (box) box.checked = false;
      }
    };
    form.addEventListener("change", showMove);
    showMove();
  }
  form.addEventListener("submit", approve);
  button.addEventListener("click", approve);
})();
