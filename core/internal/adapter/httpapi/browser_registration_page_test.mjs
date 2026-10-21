// Deterministic script checks; real browser and client acceptance are separate.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const script = readFileSync(new URL("./browser_registration_page.js", import.meta.url), "utf8");
const action = "/register/v1/" + "A".repeat(43);
const network = "01890f00-0000-7000-8000-000000000201";
const workspace = "01890f00-0000-7000-8000-000000000101";

function harness(reply = {}, options = {}) {
  const events = new Map();
  const pageEvents = new Map();
  const timers = new Map();
  const calls = [];
  let reloads = 0;
  const button = { disabled: false, addEventListener(name, handler) { events.set(name, handler); } };
  const status = { textContent: "" };
  const form = {
    busy: "false",
    getAttribute(name) { assert.equal(name, "action"); return options.action ?? action; },
    querySelector(selector) {
      assert.equal(selector, 'input[name="network"]:checked');
      if (options.noSelection) return null;
      const chosenWorkspace = options.noWorkspace ? null : workspace;
      return { value: network, getAttribute(name) { assert.equal(name, "data-workspace"); return chosenWorkspace; } };
    },
    setAttribute(name, value) { assert.equal(name, "aria-busy"); this.busy = value; },
    addEventListener(name, handler) { events.set(name, handler); },
  };
  const document = { getElementById(id) {
    return { "registration-form": form, "registration-confirm": button, "registration-status": status }[id] ?? null;
  } };
  Object.defineProperty(document, "cookie", { get() { assert.fail("cookie access"); } });
  for (const element of [status, form]) {
    Object.defineProperty(element, "innerHTML", { set() { assert.fail("HTML injection"); } });
  }
  const window = {
    location: { pathname: action, href: `https://app.example.test${action}`, reload() { reloads++; },
      replace() { assert.fail("approval page never navigates away"); } },
    sessionStorage: { setItem() { assert.fail("approval page stores nothing"); } },
    addEventListener(name, handler) { pageEvents.set(name, handler); },
    removeEventListener(name, handler) { assert.equal(pageEvents.get(name), handler); pageEvents.delete(name); },
  };
  const sandbox = { document, window, AbortController, URLSearchParams,
    DOMParser: class { parseFromString() { return { getElementById(id) {
      assert.equal(id, "registration-form");
      return {
        getAttribute() { return options.freshAction ?? action; },
        querySelector(selector) {
          assert.equal(selector, 'input[name="csrf"]');
          return { value: options.freshProof ?? "fresh-proof" };
        },
        querySelectorAll(selector) {
          assert.equal(selector, 'input[name="network"]');
          const freshWorkspace = options.freshWorkspace ?? workspace;
          return options.noFreshNetwork ? [] : [{ value: network, getAttribute() { return freshWorkspace; } }];
        },
      };
    } }; } },
    setTimeout(handler, delay) { assert.equal(delay, 15000); timers.set(1, handler); return 1; },
    clearTimeout(id) { timers.delete(id); },
    async fetch(destination, options) {
      calls.push({ destination, options });
      if (reply.reject) throw new Error("private diagnostic");
      if (reply.pending) await new Promise((resolve, reject) => {
        options.signal.addEventListener("abort", () => reject(new Error("private timeout")), { once: true });
      });
      const isGet = options.method === "GET";
      return { status: (isGet ? reply.getStatus : reply.status) ?? 200,
        redirected: (isGet ? reply.getRedirected : reply.redirected) ?? false,
        type: (isGet ? reply.getType : reply.type) ?? "basic",
        headers: { get(name) { assert.equal(name, "content-type"); return (isGet ? reply.getContentType : reply.contentType) ?? "text/html; charset=utf-8"; } },
        async text() { return "fresh same-origin registration page"; },
        body: { async cancel() {} },
      };
    },
  };
  vm.runInNewContext(script, sandbox, { timeout: 1000 });
  return { calls, button, form, status, timers, pageEvents,
    get reloads() { return reloads; },
    activate(name = "click") { return events.get(name)({ preventDefault() {} }); },
  };
}

test("GET does not automatically approve", () => {
  const instance = harness();
  assert.equal(instance.calls.length, 0);
  assert.equal(instance.reloads, 0);
});

test("explicit activation refreshes proof then sends one exact same-origin approval", async () => {
  const instance = harness();
  const pending = instance.activate();
  await instance.activate("submit");
  await pending;
  assert.equal(instance.calls.length, 2);
  const refresh = instance.calls[0];
  assert.equal(refresh.destination, `https://app.example.test${action}`);
  assert.equal(refresh.options.method, "GET");
  assert.equal(refresh.options.credentials, "same-origin");
  assert.equal(refresh.options.referrerPolicy, "no-referrer");
  const call = instance.calls[1];
  assert.equal(call.destination, action);
  assert.equal(call.options.method, "POST");
  assert.equal(call.options.mode, "same-origin");
  assert.equal(call.options.credentials, "same-origin");
  assert.equal(call.options.redirect, "error");
  assert.equal(call.options.referrerPolicy, "no-referrer");
  assert.deepEqual([...new URLSearchParams(call.options.body)], [["csrf", "fresh-proof"], ["workspace", workspace], ["network", network]]);
  assert.equal(instance.reloads, 1);
  assert.equal(instance.timers.size, 0);
  assert.equal(instance.pageEvents.size, 0);
  assert.equal(refresh.options.signal.aborted, true);
  assert.equal(call.options.signal.aborted, true);
});

for (const [name, reply] of [
  ["forbidden", { status: 403 }], ["expired", { status: 404 }], ["unavailable", { status: 503 }],
  ["redirect", { redirected: true }], ["opaque", { type: "opaque" }],
  ["unexpected response", { contentType: "application/json" }], ["network failure", { reject: true }],
]) {
  test(`${name} never claims approval or automatically retries`, async () => {
    const instance = harness(reply);
    await instance.activate();
    await instance.activate();
    assert.equal(instance.calls.length, reply.reject ? 1 : 2);
    assert.equal(instance.reloads, 0);
    assert.match(instance.status.textContent, /^Approval could not be confirmed/);
    assert.equal(instance.status.textContent.includes("private"), false);
    assert.equal(instance.timers.size, 0);
    assert.equal(instance.pageEvents.size, 0);
  });
}

test("missing selection and foreign action never send", async () => {
  for (const options of [{ noSelection: true }, { noWorkspace: true }, { action: "https://evil.example.test/" },
    { action: "/register/v1/" + "B".repeat(43) }]) {
    const instance = harness({}, options);
    await instance.activate();
    assert.equal(instance.calls.length, 0);
  }
});

test("changed Workspace or missing Network blocks POST after proof refresh", async () => {
  for (const options of [{ freshWorkspace: "01890f00-0000-7000-8000-000000000102" },
    { noFreshNetwork: true }, { freshAction: "/register/v1/" + "B".repeat(43) }]) {
    const instance = harness({}, options);
    await instance.activate();
    assert.equal(instance.calls.length, 1);
    assert.match(instance.status.textContent, /^Approval could not be confirmed/);
  }
});

test("pagehide cancels a pending approval", async () => {
  const instance = harness({ pending: true });
  const pending = instance.activate();
  instance.pageEvents.get("pagehide")();
  await pending;
  assert.equal(instance.calls[0].options.signal.aborted, true);
  assert.equal(instance.timers.size, 0);
  assert.equal(instance.reloads, 0);
});

function signinHarness(path, pathname = action, storage = {}) {
  const navigation = [];
  const stored = [];
  const signin = { dataset: { path } };
  const document = { getElementById(id) { return id === "registration-signin" ? signin : null; } };
  const window = {
    location: { pathname, replace(destination) { navigation.push(destination); } },
    sessionStorage: { setItem(key, value) {
      if (storage.blocked) throw new Error("storage disabled");
      stored.push([key, JSON.parse(value)]);
    } },
  };
  vm.runInNewContext(script, { document, window, Date: { now: () => 1234 } }, { timeout: 1000 });
  return { navigation, stored };
}

test("signed-out landing remembers the exact intent in this tab and starts Console sign-in", () => {
  const instance = signinHarness(action);
  assert.deepEqual(instance.stored, [["meshtransit.registration.return", { path: action, at: 1234 }]]);
  assert.deepEqual(instance.navigation, ["/"]);
});

test("signed-out landing ignores foreign or mismatched paths and blocked storage", () => {
  for (const [path, pathname, storage] of [
    ["https://evil.example.test/", action, {}],
    ["/register/v1/" + "B".repeat(43), action, {}],
    ["/console", "/console", {}],
    [action, action, { blocked: true }],
  ]) {
    const instance = signinHarness(path, pathname, storage);
    assert.deepEqual(instance.navigation, []);
  }
});

function switchHarness(replies, options = {}) {
  const calls = [];
  const timers = new Map();
  let handler;
  let replaced = null;
  const stored = [];
  const switcher = { disabled: false, addEventListener(name, listener) { assert.equal(name, "click"); handler = listener; } };
  const note = { textContent: "" };
  const document = { getElementById(id) {
    return { "registration-switch": switcher, "registration-switch-status": note }[id] ?? null;
  } };
  Object.defineProperty(document, "cookie", { get() { assert.fail("cookie access"); } });
  const window = {
    location: { pathname: options.path ?? action, replace(destination) { replaced = destination; } },
    sessionStorage: { setItem(key, value) { stored.push([key, JSON.parse(value)]); } },
  };
  const sandbox = { document, window, AbortController, URLSearchParams,
    setTimeout(listener, delay) { assert.equal(delay, 15000); timers.set(1, listener); return 1; },
    clearTimeout(id) { timers.delete(id); },
    async fetch(destination, init) {
      calls.push({ destination, init });
      const reply = replies[calls.length - 1] ?? {};
      if (reply.reject) throw new Error("private diagnostic");
      return { status: reply.status, redirected: reply.redirected ?? false, type: reply.type ?? "basic",
        async json() { return reply.json; } };
    },
  };
  vm.runInNewContext(script, sandbox, { timeout: 1000 });
  return { calls, timers, note, switcher, stored,
    get replaced() { return replaced; },
    click() { return handler(); },
  };
}

const prepared = { status: 200, json: { csrf_token: "mtscsrf1.proof", expires_at: "2026-10-21T10:00:00Z" } };

test("use another account ends this browser session then restarts sign-in", async () => {
  const instance = switchHarness([prepared, { status: 204 }]);
  await instance.click();
  assert.deepEqual(instance.calls.map((call) => call.destination),
    ["/auth/v1/session/prepare", "/auth/v1/session/logout"]);
  for (const call of instance.calls) {
    assert.equal(call.init.method, "POST");
    assert.equal(call.init.mode, "same-origin");
    assert.equal(call.init.credentials, "same-origin");
    assert.equal(call.init.redirect, "error");
    assert.equal(call.init.body, "{}");
    assert.equal(call.init.headers["X-MeshTransit-Session"], "v1");
  }
  assert.equal(instance.calls[0].init.headers["X-MeshTransit-CSRF"], undefined);
  assert.equal(instance.calls[1].init.headers["X-MeshTransit-CSRF"], "mtscsrf1.proof");
  assert.equal(instance.stored.length, 1);
  assert.equal(instance.stored[0][0], "meshtransit.registration.return");
  assert.equal(instance.stored[0][1].path, action);
  assert.equal(instance.replaced, "/");
  assert.equal(instance.timers.size, 0);
});

for (const [name, replies] of [
  ["prepare refused", [{ status: 401 }]],
  ["malformed proof", [{ status: 200, json: { csrf_token: "forged proof" } }]],
  ["logout refused", [prepared, { status: 403 }]],
  ["logout redirected", [prepared, { status: 204, redirected: true }]],
  ["network failure", [{ reject: true }]],
]) {
  test(`use another account stays put when ${name}`, async () => {
    const instance = switchHarness(replies);
    await instance.click();
    assert.equal(instance.replaced, null);
    assert.equal(instance.stored.length, 0);
    assert.equal(instance.switcher.disabled, false);
    assert.match(instance.note.textContent, /^Could not sign out/);
    assert.equal(instance.note.textContent.includes("private"), false);
    assert.equal(instance.timers.size, 0);
  });
}

test("use another account ignores a page outside a registration request", async () => {
  const instance = switchHarness([], { path: "/elsewhere" });
  await instance.click();
  assert.equal(instance.calls.length, 0);
  assert.equal(instance.replaced, null);
});
