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
    getAttribute(name) {
      if (name === "data-move-network") return null;
      assert.equal(name, "action");
      return options.action ?? action;
    },
    querySelector(selector) {
      if (selector === 'input[name="move"]') return null;
      assert.equal(selector, 'input[name="network"]:checked');
      if (options.noSelection) return null;
      const chosenWorkspace = options.noWorkspace ? null : workspace;
      return { value: network, getAttribute(name) { assert.equal(name, "data-workspace"); return chosenWorkspace; } };
    },
    setAttribute(name, value) { assert.equal(name, "aria-busy"); this.busy = value; },
    addEventListener(name, handler) { events.set(name, handler); },
  };
  const document = {
    getElementById(id) {
      return { "registration-form": form, "registration-confirm": button, "registration-status": status }[id] ?? null;
    },
    querySelectorAll(selector) { assert.equal(selector, "form.sibling__form"); return []; },
  };
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
      if (id === "registration-conflict") return options.conflict ? {} : null;
      assert.equal(id, "registration-form");
      return {
        getAttribute(name) { return name === "action" ? options.freshAction ?? action : null; },
        querySelector(selector) {
          if (selector === 'input[name="move"]') return null;
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
    // One activation is one attempt; the button comes back so the person
    // may try again themselves (schema 290: after ticking the move box).
    const instance = harness(reply);
    await instance.activate();
    assert.equal(instance.calls.length, reply.reject ? 1 : 2);
    assert.equal(instance.button.disabled, false);
    assert.equal(instance.reloads, 0);
    assert.match(instance.status.textContent, /^Approval could not be confirmed/);
    assert.equal(instance.status.textContent.includes("private"), false);
    assert.equal(instance.timers.size, 0);
    assert.equal(instance.pageEvents.size, 0);
  });
}

test("a computer already in that Network says so instead of the move hint", async () => {
  const instance = harness({ status: 409 }, { conflict: true });
  await instance.activate();
  assert.equal(instance.calls.length, 2);
  assert.equal(instance.reloads, 0);
  assert.match(instance.status.textContent, /^This computer is already in that Network under another account/);
});

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
  const document = {
    getElementById(id) {
      return { "registration-switch": switcher, "registration-switch-status": note }[id] ?? null;
    },
    querySelectorAll() { return []; },
  };
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
    assert.equal(call.init.mode, undefined);
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

const device = "01890f00-0000-7000-8000-000000000301";

function joinHarness(replies = [], options = {}) {
  const calls = [];
  const timers = new Map();
  let submit;
  let replacedWith = null;
  const button = { disabled: false };
  const joinStatus = { textContent: "" };
  const card = { replaceWith(node) { replacedWith = node; } };
  const joinForm = {
    getAttribute(name) {
      if (name === "action") return options.action ?? action;
      assert.equal(name, "data-join");
      return options.device ?? device;
    },
    querySelector(selector) { assert.equal(selector, "button"); return button; },
    closest(selector) { assert.equal(selector, "section.card"); return card; },
    addEventListener(name, listener) { assert.equal(name, "submit"); submit = listener; },
  };
  const joined = { id: "registration-joined" };
  const document = {
    getElementById(id) { return id === "registration-join-status" ? joinStatus : null; },
    querySelectorAll(selector) { assert.equal(selector, "form.sibling__form"); return [joinForm]; },
    importNode(node, deep) { assert.equal(deep, true); return { imported: node }; },
  };
  Object.defineProperty(document, "cookie", { get() { assert.fail("cookie access"); } });
  const window = { location: { pathname: action, href: `https://app.example.test${action}`,
    reload() { assert.fail("a joined sign-in has no page to reload"); } } };
  let parsed = 0;
  const sandbox = { document, window, AbortController, URLSearchParams,
    DOMParser: class { parseFromString() {
      parsed++;
      if (parsed === 1) {
        return { querySelector(selector) {
          assert.equal(selector, `form.sibling__form[data-join="${device}"]`);
          if (options.noFreshForm) return null;
          return { getAttribute(name) { assert.equal(name, "action"); return action; },
            querySelector(field) { assert.equal(field, 'input[name="csrf"]'); return { value: "fresh-proof" }; } };
        } };
      }
      return { getElementById(id) {
        assert.equal(id, "registration-joined");
        return options.noResult ? null : joined;
      } };
    } },
    setTimeout(listener, delay) { assert.equal(delay, 15000); timers.set(1, listener); return 1; },
    clearTimeout(id) { timers.delete(id); },
    async fetch(destination, init) {
      calls.push({ destination, init });
      const reply = replies[calls.length - 1] ?? {};
      if (reply.reject) throw new Error("private diagnostic");
      return { status: reply.status ?? 200, redirected: reply.redirected ?? false, type: reply.type ?? "basic",
        headers: { get(name) { assert.equal(name, "content-type"); return reply.contentType ?? "text/html; charset=utf-8"; } },
        async text() { return "same-origin page"; } };
    },
  };
  vm.runInNewContext(script, sandbox, { timeout: 1000 });
  return { calls, timers, button, joinStatus, joined,
    get replacedWith() { return replacedWith; },
    submit() { return submit({ preventDefault() {} }); },
  };
}

test("use that account refreshes proof, joins once and shows the result in place", async () => {
  const instance = joinHarness();
  await instance.submit();
  assert.equal(instance.calls.length, 2);
  assert.equal(instance.calls[0].init.method, "GET");
  const post = instance.calls[1];
  assert.equal(post.destination, action);
  assert.equal(post.init.method, "POST");
  assert.equal(post.init.mode, "same-origin");
  assert.equal(post.init.redirect, "error");
  assert.deepEqual([...new URLSearchParams(post.init.body)], [["csrf", "fresh-proof"], ["join", device]]);
  assert.deepEqual(instance.replacedWith, { imported: instance.joined });
  assert.equal(instance.timers.size, 0);
});

for (const [name, replies, options] of [
  ["refused", [{}, { status: 404 }], {}], ["unavailable", [{}, { status: 503 }], {}],
  ["redirected", [{}, { redirected: true }], {}], ["not a page", [{}, { contentType: "application/json" }], {}],
  ["network failure", [{ reject: true }], {}], ["gone from the fresh page", [{}], { noFreshForm: true }],
  ["no result", [{}, {}], { noResult: true }],
]) {
  test(`use that account stays put when ${name}`, async () => {
    const instance = joinHarness(replies, options);
    await instance.submit();
    assert.equal(instance.replacedWith, null);
    assert.equal(instance.button.disabled, false);
    assert.match(instance.joinStatus.textContent, /^Could not switch accounts/);
    assert.equal(instance.joinStatus.textContent.includes("private"), false);
    assert.equal(instance.timers.size, 0);
  });
}

test("use that account never sends for a foreign path or device", async () => {
  for (const options of [{ action: "https://evil.example.test/" }, { device: "x\"] , form" }]) {
    const instance = joinHarness([], options);
    await instance.submit();
    assert.equal(instance.calls.length, 0);
    assert.match(instance.joinStatus.textContent, /^Restart login/);
  }
});

function networkHarness(names) {
  const events = new Map();
  let chosen = null;
  let focused = null;
  const rows = names.map((name) => {
    const input = { name, focus() { focused = name; } };
    return {
      hidden: false, textContent: name,
      querySelector(selector) {
        if (selector === "input") return input;
        assert.equal(selector, "input:checked");
        return chosen === input ? input : null;
      },
      input,
    };
  });
  for (const row of rows) {
    row.input.closest = (selector) => {
      assert.equal(selector, "label");
      return { querySelector(selector) { assert.equal(selector, ".choice__name"); return { textContent: row.textContent }; } };
    };
  }
  const list = {
    querySelectorAll(selector) { assert.equal(selector, "li"); return rows; },
    querySelector(selector) { assert.equal(selector, "input:checked"); return chosen; },
    addEventListener(name, handler) { events.set(`list:${name}`, handler); },
  };
  const filter = { hidden: true, value: "", addEventListener(name, handler) { events.set(`filter:${name}`, handler); } };
  const more = { hidden: true, addEventListener(name, handler) { events.set(`more:${name}`, handler); } };
  const none = { hidden: true };
  const connect = { textContent: "Connect device" };
  const elements = { "network-list": list, "network-filter": filter, "network-more": more, "network-none": none,
    "registration-confirm": connect };
  const document = {
    getElementById(id) { return elements[id] ?? null; },
    querySelectorAll(selector) { assert.equal(selector, "form.sibling__form"); return []; },
  };
  vm.runInNewContext(script, { document, window: { location: { pathname: action } }, URLSearchParams }, { timeout: 1000 });
  return {
    rows, filter, more, none, connect,
    visible: () => rows.filter((row) => !row.hidden).map((row) => row.textContent),
    type(value) { filter.value = value; events.get("filter:input")(); },
    choose(index) { chosen = rows[index].input; events.get("list:change")(); },
    showMore() { events.get("more:click")(); },
    get focused() { return focused; },
  };
}

test("Networks: ten at first, search beyond, the chosen one stays, and the button names it", () => {
  const names = Array.from({ length: 13 }, (_, index) => `Net ${String(index).padStart(2, "0")}`);
  const page = networkHarness(names);
  assert.equal(page.visible().length, 10);
  assert.equal(page.filter.hidden, false);
  assert.equal(page.more.hidden, false);
  page.choose(12);
  assert.equal(page.connect.textContent, "Connect to Net 12");
  page.type("net 0");
  assert.deepEqual(page.visible(), names.slice(0, 10));
  assert.equal(page.more.hidden, true);
  page.type("nothing");
  assert.deepEqual(page.visible(), []);
  assert.equal(page.none.hidden, false);
  page.type("");
  page.showMore();
  assert.equal(page.visible().length, 13);
  assert.equal(page.more.hidden, true);
  assert.equal(page.focused, "Net 10");
});

test("Networks: a short list has no search box and no Show more", () => {
  const page = networkHarness(["Lab", "Office"]);
  assert.deepEqual(page.visible(), ["Lab", "Office"]);
  assert.equal(page.filter.hidden, true);
  assert.equal(page.more.hidden, true);
  assert.equal(page.connect.textContent, "Connect device");
});
