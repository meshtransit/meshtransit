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
      if (selector === 'input[name="network"]:checked') return options.noSelection ? null : { value: network };
      if (selector === 'input[name="workspace"]') return options.noWorkspace ? null : { value: workspace };
      assert.equal(selector, 'input[name="csrf"]');
      return { value: "synthetic-proof" };
    },
    setAttribute(name, value) { assert.equal(name, "aria-busy"); this.busy = value; },
    addEventListener(name, handler) { events.set(name, handler); },
  };
  const document = { getElementById(id) {
    return { "registration-form": form, "registration-confirm": button, "registration-status": status }[id];
  } };
  Object.defineProperty(document, "cookie", { get() { assert.fail("cookie access"); } });
  for (const element of [status, form]) {
    Object.defineProperty(element, "innerHTML", { set() { assert.fail("HTML injection"); } });
  }
  const window = {
    location: { pathname: action, reload() { reloads++; } },
    addEventListener(name, handler) { pageEvents.set(name, handler); },
    removeEventListener(name, handler) { assert.equal(pageEvents.get(name), handler); pageEvents.delete(name); },
  };
  const sandbox = { document, window, AbortController, URLSearchParams,
    setTimeout(handler, delay) { assert.equal(delay, 15000); timers.set(1, handler); return 1; },
    clearTimeout(id) { timers.delete(id); },
    async fetch(destination, options) {
      calls.push({ destination, options });
      if (reply.reject) throw new Error("private diagnostic");
      if (reply.pending) await new Promise((resolve, reject) => {
        options.signal.addEventListener("abort", () => reject(new Error("private timeout")), { once: true });
      });
      return { status: reply.status ?? 200, redirected: reply.redirected ?? false, type: reply.type ?? "basic",
        headers: { get(name) { assert.equal(name, "content-type"); return reply.contentType ?? "text/html; charset=utf-8"; } },
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

test("explicit activation sends one exact same-origin approval and reloads", async () => {
  const instance = harness();
  const pending = instance.activate();
  await instance.activate("submit");
  await pending;
  assert.equal(instance.calls.length, 1);
  const call = instance.calls[0];
  assert.equal(call.destination, action);
  assert.equal(call.options.method, "POST");
  assert.equal(call.options.mode, "same-origin");
  assert.equal(call.options.credentials, "same-origin");
  assert.equal(call.options.redirect, "error");
  assert.equal(call.options.referrerPolicy, "no-referrer");
  assert.deepEqual([...new URLSearchParams(call.options.body)], [["csrf", "synthetic-proof"], ["workspace", workspace], ["network", network]]);
  assert.equal(instance.reloads, 1);
  assert.equal(instance.timers.size, 0);
  assert.equal(instance.pageEvents.size, 0);
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
    assert.equal(instance.calls.length, 1);
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

test("pagehide cancels a pending approval", async () => {
  const instance = harness({ pending: true });
  const pending = instance.activate();
  instance.pageEvents.get("pagehide")();
  await pending;
  assert.equal(instance.calls[0].options.signal.aborted, true);
  assert.equal(instance.timers.size, 0);
  assert.equal(instance.reloads, 0);
});
