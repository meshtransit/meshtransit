// Deterministic source qualification, not a browser or live-provider acceptance test.
// Run with Node's built-in test runner; no packages, network or runtime Node dependency.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const html = readFileSync(new URL("./login_continuation_landing.html", import.meta.url), "utf8");
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const path = "/auth/v1/login/continue";
const prepared = '{"csrf_token":"syntheticProof_1","expires_in":60}';
const completed = '{"return_path":"/console"}';
const failure = "Sign-in could not be completed. Restart sign-in to try again.";

function harness(replies = [{ text: prepared }, { text: completed }], expectedPath = "/console",
  { visibilityState = "visible", prerendering = false } = {}) {
  const pageEvents = new Map();
  const documentEvents = new Map();
  const timers = new Map();
  const calls = [];
  const navigation = [];
  const history = [];
  const releases = [];
  const status = { textContent: "" };
  const restart = { hidden: true };
  const panel = { busy: "true", dataset: { returnPath: expectedPath },
    setAttribute(name, value) { assert.equal(name, "aria-busy"); this.busy = value; } };
  for (const element of [status, panel, restart]) {
    Object.defineProperty(element, "innerHTML", { set() { assert.fail("dynamic HTML"); } });
  }
  const document = { visibilityState, prerendering,
    getElementById(id) { return { "login-status": status, "login-panel": panel, "login-restart": restart }[id]; },
    addEventListener(name, handler) { documentEvents.set(name, handler); },
    removeEventListener(name, handler) { assert.equal(documentEvents.get(name), handler); documentEvents.delete(name); } };
  Object.defineProperty(document, "cookie", { get() { assert.fail("cookie read"); } });
  const location = { replace(destination) { navigation.push(destination); } };
  for (const name of ["search", "hash", "href", "pathname"]) {
    Object.defineProperty(location, name, { get() { assert.fail("location material read"); } });
  }
  const window = { location, history: { replaceState(...args) { history.push(args); } },
    addEventListener(name, handler) { pageEvents.set(name, handler); },
    removeEventListener(name, handler) { assert.equal(pageEvents.get(name), handler); pageEvents.delete(name); } };
  for (const owner of [window, document]) {
    for (const name of ["localStorage", "sessionStorage"]) {
      Object.defineProperty(owner, name, { get() { assert.fail("persistent storage"); } });
    }
  }
  const sandbox = { window, document, AbortController, Uint8Array, TextDecoder,
    console: new Proxy({}, { get() { assert.fail("browser diagnostics"); } }),
    setTimeout(handler, delay) { assert.equal(delay, 30000); timers.set(1, handler); return 1; },
    clearTimeout(id) { timers.delete(id); },
    async fetch(destination, options) {
      calls.push({ destination, options });
      const reply = replies[calls.length - 1];
      assert.ok(reply, "unexpected retry/fetch");
      if (reply.reject) throw new Error("synthetic-private-provider-diagnostic");
      if (reply.pending) {
        await new Promise((resolve, reject) => {
          options.signal.addEventListener("abort", () => reject(new Error("synthetic-abort")), { once: true });
        });
      }
      const chunks = reply.chunks || [new TextEncoder().encode(reply.text || "")];
      let index = 0;
      return { status: reply.status ?? 200, redirected: reply.redirected ?? false, type: reply.type ?? "basic",
        headers: { get(name) { assert.equal(name, "content-type"); return reply.contentType ?? "application/json"; } },
        body: { getReader() { return {
          async read() {
            if (options.signal.aborted) throw new Error("synthetic-abort");
            if (reply.pendingRead) {
              await new Promise((resolve, reject) => {
                options.signal.addEventListener("abort", () => reject(new Error("synthetic-read-abort")), { once: true });
              });
            }
            if (reply.readFailure) throw new Error("synthetic-private-reader-diagnostic");
            return index < chunks.length ? { done: false, value: chunks[index++] } : { done: true };
          },
          releaseLock() { releases.push(calls.length); },
        }; } },
      };
    } };
  vm.runInNewContext(script, sandbox, { timeout: 1000 });
  return { status, panel, restart, pageEvents, documentEvents, timers, calls, navigation, history, releases,
    // Drain every queued microtask and immediate so the chain reaches a fixture wait or its end.
    async settle() { for (let turn = 0; turn < 10; turn++) await new Promise(resolve => setImmediate(resolve)); },
    show() { document.visibilityState = "visible"; documentEvents.get("visibilitychange")?.(); },
    activate() { document.prerendering = false; documentEvents.get("prerenderingchange")?.(); },
    hide() { pageEvents.get("pagehide")?.(); } };
}

function assertSettled(instance) {
  assert.equal(instance.timers.size, 0);
  assert.equal(instance.pageEvents.size, 0);
  assert.equal(instance.documentEvents.size, 0);
  for (const call of instance.calls) {
    assert.equal(call.options.signal.aborted, true, "joined fetch cleanup");
  }
}

function assertFailed(instance) {
  assertSettled(instance);
  assert.equal(instance.status.textContent, failure);
  assert.equal(instance.restart.hidden, false);
  assert.equal(instance.panel.busy, "false");
  assert.deepEqual(instance.navigation, []);
}

test("a shown page completes exactly one fixed prepare/continue chain without interaction", async () => {
  const instance = harness();
  assert.deepEqual(instance.history, [[null, "", path]]);
  await instance.settle();
  instance.show();
  await instance.settle();
  assert.equal(instance.calls.length, 2);
  assert.deepEqual(instance.calls.map(call => call.destination), [path + "/prepare", path]);
  for (const call of instance.calls) {
    const options = call.options;
    assert.equal(options.method, "POST");
    assert.equal(options.mode, "same-origin");
    assert.equal(options.credentials, "same-origin");
    assert.equal(options.redirect, "error");
    assert.equal(options.cache, "no-store");
    assert.equal(options.referrerPolicy, "no-referrer");
    assert.equal(options.body, "{}");
    assert.equal(options.headers["Content-Type"], "application/json");
    assert.equal(options.headers["X-MeshTransit-Login"], "v1");
  }
  assert.equal(instance.calls[0].options.headers["X-MeshTransit-CSRF"], undefined);
  assert.equal(instance.calls[1].options.headers["X-MeshTransit-CSRF"], "syntheticProof_1");
  assert.deepEqual(instance.navigation, ["/console"]);
  assert.equal(instance.status.textContent.includes("syntheticProof"), false);
  assert.equal(instance.restart.hidden, true);
  assert.equal(instance.releases.length, 2);
  assertSettled(instance);
});

test("a background tab waits until it is shown, then starts once", async () => {
  const instance = harness(undefined, "/console", { visibilityState: "hidden" });
  await instance.settle();
  assert.equal(instance.calls.length, 0);
  instance.show();
  instance.show();
  await instance.settle();
  assert.equal(instance.calls.length, 2);
  assert.deepEqual(instance.navigation, ["/console"]);
  assertSettled(instance);
});

test("a prerendered page never posts until activation", async () => {
  const instance = harness(undefined, "/console", { prerendering: true });
  await instance.settle();
  assert.equal(instance.calls.length, 0);
  instance.activate();
  await instance.settle();
  assert.equal(instance.calls.length, 2);
  assert.deepEqual(instance.navigation, ["/console"]);
  assertSettled(instance);
});

test("pagehide before the page is shown ends without any POST", async () => {
  const instance = harness([], "/console", { visibilityState: "hidden" });
  instance.hide();
  instance.show();
  await instance.settle();
  assert.equal(instance.calls.length, 0);
  assert.equal(instance.status.textContent, failure);
  assert.equal(instance.restart.hidden, false);
});

for (const [name, reply] of [
  ["non-200", { status: 403, text: "synthetic-private-provider-diagnostic" }],
  ["redirect", { redirected: true, text: prepared }],
  ["opaque", { type: "opaque", text: prepared }],
  ["wrong content type", { contentType: "text/html", text: prepared }],
  ["fetch failure", { reject: true }],
  ["reader failure", { text: prepared, readFailure: true }],
  ["invalid json", { text: "not-json" }],
  ["array", { text: "[]" }],
  ["null", { text: "null" }],
  ["unknown field", { text: '{"csrf_token":"syntheticProof_1","expires_in":60,"token":"private"}' }],
  ["duplicate proof", { text: '{"csrf_token":"a","csrf_token":"b","expires_in":60}' }],
  ["aliased name", { text: '{"csrf_\\u0074oken":"a","expires_in":60}' }],
  ["proof encoding", { text: '{"csrf_token":"a=","expires_in":60}' }],
  ["expired proof", { text: '{"csrf_token":"a","expires_in":0}' }],
  ["too long proof window", { text: '{"csrf_token":"a","expires_in":121}' }],
  ["fractional proof window", { text: '{"csrf_token":"a","expires_in":1.5}' }],
  ["response budget", { chunks: [new Uint8Array(1025)] }],
  ["empty stream chunk", { chunks: [new Uint8Array(0)] }],
  ["invalid utf8", { chunks: [new Uint8Array([255])] }],
]) {
  test(`prepare ${name} stops once, generic message, no continue/retry`, async () => {
    const instance = harness([reply]);
    await instance.settle();
    instance.show();
    await instance.settle();
    assert.equal(instance.calls.length, 1);
    assertFailed(instance);
  });
}

for (const [name, reply] of [
  ["unavailable", { status: 503, text: "synthetic-private-diagnostic" }],
  ["unknown transport", { reject: true }],
  ["wrong local mapping", { text: '{"return_path":"/other"}' }],
  ["outside origin", { text: '{"return_path":"https://evil.example.test/"}' }],
  ["scheme-relative", { text: '{"return_path":"//evil.example.test"}' }],
  ["query", { text: '{"return_path":"/console?code=a"}' }],
  ["auth loop", { text: '{"return_path":"/auth/v1/login/continue"}' }],
  ["duplicate return", { text: '{"return_path":"/other","return_path":"/console"}' }],
  ["bearer field", { text: '{"return_path":"/console","token":"private"}' }],
  ["partial json", { text: '{"return_path":"/console"' }],
  ["response budget", { chunks: [new Uint8Array(1025)] }],
]) {
  test(`completion ${name} never retries or claims non-commit`, async () => {
    const instance = harness([{ text: prepared }, reply]);
    await instance.settle();
    instance.show();
    await instance.settle();
    assert.equal(instance.calls.length, 2);
    assertFailed(instance);
  });
}

test("fragmented bounded canonical responses preserve exact bytes", async () => {
  const fragment = text => Array.from(new TextEncoder().encode(text), byte => new Uint8Array([byte]));
  const instance = harness([{ chunks: fragment(prepared) }, { chunks: fragment(completed) }]);
  await instance.settle();
  assert.deepEqual(instance.navigation, ["/console"]);
  assertSettled(instance);
});

for (const phase of ["prepare", "continue"]) {
  for (const reason of ["timeout", "pagehide"]) {
    test(`${reason} aborts and joins pending ${phase}, no repeat`, async () => {
      const replies = phase === "prepare" ? [{ pending: true }] : [{ text: prepared }, { pending: true }];
      const instance = harness(replies);
      await instance.settle();
      assert.equal(instance.calls.length, replies.length);
      if (reason === "timeout") instance.timers.get(1)();
      else instance.hide();
      await instance.settle();
      instance.show();
      await instance.settle();
      assert.equal(instance.calls.length, replies.length);
      assertFailed(instance);
    });
  }
}

for (const phase of ["prepare", "continue"]) {
  test(`whole timeout aborts a pending ${phase} response body, no replay`, async () => {
    const replies = phase === "prepare" ? [{ pendingRead: true }] : [{ text: prepared }, { pendingRead: true }];
    const instance = harness(replies);
    await instance.settle();
    assert.equal(instance.calls.length, replies.length);
    instance.timers.get(1)();
    await instance.settle();
    assert.equal(instance.releases.length, replies.length);
    assertFailed(instance);
  });
}

for (const expectedPath of ["/", "/console/nodes", "/" + "x".repeat(255)]) {
  test(`exact canonical mapping ${expectedPath} remains Core-owned`, async () => {
    const instance = harness([{ text: prepared }, { text: JSON.stringify({ return_path: expectedPath }) }], expectedPath);
    await instance.settle();
    assert.deepEqual(instance.navigation, [expectedPath]);
    assertSettled(instance);
  });
}

for (const expectedPath of ["//evil.example.test", "/auth", "/x/../console", "/console?code=a", "/console/", "", "/" + "x".repeat(256)]) {
  test(`unsafe mapping ${expectedPath || "empty"} fails before any POST`, async () => {
    const instance = harness([], expectedPath);
    await instance.settle();
    assert.equal(instance.calls.length, 0);
    assert.equal(instance.status.textContent, failure);
    assert.equal(instance.restart.hidden, false);
  });
}
