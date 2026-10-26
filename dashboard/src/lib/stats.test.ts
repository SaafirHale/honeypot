import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { bucket, parseStats, pct, StatsError, utcShort } from "./stats.ts";

const sample = JSON.parse(readFileSync(new URL("../../public/stats.json", import.meta.url), "utf8"));

test("parses the committed sample without dropping anything", () => {
  const s = parseStats(sample);
  assert.equal(s.totals.sessions, sample.totals.sessions);
  assert.equal(s.hourly.length, 168);
  assert.equal(s.countries.length, sample.countries.length);
  assert.equal(s.recent_commands.length, sample.recent_commands.length);
  assert.equal(s.payloads.length, sample.payloads.length);
});

test("rejects wrong schema and missing window", () => {
  assert.throws(() => parseStats(null), StatsError);
  assert.throws(() => parseStats({ schema: 2, window: { end: "2026-10-25T00:00:00Z" } }), StatsError);
  assert.throws(() => parseStats({ schema: 1, window: {} }), StatsError);
});

test("drops malformed items and hostile values", () => {
  const s = parseStats({
    schema: 1,
    window: { end: "2026-10-25T00:00:00Z" },
    totals: { sessions: -5, commands: "12", login_attempts: 3.7 },
    countries: [{ code: "US", name: "United States", sessions: 3 }, { code: "<script>", sessions: 1 }],
    payloads: [{ sha256: "a".repeat(64), via: ["upload", "evil"] }, { sha256: "javascript:alert(1)" }],
    recent_commands: [{ t: "2026-10-25T00:00:00Z", cmd: "echo \u202eevil\u0007", country: "xx" }],
    usernames: [{ value: "root", count: 2 }, "nope", { value: "", count: 1 }],
  });
  assert.equal(s.totals.sessions, 0);
  assert.equal(s.totals.commands, 0);
  assert.equal(s.totals.login_attempts, 3);
  assert.deepEqual(s.countries.map((c) => c.code), ["US"]);
  assert.equal(s.payloads.length, 1);
  assert.deepEqual(s.payloads[0].via, ["upload"]);
  assert.equal(s.recent_commands[0].cmd, "echo evil");
  assert.equal(s.recent_commands[0].country, "ZZ");
  assert.deepEqual(s.usernames, [{ value: "root", count: 2 }]);
  assert.equal(s.dataset, "live");
});

test("caps very long strings", () => {
  const s = parseStats({
    schema: 1,
    window: { end: "2026-10-25T00:00:00Z" },
    commands: [{ value: "A".repeat(5000), count: 1 }],
  });
  assert.equal(s.commands[0].value.length, 200);
});

test("formatters", () => {
  assert.equal(pct(1, 3), "33%");
  assert.equal(pct(1, 200), "0.5%");
  assert.equal(pct(1, 0), "0%");
  assert.equal(utcShort("2026-10-25T13:05:00Z"), "25 Oct 13:05");
  assert.equal(bucket(0, 100), 0);
  assert.equal(bucket(100, 100), 5);
  assert.equal(bucket(1, 100), 1);
  assert.ok(bucket(10, 100) > 1 && bucket(10, 100) < 5);
});
