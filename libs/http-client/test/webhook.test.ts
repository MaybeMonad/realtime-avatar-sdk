import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { test } from "node:test";
import { verifyTranscript } from "../src/webhook.ts";
import type { InputProvenance, TranscriptPayload } from "../src/index.ts";

const SECRET = "a-secret-at-least-16-chars";

function sign(body: string, ts: number): Record<string, string> {
  const mac = createHmac("sha256", SECRET).update(`${ts}.${body}`).digest("hex");
  return { "x-rta-signature": `v1=${mac}`, "x-rta-timestamp": String(ts) };
}

const PAYLOAD = JSON.stringify({
  type: "session.transcript", session_id: "s", avatar_id: "a", mode: "voice",
  started_at: 1, ended_at: 2, seconds: 1, truncated: false,
  segments: [{ role: "user", text: "hi", ts: 1 }], client_metadata: { user_id: "u1" },
});

test("a correctly signed payload verifies", async () => {
  const ts = Math.floor(Date.now() / 1000);
  const out = await verifyTranscript(PAYLOAD, sign(PAYLOAD, ts), SECRET);
  assert.equal(out.client_metadata.user_id, "u1");
  assert.deepEqual(out.segments, [{ role: "user", text: "hi", ts: 1 }], "legacy provenance must stay absent");
});

test("signed webhook verification preserves optional user provenance and retry identity", async () => {
  const provenance: InputProvenance = {
    version: 1, observed_source: "text", observed_by: "sdk",
    declared_source: "client_stt", declaration_scope: "adapter", ingress: "room_text",
  };
  const segments: TranscriptPayload["segments"] = [{
    role: "user", text: "Spoken input", ts: 1, message_id: "message-2",
    turn_id: "attempt-2", retry_of_turn_id: "attempt-1", input_source: "client_stt", input_provenance: provenance,
  }, {
    role: "user", text: "Room speech", ts: 2, input_source: "server_stt",
    input_provenance: { version: 1, observed_source: "server_stt", observed_by: "worker", ingress: "room_audio_stt" },
  }, {
    role: "user", text: "Legacy origin", ts: 3, input_source: "unknown",
    input_provenance: { version: 1, observed_source: "unknown", observed_by: "unknown", ingress: "unknown" },
  }, { role: "assistant", text: "Answer", ts: 4, interrupted: true }];
  const body = JSON.stringify({ ...JSON.parse(PAYLOAD), segments });
  const ts = Math.floor(Date.now() / 1000);
  const verified = await verifyTranscript(Buffer.from(body), new Headers(sign(body, ts)), SECRET);
  assert.deepEqual(verified.segments, segments);
  await assert.rejects(
    verifyTranscript(body.replace('\"input_source\":\"client_stt\"', '\"input_source\":\"text\"'), sign(body, ts), SECRET),
    /signature mismatch/,
  );
});

test("a tampered body is rejected", async () => {
  const ts = Math.floor(Date.now() / 1000);
  const headers = sign(PAYLOAD, ts);
  await assert.rejects(() => verifyTranscript(PAYLOAD.replace("hi", "hj"), headers, SECRET), /signature mismatch/);
});

test("an old timestamp is rejected even with a valid signature", async () => {
  const ts = Math.floor(Date.now() / 1000) - 4000;
  await assert.rejects(() => verifyTranscript(PAYLOAD, sign(PAYLOAD, ts), SECRET), /replay window/);
});

test("re-serializing the body breaks the signature — verify the RAW bytes", async () => {
  const ts = Math.floor(Date.now() / 1000);
  const headers = sign(PAYLOAD, ts);
  const reserialized = JSON.stringify(JSON.parse(PAYLOAD), null, 2);
  await assert.rejects(() => verifyTranscript(reserialized, headers, SECRET), /signature mismatch/);
});
