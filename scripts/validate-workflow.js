#!/usr/bin/env node
// n8n-outbound-dns-dmarc-rua-xml-report-parser :: offline workflow validator
// Full text: DISCLAIMER.md · Licensed under the MIT License. License: MIT © 2026 dhRobin Systems · Provided as-is, see the disclaimer.
//
// Validates workflow.json WITHOUT an n8n instance:
//   1. Structure: unique node names, every connection points to an existing node, credentials are placeholders.
//   2. Licensing: every Code node starts with the project license header.
//   3. Secret hygiene: no live-looking tokens, keys or webhook URLs anywhere in the repo.
//   4. Fixture hygiene: every IP in the sample sits in an RFC 5737 / RFC 3849 documentation range.
//   5. Logic: executes the real Code-node source (extracted from workflow.json) against the sample XML,
//      parsed with xml2js using the same options as the workflow's XML node, and asserts the results.
//
// Usage: npm install && npm test

'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert');

const ROOT = path.resolve(__dirname, '..');
const LICENSE = 'Full text: DISCLAIMER.md · Licensed under the MIT License. License: MIT © 2026 dhRobin Systems · Provided as-is, see the disclaimer.';

let passed = 0;
async function check(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ok   ${name}`);
  } catch (e) {
    console.error(`  FAIL ${name}\n       ${e.message}`);
    process.exitCode = 1;
  }
}

const wf = JSON.parse(fs.readFileSync(path.join(ROOT, 'workflow.json'), 'utf8'));
const byName = Object.fromEntries(wf.nodes.map((n) => [n.name, n]));
const sampleXml = fs.readFileSync(path.join(ROOT, 'sample-payloads/dmarc-rua-sample.xml'), 'utf8');

// Runs an n8n Code node ("Run Once for All Items") in a VM with n8n-like globals.
async function runCode(nodeName, items, { env = {}, upstream = {}, binaries = {} } = {}) {
  const src = byName[nodeName].parameters.jsCode;
  const sandbox = {
    $input: { all: () => items },
    $env: env,
    $: (name) => ({
      itemMatching: (i) => {
        if (!upstream[name]) throw new Error(`no upstream stub for ${name}`);
        return upstream[name][i];
      },
    }),
    console,
    Buffer,
    BigInt,
  };
  const ctx = { helpers: { getBinaryDataBuffer: async (i, key) => binaries[`${i}:${key}`] } };
  vm.createContext(sandbox);
  const fn = vm.runInContext(`(async function () {\n${src}\n})`, sandbox);
  // JSON round-trip = what n8n persists between nodes; also strips cross-realm prototypes.
  return JSON.parse(JSON.stringify(await fn.call(ctx)));
}

async function parseLikeXmlNode(xml) {
  const xml2js = require('xml2js');
  const o = byName['Parse DMARC XML'].parameters.options;
  const parser = new xml2js.Parser({ explicitArray: o.explicitArray, explicitRoot: o.explicitRoot, ignoreAttrs: o.ignoreAttrs, mergeAttrs: o.mergeAttrs, normalize: o.normalize, normalizeTags: o.normalizeTags, trim: o.trim });
  return parser.parseStringPromise(xml);
}

const ENV = {
  SANDBOX_MODE: 'true',
  DOMAIN_WATCHLIST: 'example.com,example.net',
  AUTHORIZED_SENDER_IPS: '192.0.2.0/27,192.0.2.40,2001:db8:10::/48',
  SPOOF_MIN_MESSAGES: '5',
  HEALTH_WARN_THRESHOLD: '98',
  HEALTH_CRITICAL_THRESHOLD: '90',
};

(async () => {
  console.log('\nStructure');
  await check('node names are unique', () => assert.strictEqual(new Set(wf.nodes.map((n) => n.name)).size, wf.nodes.length));
  await check('every connection targets an existing node', () => {
    for (const [from, outs] of Object.entries(wf.connections)) {
      assert.ok(byName[from], `unknown source node ${from}`);
      for (const branch of outs.main) for (const t of branch) assert.ok(byName[t.node], `${from} -> unknown ${t.node}`);
    }
  });
  await check('workflow ships inactive', () => assert.strictEqual(wf.active, false));
  await check('credentials are placeholders only', () => {
    for (const n of wf.nodes) for (const cred of Object.values(n.credentials || {})) assert.match(cred.id, /^REPLACE_WITH_/, `${n.name} has a non-placeholder credential id`);
  });

  console.log('\nLicensing');
  await check('every Code node carries the license header', () => {
    for (const n of wf.nodes.filter((x) => x.type === 'n8n-nodes-base.code')) assert.ok(n.parameters.jsCode.split('\n').slice(0, 3).join('\n').includes(LICENSE), `${n.name} missing header`);
  });
  await check('workflow meta carries the license', () => assert.strictEqual(wf.meta.license, LICENSE));

  console.log('\nSecret & data hygiene');
  await check('no live-looking secrets in repository files', () => {
    const patterns = [/xox[abprs]-[0-9A-Za-z-]{10,}/, /hooks\.slack\.com\/services\/T[0-9A-Z]{6,}/, /\bsk-[A-Za-z0-9]{20,}/, /\bAKIA[0-9A-Z]{16}\b/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/, /\bgh[pousr]_[A-Za-z0-9]{30,}/, /discord(app)?\.com\/api\/webhooks\/\d+/];
    const files = ['workflow.json', 'README.md', '.env.example', 'DISCLAIMER.md', '.gitignore', 'sample-payloads/dmarc-rua-sample.xml'];
    for (const f of files) {
      const t = fs.readFileSync(path.join(ROOT, f), 'utf8');
      for (const p of patterns) assert.ok(!p.test(t), `${f} matches ${p}`);
    }
  });
  await check('sample fixture uses documentation IP ranges only', () => {
    const ips = [...sampleXml.matchAll(/<source_ip>([^<]+)<\/source_ip>/g)].map((m) => m[1]);
    assert.ok(ips.length > 0);
    for (const ip of ips) assert.ok(/^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d+$/.test(ip) || /^2001:db8:/i.test(ip), `non-documentation IP ${ip}`);
  });
  await check('sandbox loader embeds the exact sample fixture', () => assert.ok(byName['Load Synthetic Sample Report'].parameters.jsCode.includes(sampleXml), 'embedded XML drifted from sample-payloads/dmarc-rua-sample.xml; rebuild workflow.json'));

  console.log('\nIngestion logic');
  await check('attachment splitter classifies zip / gz / xml and ignores others', async () => {
    const out = await runCode('Split Report Attachments', [{
      json: { subject: 'Report Domain: example.com', from: 'dmarc@example.org' },
      binary: {
        attachment_0: { fileName: 'example.org!example.com!1794787200!1794873599.zip', mimeType: 'application/zip' },
        attachment_1: { fileName: 'report.xml.gz', mimeType: 'application/gzip' },
        attachment_2: { fileName: 'report.xml', mimeType: 'text/xml' },
        attachment_3: { fileName: 'logo.png', mimeType: 'image/png' },
      },
    }]);
    assert.deepStrictEqual(out.map((o) => o.json.kind), ['zip', 'gz', 'xml']);
    assert.ok(out.every((o) => o.binary.report));
  });
  await check('extractor accepts a valid report and rejects DOCTYPE / non-DMARC / oversize', async () => {
    const items = [0, 1, 2, 3].map((i) => ({ json: { file_name: `f${i}.xml`, kind: 'xml' }, binary: { report: { fileName: `f${i}.xml` } } }));
    const binaries = {
      '0:report': Buffer.from(sampleXml),
      '1:report': Buffer.from('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><feedback/>'),
      '2:report': Buffer.from('<html><body>not a report</body></html>'),
      '3:report': Buffer.alloc(2048, 'a'),
    };
    const out = await runCode('Extract & Validate XML', items, { env: { MAX_XML_BYTES: '1024', ...ENV }, binaries });
    // MAX_XML_BYTES=1024 also rejects the real sample, so re-run item 0 with the default limit.
    assert.deepStrictEqual(out.map((o) => o.json.reason || 'ok'), ['xml_too_large', 'doctype_or_entity_rejected', 'not_a_dmarc_aggregate_report', 'xml_too_large']);
    const ok = await runCode('Extract & Validate XML', [items[0]], { env: ENV, binaries });
    assert.strictEqual(ok[0].json.ok, true);
    assert.ok(!('kind' in ok[0].json));
  });

  console.log('\nAnalysis logic (sample report)');
  const parsed = await parseLikeXmlNode(sampleXml);
  const meta = { json: { source: 'sandbox', file_name: 'sample-payloads/dmarc-rua-sample.xml' } };
  const [event] = (await runCode('Compute Alignment & Detect Spoofing', [{ json: parsed }], { env: ENV, upstream: { 'XML Extracted?': [meta] } })).map((o) => o.json);
  const ip = (addr) => event.per_ip.find((p) => p.source_ip === addr);

  await check('report metadata and policy are parsed', () => {
    assert.strictEqual(event.event_type, 'dmarc_report');
    assert.strictEqual(event.report_key, 'Example Mailbox Provider|synthetic-rua-20261116-0001');
    assert.strictEqual(event.policy_domain, 'example.com');
    assert.strictEqual(event.policy.p, 'none');
    assert.strictEqual(event.date_range.begin, '2026-11-16T00:00:00.000Z');
    assert.strictEqual(event.in_scope, true);
    assert.strictEqual(event.file_name, 'sample-payloads/dmarc-rua-sample.xml');
  });
  await check('totals and alignment rates are correct', () => {
    assert.strictEqual(event.totals.messages, 1765);
    assert.strictEqual(event.totals.unique_ips, 8);
    assert.strictEqual(event.totals.dkim_aligned_pass, 1685);
    assert.strictEqual(event.totals.spf_aligned_pass, 1285);
    assert.strictEqual(event.rates.dmarc_pass, 95.47);
    assert.strictEqual(ip('192.0.2.25').spf_aligned_rate, 0);
    assert.strictEqual(ip('192.0.2.25').spf_auth_rate, 100);
  });
  await check('every source IP is classified as expected', () => {
    const expected = {
      '192.0.2.10': 'authorized_aligned',
      '192.0.2.25': 'authorized_aligned',
      '2001:db8:10::5': 'authorized_aligned',
      '192.0.2.40': 'authorized_misaligned',
      '203.0.113.50': 'unlisted_aligned_sender',
      '198.51.100.150': 'probable_forwarder',
      '203.0.113.200': 'unauthorized_low_volume',
      '198.51.100.77': 'unauthorized_spoofing',
    };
    for (const [addr, cls] of Object.entries(expected)) assert.strictEqual(ip(addr).classification, cls, addr);
  });
  await check('spoofing detection, health score and alert decision', () => {
    assert.deepStrictEqual(event.spoofing.sources.map((s) => s.source_ip), ['198.51.100.77']);
    assert.strictEqual(event.spoofing.message_count, 45);
    assert.strictEqual(event.health.legitimate_messages, 1705);
    assert.strictEqual(event.health.score, 98.83);
    assert.strictEqual(event.health.status, 'healthy');
    assert.strictEqual(event.alert_required, true);
    assert.ok(event.recommendations.some((r) => r.includes('p=none')));
  });
  await check('out-of-watchlist domains are logged but never alerted', async () => {
    const [e] = await runCode('Compute Alignment & Detect Spoofing', [{ json: parsed }], { env: { ...ENV, DOMAIN_WATCHLIST: 'example.org' } });
    assert.strictEqual(e.json.in_scope, false);
    assert.strictEqual(e.json.alert_required, false);
  });
  await check('empty allowlist still flags DMARC-failing traffic and recommends configuration', async () => {
    const [e] = await runCode('Compute Alignment & Detect Spoofing', [{ json: parsed }], { env: { ...ENV, AUTHORIZED_SENDER_IPS: '' } });
    assert.strictEqual(e.json.per_ip.find((p) => p.source_ip === '192.0.2.10').classification, 'aligned_sender');
    assert.ok(e.json.spoofing.sources.some((s) => s.source_ip === '198.51.100.77'));
    assert.ok(e.json.recommendations.some((r) => r.includes('AUTHORIZED_SENDER_IPS is empty')));
  });
  await check('structurally broken XML becomes a parse_failure event', async () => {
    const [e] = await runCode('Compute Alignment & Detect Spoofing', [{ json: { feedback: { version: '1.0' } } }], { env: ENV });
    assert.strictEqual(e.json.event_type, 'parse_failure');
    assert.strictEqual(e.json.reason, 'missing_required_dmarc_sections');
  });
  await check('truncated sandbox fixture really fails XML parsing', async () => {
    await assert.rejects(parseLikeXmlNode('<?xml version="1.0"?><feedback><report_metadata><org_name>Truncated Example</org_name>'));
  });

  console.log('\nDelivery logic');
  await check('alert formatter produces a Slack-safe text payload', async () => {
    const [a] = await runCode('Format Alert Message', [{ json: event }], { env: ENV });
    assert.deepStrictEqual(Object.keys(a.json), ['text']);
    assert.ok(a.json.text.includes('198.51.100.77'));
    const [g] = await runCode('Format Alert Message', [{ json: event }], { env: { ...ENV, ALERT_PAYLOAD_FORMAT: 'generic' } });
    assert.strictEqual(g.json.event.report_key, event.report_key);
  });
  await check('parse-failure builder and error formatter honour sandbox mode', async () => {
    const [pf] = await runCode('Build Parse-Failure Event', [{ json: { error: 'Unclosed root tag', file_name: 'x.xml' } }], { env: ENV });
    assert.strictEqual(pf.json.reason, 'xml_parse_error');
    assert.strictEqual(pf.json.sandbox_mode, true);
    const silent = await runCode('Format Workflow Error', [{ json: { execution: { error: { message: 'x' } } } }], { env: { ...ENV, ALERT_WEBHOOK_URL: 'https://hooks.example.com/x' } });
    assert.strictEqual(silent.length, 0);
    const live = await runCode('Format Workflow Error', [{ json: { execution: { error: { message: 'boom' }, lastNodeExecuted: 'Parse DMARC XML' } } }], { env: { ...ENV, SANDBOX_MODE: 'false', ALERT_WEBHOOK_URL: 'https://hooks.example.com/x' } });
    assert.strictEqual(live[0].json.url, 'https://hooks.example.com/x');
  });

  console.log(`\n${passed} checks passed${process.exitCode ? ', some FAILED' : ''}.`);
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
