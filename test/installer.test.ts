import { createPackage, extractFile, getRawHeader } from "@electron/asar";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  adHocEntitlements,
  electronAsarIntegrityDigest,
  electronAsarIntegrityDigestSlotOffsets,
  getStatus,
  install,
  uninstall,
  type AsarIntegrity,
} from "../src/installer";

test("prepares entitlements that macOS permits on an ad-hoc signature", () => {
  const original = {
    "application-identifier": "BQR82RBBHL.com.tinyspeck.slackmacgap",
    "com.apple.application-identifier": "BQR82RBBHL.com.tinyspeck.slackmacgap",
    "com.apple.developer.associated-domains": ["applinks:slack.com"],
    "com.apple.developer.team-identifier": "BQR82RBBHL",
    "com.apple.security.cs.allow-jit": true,
    "com.apple.security.cs.disable-library-validation": false,
    "com.apple.security.device.audio-input": true,
    "keychain-access-groups": ["BQR82RBBHL.com.tinyspeck.slackmacgap.webauthn"],
  };

  assert.deepEqual(adHocEntitlements(original), {
    "com.apple.security.cs.allow-jit": true,
    "com.apple.security.cs.disable-library-validation": true,
    "com.apple.security.device.audio-input": true,
  });
  assert.equal(original["com.apple.developer.team-identifier"], "BQR82RBBHL");
});

test("computes Electron's order-independent ASAR integrity digest", () => {
  const integrity: AsarIntegrity = {
    "Resources/_app.asar": { algorithm: "SHA256", hash: "b".repeat(64) },
    "Resources/app.asar": { algorithm: "SHA256", hash: "a".repeat(64) },
  };
  assert.equal(
    electronAsarIntegrityDigest(integrity).toString("hex"),
    "5e6026d624b2056d4572e16ce261d5a3cde92b6ab9f45084b9ab3f018fe557c5",
  );
  assert.deepEqual(
    electronAsarIntegrityDigest({
      "Resources/app.asar": integrity["Resources/app.asar"],
      "Resources/_app.asar": integrity["Resources/_app.asar"],
    }),
    electronAsarIntegrityDigest(integrity),
  );
});

test("finds every embedded Electron ASAR integrity digest slot", () => {
  const sentinel = "AGbevlPCksUGKNL8TSn7wGmJEuJsXb2A";
  const binary = Buffer.from(`prefix${sentinel}${"x".repeat(34)}middle${sentinel}${"y".repeat(34)}`);
  assert.deepEqual(electronAsarIntegrityDigestSlotOffsets(binary), [
    "prefix".length + sentinel.length,
    "prefix".length + sentinel.length + 34 + "middle".length + sentinel.length,
  ]);
});

function integrityHash(asarPath: string): string {
  return createHash("sha256").update(getRawHeader(asarPath).headerString).digest("hex");
}

function integrityEntries(appPath: string): Record<string, { algorithm: string; hash: string }> {
  const output = execFileSync(
    "/usr/bin/plutil",
    ["-extract", "ElectronAsarIntegrity", "json", "-o", "-", path.join(appPath, "Contents", "Info.plist")],
    { encoding: "utf8" },
  );
  return JSON.parse(output) as Record<string, { algorithm: string; hash: string }>;
}

function embeddedIntegrityDigests(appPath: string): Buffer[] {
  const framework = fs.readFileSync(
    path.join(
      appPath,
      "Contents",
      "Frameworks",
      "Electron Framework.framework",
      "Electron Framework",
    ),
  );
  return electronAsarIntegrityDigestSlotOffsets(framework).map((offset) =>
    framework.subarray(offset, offset + 34),
  );
}

async function fixture(): Promise<{ appPath: string; klackRoot: string; root: string }> {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "klack-test-"));
  const appPath = path.join(root, "Slack.app");
  const resources = path.join(appPath, "Contents", "Resources");
  const framework = path.join(
    appPath,
    "Contents",
    "Frameworks",
    "Electron Framework.framework",
    "Electron Framework",
  );
  const source = path.join(root, "slack-source");
  const klackRoot = path.join(root, "klack");

  fs.mkdirSync(path.join(source, "dist"), { recursive: true });
  fs.mkdirSync(path.join(resources, "app.asar.unpacked"), { recursive: true });
  fs.mkdirSync(path.dirname(framework), { recursive: true });
  fs.mkdirSync(path.join(klackRoot, "dist"), { recursive: true });

  fs.writeFileSync(
    path.join(source, "package.json"),
    JSON.stringify({
      main: "dist/boot.bundle.cjs",
      name: "slack-desktop",
      productName: "Slack",
      version: "4.53.276",
    }),
  );
  fs.writeFileSync(path.join(source, "dist", "boot.bundle.cjs"), "globalThis.slackBooted = true;\n");
  fs.writeFileSync(path.join(source, "dist", "preload.bundle.js"), "globalThis.slackPreloaded = true;\n");
  fs.writeFileSync(path.join(resources, "app.asar.unpacked", "native.node"), "fixture");
  const sentinel = "AGbevlPCksUGKNL8TSn7wGmJEuJsXb2A";
  fs.writeFileSync(framework, `prefix${sentinel}${"x".repeat(34)}middle${sentinel}${"y".repeat(34)}`);
  fs.writeFileSync(path.join(klackRoot, "dist", "main.cjs"), "// Klack main fixture\n");
  fs.writeFileSync(path.join(klackRoot, "dist", "preload.js"), "globalThis.klackPreloaded = true;\n");

  await createPackage(source, path.join(resources, "app.asar"));
  const originalIntegrity = integrityHash(path.join(resources, "app.asar"));
  fs.writeFileSync(
    path.join(appPath, "Contents", "Info.plist"),
    `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>ElectronAsarIntegrity</key><dict><key>Resources/app.asar</key><dict><key>algorithm</key><string>SHA256</string><key>hash</key><string>${originalIntegrity}</string></dict></dict></dict></plist>`,
  );
  return { appPath, klackRoot, root };
}

test("install, reinstall, and uninstall preserve Slack's original ASAR", async (t) => {
  const { appPath, klackRoot, root } = await fixture();
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));

  assert.equal(getStatus(appPath).state, "not-installed");

  const installed = await install({ appPath, klackRoot, resign: false });
  assert.equal(installed.state, "installed");
  assert.equal(installed.slackVersion, "4.53.276");

  const resources = path.join(appPath, "Contents", "Resources");
  assert.ok(fs.existsSync(path.join(resources, "_app.asar")));
  assert.ok(fs.existsSync(path.join(resources, "_app.asar.unpacked", "native.node")));
  assert.equal(fs.existsSync(path.join(resources, "app.asar.unpacked")), false);

  const bootstrap = JSON.parse(
    extractFile(path.join(resources, "app.asar"), "package.json").toString("utf8"),
  ) as { name: string; productName: string; version: string };
  assert.equal(bootstrap.name, "klack-bootstrap");
  assert.equal(bootstrap.productName, "Slack");
  assert.equal(bootstrap.version, "4.53.276");

  let integrity = integrityEntries(appPath);
  assert.equal(integrity["Resources/app.asar"].hash, integrityHash(path.join(resources, "app.asar")));
  assert.equal(integrity["Resources/_app.asar"].hash, integrityHash(path.join(resources, "_app.asar")));
  const installedDigest = Buffer.concat([
    Buffer.from([1, 1]),
    electronAsarIntegrityDigest(integrity as AsarIntegrity),
  ]);
  assert.deepEqual(embeddedIntegrityDigests(appPath), [installedDigest, installedDigest]);

  const combinedPreload = fs.readFileSync(path.join(klackRoot, "runtime", "preload.bundle.js"), "utf8");
  assert.ok(combinedPreload.indexOf("klackPreloaded") < combinedPreload.indexOf("slackPreloaded"));

  const backupBeforeReinstall = fs.readFileSync(path.join(resources, "_app.asar"));
  assert.equal((await install({ appPath, klackRoot, resign: false })).state, "installed");
  assert.deepEqual(fs.readFileSync(path.join(resources, "_app.asar")), backupBeforeReinstall);

  const restored = uninstall(appPath, { resign: false });
  assert.equal(restored.state, "not-installed");
  assert.ok(fs.existsSync(path.join(resources, "app.asar.unpacked", "native.node")));
  assert.equal(fs.existsSync(path.join(resources, "_app.asar")), false);

  const original = JSON.parse(
    extractFile(path.join(resources, "app.asar"), "package.json").toString("utf8"),
  ) as { name: string };
  assert.equal(original.name, "slack-desktop");

  integrity = integrityEntries(appPath);
  assert.equal(integrity["Resources/app.asar"].hash, integrityHash(path.join(resources, "app.asar")));
  assert.equal(integrity["Resources/_app.asar"], undefined);
  const restoredDigest = Buffer.concat([
    Buffer.from([1, 1]),
    electronAsarIntegrityDigest(integrity as AsarIntegrity),
  ]);
  assert.deepEqual(embeddedIntegrityDigests(appPath), [restoredDigest, restoredDigest]);
});
