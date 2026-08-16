"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");

const { resolveTarget, artifactName } = require("./resolve-target");

async function download(url) {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`download failed: ${url} (${res.status})`);
  return Buffer.from(await res.arrayBuffer());
}

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

async function main() {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, "package.json"), "utf8"));
  const version = pkg.version;
  const target = resolveTarget(process.platform, process.arch);
  const artifact = artifactName(target);
  const base = `https://github.com/wistprotocol/graven/releases/download/v${version}/`;

  const archive = await download(base + artifact);
  const checksumText = (await download(base + `${artifact}.sha256`)).toString("utf8");
  const expected = checksumText.trim().split(/\s+/)[0];
  const actual = sha256Hex(archive);
  if (actual !== expected) {
    throw new Error(`checksum mismatch for ${artifact}: expected ${expected}, got ${actual}`);
  }

  const binDir = path.join(__dirname, "bin");
  fs.rmSync(binDir, { recursive: true, force: true });
  fs.mkdirSync(binDir, { recursive: true });

  const archivePath = path.join(binDir, artifact);
  fs.writeFileSync(archivePath, archive);

  const tarArgs = artifact.endsWith(".zip") ? ["-xf", archivePath] : ["-xJf", archivePath];
  execFileSync("tar", tarArgs, { cwd: binDir });
  fs.unlinkSync(archivePath);

  const extractedDir = path.join(binDir, artifact.replace(/\.(tar\.xz|zip)$/, ""));
  const binName = target.includes("windows") ? "graven.exe" : "graven";
  fs.renameSync(path.join(extractedDir, binName), path.join(binDir, binName));
  fs.rmSync(extractedDir, { recursive: true, force: true });

  if (process.platform !== "win32") {
    fs.chmodSync(path.join(binDir, binName), 0o755);
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
