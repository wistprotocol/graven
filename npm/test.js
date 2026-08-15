"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { resolveTarget, artifactName } = require("./resolve-target");

test("resolveTarget maps known platform-arch pairs", () => {
  assert.equal(resolveTarget("linux", "x64"), "x86_64-unknown-linux-gnu");
  assert.equal(resolveTarget("linux", "arm64"), "aarch64-unknown-linux-gnu");
  assert.equal(resolveTarget("darwin", "x64"), "x86_64-apple-darwin");
  assert.equal(resolveTarget("darwin", "arm64"), "aarch64-apple-darwin");
  assert.equal(resolveTarget("win32", "x64"), "x86_64-pc-windows-msvc");
  assert.equal(resolveTarget("win32", "arm64"), "aarch64-pc-windows-msvc");
});

test("resolveTarget throws on unknown platform-arch and names supported list", () => {
  assert.throws(
    () => resolveTarget("freebsd", "x64"),
    (err) => {
      assert.match(err.message, /unsupported platform freebsd-x64/);
      assert.match(err.message, /linux-x64/);
      assert.match(err.message, /win32-arm64/);
      return true;
    },
  );
});

test("artifactName uses .zip only for windows targets", () => {
  assert.equal(artifactName("x86_64-pc-windows-msvc"), "graven-x86_64-pc-windows-msvc.zip");
  assert.equal(artifactName("aarch64-pc-windows-msvc"), "graven-aarch64-pc-windows-msvc.zip");
  assert.equal(artifactName("x86_64-unknown-linux-gnu"), "graven-x86_64-unknown-linux-gnu.tar.xz");
  assert.equal(artifactName("aarch64-unknown-linux-gnu"), "graven-aarch64-unknown-linux-gnu.tar.xz");
  assert.equal(artifactName("x86_64-apple-darwin"), "graven-x86_64-apple-darwin.tar.xz");
  assert.equal(artifactName("aarch64-apple-darwin"), "graven-aarch64-apple-darwin.tar.xz");
});
