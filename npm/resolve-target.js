const MAP = {
  "linux-x64": "x86_64-unknown-linux-gnu",
  "linux-arm64": "aarch64-unknown-linux-gnu",
  "darwin-x64": "x86_64-apple-darwin",
  "darwin-arm64": "aarch64-apple-darwin",
  "win32-x64": "x86_64-pc-windows-msvc",
  "win32-arm64": "aarch64-pc-windows-msvc",
};

function resolveTarget(platform, arch) {
  const t = MAP[`${platform}-${arch}`];
  if (!t) throw new Error(`unsupported platform ${platform}-${arch}; supported: ${Object.keys(MAP).join(", ")}`);
  return t;
}

function artifactName(target) {
  return target.includes("windows") ? `graven-${target}.zip` : `graven-${target}.tar.xz`;
}

module.exports = { resolveTarget, artifactName };
