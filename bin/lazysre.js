#!/usr/bin/env node

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

function pythonCandidates() {
  const envPy = process.env.PYTHON_BIN ? [process.env.PYTHON_BIN] : [];
  if (process.platform === "win32") {
    return [
      ...envPy,
      "py -3",
      "python",
      "python3"
    ];
  }
  return [
    ...envPy,
    "python3",
    "python"
  ];
}

function splitCommand(command) {
  const parts = command.trim().split(/\s+/).filter(Boolean);
  return {
    cmd: parts[0],
    baseArgs: parts.slice(1)
  };
}

function run(command, args, options = {}) {
  const { cmd, baseArgs } = splitCommand(command);
  return spawnSync(cmd, [...baseArgs, ...args], {
    stdio: options.stdio || "pipe",
    encoding: "utf-8",
    shell: false,
    windowsHide: true
  });
}

function findPython() {
  for (const candidate of pythonCandidates()) {
    const result = run(candidate, ["--version"]);
    if (result.status === 0) {
      return candidate;
    }
  }
  return "";
}

function ensurePip(pythonCmd) {
  const check = run(pythonCmd, ["-m", "pip", "--version"], { stdio: "pipe" });
  if (check.status === 0) {
    return true;
  }
  const bootstrap = run(pythonCmd, ["-m", "ensurepip", "--upgrade"], { stdio: "inherit" });
  return bootstrap.status === 0;
}

function pipInstallArgs(source) {
  const args = ["-m", "pip", "install", "--user", "--upgrade"];
  const indexUrl = (process.env.LAZYSRE_PIP_INDEX_URL || "").trim();
  const extraIndex = (process.env.LAZYSRE_PIP_EXTRA_INDEX_URL || "").trim();
  const trustedHosts = (process.env.LAZYSRE_PIP_TRUSTED_HOST || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (indexUrl) {
    args.push("--index-url", indexUrl);
  }
  if (extraIndex) {
    args.push("--extra-index-url", extraIndex);
  }
  for (const host of trustedHosts) {
    args.push("--trusted-host", host);
  }
  args.push(source);
  return args;
}

function ensureLazySRE(pythonCmd) {
  const importCheck = run(pythonCmd, ["-c", "import lazysre"], { stdio: "pipe" });
  if (importCheck.status === 0) {
    return { installedNow: false, source: "" };
  }

  if (process.env.LAZYSRE_NO_AUTO_INSTALL === "1") {
    throw new Error("lazysre python module is missing and LAZYSRE_NO_AUTO_INSTALL=1.");
  }

  if (!ensurePip(pythonCmd)) {
    throw new Error("pip is unavailable for current python runtime.");
  }

  const preferred = process.env.LAZYSRE_PIP_SOURCE
    ? [process.env.LAZYSRE_PIP_SOURCE]
    : ["lazysre", "https://github.com/not1ie/lazysre/archive/refs/heads/main.zip"];

  let installed = false;
  let usedSource = "";
  let lastErr = "";
  for (const source of preferred) {
    const install = run(
      pythonCmd,
      pipInstallArgs(source),
      { stdio: "inherit" }
    );
    if (install.status === 0) {
      installed = true;
      usedSource = source;
      break;
    }
    lastErr = `pip install failed for source=${source} (exit=${install.status})`;
  }
  if (!installed) {
    throw new Error(lastErr || "unable to install lazysre via pip");
  }
  return { installedNow: true, source: usedSource };
}

function markerFilePath() {
  return path.join(os.homedir(), ".lazysre", ".npm-launcher-installed");
}

function emitFirstRunHint(source) {
  const marker = markerFilePath();
  if (fs.existsSync(marker)) {
    return;
  }
  fs.mkdirSync(path.dirname(marker), { recursive: true });
  fs.writeFileSync(marker, `installed_from=${source || "unknown"}\n`, "utf-8");
  const lines = [
    "[LazySRE] Python core installed successfully.",
    `         source: ${source || "unknown"}`,
    "         Tip: use `lazysre chat` to enter interactive mode.",
    "         Tip: use `lazysre install-doctor` to verify local runtime."
  ];
  console.error(lines.join("\n"));
}

function printInstallFailureGuide(err, pythonCmd) {
  const msg = String(err && err.message ? err.message : err);
  const lines = [
    "[LazySRE] Failed to prepare Python core runtime.",
    `  reason: ${msg}`,
    `  python: ${pythonCmd}`,
    "",
    "Try one of these:",
    `  1) ${pythonCmd} -m pip install --user --upgrade lazysre`,
    `  2) ${pythonCmd} -m pip install --user --upgrade https://github.com/not1ie/lazysre/archive/refs/heads/main.zip`,
    "  3) if behind proxy/mirror, set env LAZYSRE_PIP_INDEX_URL and retry.",
    "",
    "Then run: lazysre --help"
  ];
  console.error(lines.join("\n"));
}

function main() {
  const pythonCmd = findPython();
  if (!pythonCmd) {
    console.error("LazySRE requires Python 3.11+. Please install Python first.");
    process.exit(1);
  }

  try {
    const state = ensureLazySRE(pythonCmd);
    if (state.installedNow) {
      emitFirstRunHint(state.source);
    }
  } catch (err) {
    printInstallFailureGuide(err, pythonCmd);
    process.exit(1);
  }

  const args = process.argv.slice(2);
  const result = run(
    pythonCmd,
    ["-m", "lazysre", ...args],
    { stdio: "inherit" }
  );
  process.exit(result.status == null ? 1 : result.status);
}

main();
