#!/usr/bin/env node

const { spawnSync } = require("node:child_process");

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
    shell: false
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

function ensureLazySRE(pythonCmd) {
  const importCheck = run(pythonCmd, ["-c", "import lazysre"], { stdio: "pipe" });
  if (importCheck.status === 0) {
    return;
  }

  const preferred = process.env.LAZYSRE_PIP_SOURCE
    ? [process.env.LAZYSRE_PIP_SOURCE]
    : ["lazysre", "https://github.com/not1ie/lazysre/archive/refs/heads/main.zip"];

  let installed = false;
  let lastErr = "";
  for (const source of preferred) {
    const install = run(
      pythonCmd,
      ["-m", "pip", "install", "--user", "--upgrade", source],
      { stdio: "inherit" }
    );
    if (install.status === 0) {
      installed = true;
      break;
    }
    lastErr = `pip install failed for source=${source}`;
  }
  if (!installed) {
    throw new Error(lastErr || "unable to install lazysre via pip");
  }
}

function main() {
  const pythonCmd = findPython();
  if (!pythonCmd) {
    console.error("LazySRE requires Python 3.11+. Please install Python first.");
    process.exit(1);
  }

  try {
    ensureLazySRE(pythonCmd);
  } catch (err) {
    console.error(String(err && err.message ? err.message : err));
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
