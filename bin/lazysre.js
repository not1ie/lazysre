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
    windowsHide: true,
    env: options.env || process.env,
    cwd: options.cwd
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

function pipNetworkArgs() {
  const args = [];
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
  return args;
}

function pipInstallArgs(source, mode) {
  const args = ["-m", "pip", "install"];
  if (mode === "user") {
    args.push("--user");
  } else if (mode === "user-break-system") {
    args.push("--break-system-packages", "--user");
  }
  args.push("--upgrade", ...pipNetworkArgs(), source);
  return args;
}

function isPep668Error(text) {
  return /externally-managed-environment|externally managed|PEP 668/i.test(text || "");
}

function normalizeOutput(result) {
  return `${result.stdout || ""}\n${result.stderr || ""}`;
}

function launcherVenvDir() {
  const envDir = (process.env.LAZYSRE_LAUNCHER_VENV || "").trim();
  if (envDir) {
    return envDir;
  }
  return path.join(os.homedir(), ".lazysre", "launcher-venv");
}

function launcherVenvPythonPath() {
  const dir = launcherVenvDir();
  if (process.platform === "win32") {
    return path.join(dir, "Scripts", "python.exe");
  }
  return path.join(dir, "bin", "python");
}

function launcherVenvPythonCmd() {
  return launcherVenvPythonPath();
}

function localSourceRoot() {
  const cwd = process.cwd();
  const byCwd = path.join(cwd, "src", "lazysre", "__main__.py");
  if (fs.existsSync(byCwd)) {
    return cwd;
  }
  const launcherRoot = path.resolve(__dirname, "..");
  const byLauncher = path.join(launcherRoot, "src", "lazysre", "__main__.py");
  if (fs.existsSync(byLauncher)) {
    return launcherRoot;
  }
  return "";
}

function envWithPythonPath(projectRoot) {
  const srcPath = path.join(projectRoot, "src");
  const env = { ...process.env };
  const key = process.platform === "win32" ? "Path" : "PATH";
  if (!env[key]) {
    env[key] = process.env[key] || "";
  }
  const existing = env.PYTHONPATH ? env.PYTHONPATH.split(path.delimiter) : [];
  if (!existing.includes(srcPath)) {
    env.PYTHONPATH = [srcPath, ...existing].filter(Boolean).join(path.delimiter);
  }
  return env;
}

function ensureLauncherVenv(basePythonCmd) {
  const pythonPath = launcherVenvPythonPath();
  if (!fs.existsSync(pythonPath)) {
    const create = run(basePythonCmd, ["-m", "venv", launcherVenvDir()], { stdio: "inherit" });
    if (create.status !== 0) {
      throw new Error(`failed to create launcher venv at ${launcherVenvDir()}`);
    }
  }
  const venvPython = launcherVenvPythonCmd();
  if (!ensurePip(venvPython)) {
    throw new Error(`pip unavailable inside launcher venv at ${launcherVenvDir()}`);
  }
  return venvPython;
}

function ensureLazySRE(pythonCmd) {
  const localRoot = localSourceRoot();
  if (localRoot) {
    const localEnv = envWithPythonPath(localRoot);
    const localImportCheck = run(pythonCmd, ["-c", "import lazysre"], { stdio: "pipe", env: localEnv });
    if (localImportCheck.status === 0) {
      return {
        installedNow: false,
        source: localRoot,
        runtimePython: pythonCmd,
        installMethod: "local-source",
        runtimeEnv: localEnv
      };
    }
  }

  const importCheck = run(pythonCmd, ["-c", "import lazysre"], { stdio: "pipe" });
  if (importCheck.status === 0) {
    return {
      installedNow: false,
      source: "",
      runtimePython: pythonCmd,
      installMethod: "system",
      runtimeEnv: process.env
    };
  }

  const existingVenvPy = launcherVenvPythonCmd();
  if (fs.existsSync(launcherVenvPythonPath())) {
    const venvImport = run(existingVenvPy, ["-c", "import lazysre"], { stdio: "pipe" });
    if (venvImport.status === 0) {
      return {
        installedNow: false,
        source: "launcher-venv",
        runtimePython: existingVenvPy,
        installMethod: "launcher-venv",
        runtimeEnv: process.env
      };
    }
  }

  if (process.env.LAZYSRE_NO_AUTO_INSTALL === "1") {
    throw new Error("lazysre python module is missing and LAZYSRE_NO_AUTO_INSTALL=1.");
  }

  if (!ensurePip(pythonCmd)) {
    throw new Error("pip is unavailable for current python runtime.");
  }

  const preferred = process.env.LAZYSRE_PIP_SOURCE
    ? [process.env.LAZYSRE_PIP_SOURCE]
    : ["https://github.com/not1ie/lazysre/archive/refs/heads/main.zip", "lazysre"];

  let installed = false;
  let usedSource = "";
  let installMethod = "";
  let runtimePython = pythonCmd;
  let lastErr = "";
  for (const source of preferred) {
    const userInstall = run(pythonCmd, pipInstallArgs(source, "user"), { stdio: "pipe" });
    if (userInstall.status === 0) {
      installed = true;
      usedSource = source;
      installMethod = "pip-user";
      break;
    }
    const output = normalizeOutput(userInstall);
    process.stderr.write(output);
    if (isPep668Error(output)) {
      const breakInstall = run(pythonCmd, pipInstallArgs(source, "user-break-system"), { stdio: "pipe" });
      if (breakInstall.status === 0) {
        installed = true;
        usedSource = source;
        installMethod = "pip-user-break-system";
        break;
      }
      process.stderr.write(normalizeOutput(breakInstall));
      lastErr = `pip install failed for source=${source} in PEP668 mode (exit=${breakInstall.status})`;
      continue;
    }
    lastErr = `pip install failed for source=${source} (exit=${userInstall.status})`;
  }

  if (!installed) {
    let venvPython = "";
    try {
      venvPython = ensureLauncherVenv(pythonCmd);
      for (const source of preferred) {
        const venvInstall = run(venvPython, pipInstallArgs(source, "venv"), { stdio: "pipe" });
        if (venvInstall.status === 0) {
          installed = true;
          usedSource = source;
          installMethod = "launcher-venv";
          runtimePython = venvPython;
          break;
        }
        process.stderr.write(normalizeOutput(venvInstall));
        lastErr = `venv pip install failed for source=${source} (exit=${venvInstall.status})`;
      }
    } catch (err) {
      lastErr = String(err && err.message ? err.message : err);
    }
  }

  if (!installed) {
    throw new Error(lastErr || "unable to install lazysre via pip/venv");
  }
  return {
    installedNow: true,
    source: usedSource,
    runtimePython,
    installMethod,
    runtimeEnv: process.env
  };
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
  const venvDir = launcherVenvDir();
  const lines = [
    "[LazySRE] Failed to prepare Python core runtime.",
    `  reason: ${msg}`,
    `  python: ${pythonCmd}`,
    "",
    "Try one of these:",
    `  1) ${pythonCmd} -m pip install --user --upgrade lazysre`,
    `  2) ${pythonCmd} -m pip install --break-system-packages --user --upgrade lazysre`,
    `  3) ${pythonCmd} -m venv "${venvDir}" && "${launcherVenvPythonPath()}" -m pip install --upgrade lazysre`,
    "  4) if behind proxy/mirror, set env LAZYSRE_PIP_INDEX_URL and retry.",
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
      emitFirstRunHint(`${state.source} (${state.installMethod})`);
    }
    const runtimePython = state.runtimePython || pythonCmd;
    const runtimeEnv = state.runtimeEnv || process.env;
    const args = process.argv.slice(2);
    const result = run(
      runtimePython,
      ["-m", "lazysre", ...args],
      { stdio: "inherit", env: runtimeEnv }
    );
    process.exit(result.status == null ? 1 : result.status);
  } catch (err) {
    printInstallFailureGuide(err, pythonCmd);
    process.exit(1);
  }
}

main();
