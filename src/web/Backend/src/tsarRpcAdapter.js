const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const readline = require("readline");

const projectRoot = path.join(__dirname, "..", "..", "..", "..");
const venvRoot = process.env.VIRTUAL_ENV || path.join(projectRoot, ".venv");
const venvPython =
  process.platform === "win32"
    ? path.join(venvRoot, "Scripts", "python.exe")
    : path.join(venvRoot, "bin", "python");
const pythonBin = process.env.TSAR_PYTHON || (fs.existsSync(venvPython) ? venvPython : "python");
const scriptPath = path.join(__dirname, "python/py_rpc_client.py");
const WORKER_REQUEST_TIMEOUT_MS = 60 * 1000;

let worker = null;
let workerSeq = 0;
const pending = new Map();

const rejectAllPending = (err) => {
  for (const entry of pending.values()) {
    clearTimeout(entry.timeout);
    entry.reject(err);
  }
  pending.clear();
};

const handleWorkerLine = (line) => {
  const raw = String(line || "").trim();
  if (!raw) return;
  let msg;
  try {
    msg = JSON.parse(raw);
  } catch (_err) {
    return;
  }
  if (!msg || typeof msg !== "object" || msg.id === undefined) return;
  const entry = pending.get(msg.id);
  if (!entry) return;
  pending.delete(msg.id);
  clearTimeout(entry.timeout);
  const payload = Object.prototype.hasOwnProperty.call(msg, "payload") ? msg.payload : msg;
  entry.resolve(payload);
};

const startWorker = () => {
  const child = spawn(pythonBin, [scriptPath, "worker"], {
    cwd: projectRoot,
    stdio: ["pipe", "pipe", "pipe"],
  });
  child.stdin.setDefaultEncoding("utf8");

  const rl = readline.createInterface({ input: child.stdout });
  rl.on("line", handleWorkerLine);

  child.stderr.on("data", (chunk) => {
    const text = String(chunk || "").trim();
    if (text) {
      console.error("[py_rpc_worker]", text);
    }
  });

  child.on("error", (err) => {
    rejectAllPending(err);
    worker = null;
  });

  child.on("exit", (code, signal) => {
    rejectAllPending(new Error(`python_worker_exit:${code ?? "null"}:${signal ?? ""}`));
    worker = null;
  });

  worker = child;
  return child;
};

const ensureWorker = () => {
  if (worker && !worker.killed) return worker;
  return startWorker();
};

async function rpcCall(op, param, host, port) {
  const child = ensureWorker();
  const id = (workerSeq += 1);
  const request = {
    id,
    op,
    param: param ?? null,
    host: host ?? null,
    port: port ?? null,
  };

  const payload = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      pending.delete(id);
      reject(new Error("rpc_timeout"));
      try {
        child.kill();
      } catch (_err) {
      }
    }, WORKER_REQUEST_TIMEOUT_MS);

    pending.set(id, { resolve, reject, timeout });
    try {
      child.stdin.write(`${JSON.stringify(request)}\n`);
    } catch (err) {
      clearTimeout(timeout);
      pending.delete(id);
      reject(err);
    }
  });

  if (!payload) {
    throw new Error("empty_response");
  }
  if (payload.error) {
    throw new Error(payload.error);
  }
  return payload;
}

module.exports = { rpcCall };
