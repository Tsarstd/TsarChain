const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const projectRoot = path.join(__dirname, "..", "..", "..", "..");
const venvRoot = process.env.VIRTUAL_ENV || path.join(projectRoot, ".venv");
const venvPython =
  process.platform === "win32"
    ? path.join(venvRoot, "Scripts", "python.exe")
    : path.join(venvRoot, "bin", "python");
const pythonBin = process.env.TSAR_PYTHON || (fs.existsSync(venvPython) ? venvPython : "python");

function rpcCall(op, param, host, port) {
  const script = path.join(__dirname, "py_rpc_client.py");
  const args = [script, op];
  if (param !== null && param !== undefined) args.push(String(param));
  if (host) args.push(String(host));
  if (port) args.push(String(port));

  const res = spawnSync(pythonBin, args, {
    encoding: "utf8",
    cwd: projectRoot,
  });

  if (res.error) {
    throw res.error;
  }
  const stdout = res.stdout?.trim() || "";
  if (!stdout) {
    throw new Error("empty_response");
  }
  let json;
  try {
    json = JSON.parse(stdout);
  } catch (err) {
    throw new Error(`invalid_json: ${stdout}`);
  }
  if (json.error) {
    throw new Error(json.error);
  }
  return json;
}

module.exports = { rpcCall };
