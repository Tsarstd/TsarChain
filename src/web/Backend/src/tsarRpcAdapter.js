const { spawnSync } = require("child_process");
const path = require("path");

function rpcCall(op, param, host, port) {
  const script = path.join(__dirname, "py_rpc_client.py");
  const args = [script, op];
  if (param !== null && param !== undefined) args.push(String(param));
  if (host) args.push(String(host));
  if (port) args.push(String(port));

  const res = spawnSync("python", args, {
    encoding: "utf8",
    cwd: path.join(__dirname, "..", "..", "..", ".."),
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
