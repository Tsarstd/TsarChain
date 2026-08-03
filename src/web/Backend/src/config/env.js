const path = require("node:path");
const dotenv = require("dotenv");

// Load .env if present
dotenv.config({ path: path.join(__dirname, "..", "..", ".env") });

const getConfig = () => {
  const port = Number(process.env.PORT) || 4000;
  const host = process.env.HOST || "::";
  const nodeHost = process.env.TSAR_NODE_HOST || "127.0.0.1";
  const nodePort = Number(process.env.TSAR_NODE_PORT) || 19000;
  const allowedOrigins = process.env.ALLOWED_ORIGINS 
    ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim()) 
    : ['http://localhost:5173', 'http://127.0.0.1:5173', 'http://localhost:3000'];

  return { 
    port, 
    host,
    nodeHost, 
    nodePort,
    allowedOrigins
  };
};

module.exports = { getConfig };