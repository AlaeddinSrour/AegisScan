const fs = require("node:fs");
const https = require("node:https");

function fetchHealthcheck() {
  return https.get("https://status.example.com/health");
}

function readFile(path) {
  try {
    return fs.readFileSync(path, "utf8");
  } catch (error) {
    if (error.code === "ENOENT") return "";
    throw error;
  }
}

module.exports = { fetchHealthcheck, readFile };
