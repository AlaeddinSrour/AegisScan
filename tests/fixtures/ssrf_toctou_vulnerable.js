const fs = require("node:fs");
const https = require("node:https");

function fetchPreview(req) {
  const target = req.query.url;
  return https.get(target);
}

function readExisting(path) {
  if (fs.existsSync(path)) {
    return fs.readFileSync(path, "utf8");
  }
  return "";
}

async function readAccessible(path) {
  await fs.promises.access(path);
  return await fs.promises.readFile(path, "utf8");
}

module.exports = { fetchPreview, readExisting, readAccessible };
