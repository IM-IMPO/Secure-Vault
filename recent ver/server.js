/**
 * SecureVault local data server.
 *
 * This is a tiny local-only Node/Express server. It does exactly one thing:
 * read and write a single JSON file that holds all of your SecureVault data,
 * saved directly on your computer. It never talks to the internet — it only
 * listens on localhost, so only apps running on this same PC can reach it.
 *
 * Data file location: D:\Local Data\securevault-data.json
 * (created automatically the first time you save something)
 *
 * Run it with:  node server.js
 * It listens on: http://localhost:4787
 */

const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

// ---- Where your data is stored -------------------------------------------
// Change this if you want a different folder or drive letter.
const DATA_DIR = process.env.SV_DATA_DIR || "D:\\Local Data";
const DATA_FILE = path.join(DATA_DIR, "securevault-data.json");

// Make sure the folder exists.
try {
  fs.mkdirSync(DATA_DIR, { recursive: true });
} catch (err) {
  console.error(`Could not create data folder at "${DATA_DIR}":`, err.message);
  console.error("Edit DATA_DIR at the top of server.js to point at a folder/drive that exists on this PC.");
}

const app = express();
app.use(cors());
app.use(express.json({ limit: "25mb" }));

// Health check — the frontend uses this to know the server is reachable.
app.get("/api/ping", (req, res) => {
  res.json({ ok: true, dataFile: DATA_FILE });
});

// Load all SecureVault data.
app.get("/api/data", (req, res) => {
  try {
    if (!fs.existsSync(DATA_FILE)) {
      return res.json({ data: null }); // nothing saved yet — frontend will seed demo data
    }
    const raw = fs.readFileSync(DATA_FILE, "utf8");
    const data = JSON.parse(raw);
    res.json({ data });
  } catch (err) {
    console.error("Failed to read data file:", err.message);
    res.status(500).json({ error: "Failed to read local data file." });
  }
});

// Save all SecureVault data (the frontend sends the full state each time,
// debounced, so this file is always a complete, current snapshot).
app.post("/api/data", (req, res) => {
  try {
    const json = JSON.stringify(req.body, null, 2);
    // Write to a temp file then rename, so a save that gets interrupted
    // (e.g. power loss) can't corrupt your existing data file.
    const tmpFile = DATA_FILE + ".tmp";
    fs.writeFileSync(tmpFile, json, "utf8");
    fs.renameSync(tmpFile, DATA_FILE);
    res.json({ ok: true });
  } catch (err) {
    console.error("Failed to write data file:", err.message);
    res.status(500).json({ error: "Failed to save local data file." });
  }
});

const PORT = process.env.SV_PORT || 4787;
app.listen(PORT, "127.0.0.1", () => {
  console.log(`SecureVault local server running at http://localhost:${PORT}`);
  console.log(`Saving data to: ${DATA_FILE}`);
});
