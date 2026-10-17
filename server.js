/**
 * SecureVault local data server.
 *
 * Local-only Node/Express server for SecureVault.
 *
 * Features:
 * - Encrypted vault data storage
 * - Atomic saves
 * - Automatic version history
 * - Vault integrity checking
 * - Tamper detection
 * - Rollback detection
 * - Version restore
 * - Undo restore support
 * - Trust Changes
 * - Manual encrypted backups
 * - Safe deletion
 * - Reminder synchronization for Electron notifications
 * - Development + Electron packaged-app support
 *
 * Development default:
 *   D:\Local Data\securevault-data.json
 *
 * Packaged Electron:
 *   Electron provides SV_DATA_DIR automatically.
 *
 * Server:
 *   http://localhost:4787
 */

const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// ============================================================================
// DATA LOCATION
// ============================================================================

const DATA_DIR =
  process.env.SV_DATA_DIR || "D:\\Local Data";

const DATA_FILE =
  path.join(DATA_DIR, "securevault-data.json");

const INTEGRITY_FILE =
  path.join(DATA_DIR, "securevault-integrity.json");

const VERSIONS_DIR =
  path.join(DATA_DIR, "SecureVault Versions");

const REMINDERS_FILE =
  path.join(DATA_DIR, "securevault-reminders.json");

const NOTIFY_STATE_FILE =
  path.join(DATA_DIR, "securevault-notify-state.json");

const VERSION_CAP = 30;

// ============================================================================
// CREATE DATA DIRECTORIES
// ============================================================================

try {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.mkdirSync(VERSIONS_DIR, { recursive: true });

  console.log("SecureVault data directory ready:");
  console.log(DATA_DIR);
} catch (err) {
  console.error(
    `Could not create data folders under "${DATA_DIR}":`,
    err.message
  );

  console.error(
    "Check that the selected folder/drive exists and that SecureVault has permission to access it."
  );
}

// ============================================================================
// EXPRESS
// ============================================================================

const app = express();

app.use(cors());

app.use(
  express.json({
    limit: "25mb"
  })
);

// ============================================================================
// INTEGRITY HELPERS
// ============================================================================

function sha256(buffer) {
  return (
    "sha256:" +
    crypto
      .createHash("sha256")
      .update(buffer)
      .digest("hex")
  );
}

function readIntegrityRecord() {
  try {
    if (!fs.existsSync(INTEGRITY_FILE)) {
      return null;
    }

    return JSON.parse(
      fs.readFileSync(INTEGRITY_FILE, "utf8")
    );
  } catch (err) {
    console.error(
      "Could not read integrity record:",
      err.message
    );

    return null;
  }
}

function writeIntegrityRecord(record) {
  const tmpFile = INTEGRITY_FILE + ".tmp";

  fs.writeFileSync(
    tmpFile,
    JSON.stringify(record, null, 2),
    "utf8"
  );

  fs.renameSync(tmpFile, INTEGRITY_FILE);
}

// ============================================================================
// VERSION HISTORY
// ============================================================================

function listVersionFiles() {
  try {
    return fs
      .readdirSync(VERSIONS_DIR)
      .filter(
        (file) =>
          file.startsWith("securevault-data.v") &&
          file.endsWith(".json")
      )
      .map((file) => {
        const match = file.match(/\.v(\d+)-/);
        const version = match ? Number(match[1]) : 0;

        const fullPath = path.join(VERSIONS_DIR, file);
        const stat = fs.statSync(fullPath);

        return {
          file,
          version,
          savedAt: stat.mtime.toISOString(),
          size: stat.size
        };
      })
      .sort((a, b) => b.version - a.version);
  } catch (err) {
    console.error(
      "Could not list version files:",
      err.message
    );

    return [];
  }
}

function snapshotCurrentFile(version) {
  if (!fs.existsSync(DATA_FILE)) {
    return null;
  }

  const stamp = new Date()
    .toISOString()
    .replace(/[:.]/g, "-");

  const filename =
    `securevault-data.v${version}-${stamp}.json`;

  const destination = path.join(
    VERSIONS_DIR,
    filename
  );

  fs.copyFileSync(DATA_FILE, destination);

  const versions = listVersionFiles();

  if (versions.length > VERSION_CAP) {
    versions
      .slice(VERSION_CAP)
      .forEach((versionInfo) => {
        try {
          fs.unlinkSync(
            path.join(VERSIONS_DIR, versionInfo.file)
          );
        } catch {
          // Ignore cleanup failures.
        }
      });
  }

  return filename;
}

// ============================================================================
// INTEGRITY STATUS
// ============================================================================

function computeIntegrityStatus() {
  const record = readIntegrityRecord();
  const fileExists = fs.existsSync(DATA_FILE);

  if (!record) {
    if (!fileExists) {
      return {
        status: "ok",
        version: 0
      };
    }

    let bytes;

    try {
      bytes = fs.readFileSync(DATA_FILE);
    } catch {
      return {
        status: "corrupted"
      };
    }

    const hash = sha256(bytes);

    writeIntegrityRecord({
      version: 1,
      hash,
      updatedAt: new Date().toISOString(),
      history: []
    });

    return {
      status: "ok",
      version: 1
    };
  }

  if (!fileExists) {
    return {
      status: "missing",
      expectedVersion: record.version
    };
  }

  let bytes;

  try {
    bytes = fs.readFileSync(DATA_FILE);

    JSON.parse(bytes.toString("utf8"));
  } catch {
    const versions = listVersionFiles();

    return {
      status: "corrupted",
      previousVersion: versions[0] || null
    };
  }

  const currentHash = sha256(bytes);

  if (currentHash === record.hash) {
    return {
      status: "ok",
      version: record.version
    };
  }

  const rolledBackTo = (record.history || []).find(
    (historyItem) => historyItem.hash === currentHash
  );

  const versions = listVersionFiles();
  const stat = fs.statSync(DATA_FILE);

  if (rolledBackTo) {
    return {
      status: "rolled_back",
      modifiedAt: stat.mtime.toISOString(),
      rolledBackToVersion: rolledBackTo.version,
      rolledBackToDate: rolledBackTo.savedAt,
      previousVersion: versions[0] || null
    };
  }

  return {
    status: "modified",
    modifiedAt: stat.mtime.toISOString(),
    expectedVersion: record.version,
    previousVersion: versions[0] || null
  };
}

// ============================================================================
// FILENAME VALIDATION
// ============================================================================

function isSafeVersionFilename(file) {
  return /^securevault-data\.v\d+-[\w.-]+\.json$/.test(
    file
  );
}

// ============================================================================
// REMINDERS
// Plaintext reminder index for Electron notifications while the vault is locked.
// Only notification-related fields are stored outside the encrypted vault.
// ============================================================================

function readReminders() {
  try {
    if (!fs.existsSync(REMINDERS_FILE)) {
      return [];
    }

    const value = JSON.parse(
      fs.readFileSync(REMINDERS_FILE, "utf8")
    );

    return Array.isArray(value) ? value : [];
  } catch (err) {
    console.error(
      "Could not read reminders:",
      err.message
    );

    return [];
  }
}

function writeReminders(list) {
  const tmp = REMINDERS_FILE + ".tmp";

  fs.writeFileSync(
    tmp,
    JSON.stringify(list, null, 2),
    "utf8"
  );

  fs.renameSync(tmp, REMINDERS_FILE);
}

function readNotifyState() {
  try {
    if (!fs.existsSync(NOTIFY_STATE_FILE)) {
      return {};
    }

    return JSON.parse(
      fs.readFileSync(NOTIFY_STATE_FILE, "utf8")
    );
  } catch {
    return {};
  }
}

function writeNotifyState(state) {
  const tmp = NOTIFY_STATE_FILE + ".tmp";

  fs.writeFileSync(
    tmp,
    JSON.stringify(state, null, 2),
    "utf8"
  );

  fs.renameSync(tmp, NOTIFY_STATE_FILE);
}

function pad2(n) {
  return String(n).padStart(2, "0");
}

function ymdLocal(d) {
  return (
    `${d.getFullYear()}-` +
    `${pad2(d.getMonth() + 1)}-` +
    `${pad2(d.getDate())}`
  );
}

function clampDayOfMonthNode(year, month, day) {
  return Math.min(
    day,
    new Date(year, month + 1, 0).getDate()
  );
}

function occursOnDate(reminder, dateStr) {
  const anchor = reminder.date;

  if (
    !reminder.recurrence ||
    reminder.recurrence === "none"
  ) {
    return anchor === dateStr;
  }

  const anchorDate = new Date(anchor + "T00:00:00");
  const target = new Date(dateStr + "T00:00:00");

  if (
    Number.isNaN(anchorDate.getTime()) ||
    Number.isNaN(target.getTime()) ||
    target < anchorDate
  ) {
    return false;
  }

  if (reminder.recurrence === "weekly") {
    return (
      Math.round(
        (target - anchorDate) / 86400000
      ) % 7 === 0
    );
  }

  if (reminder.recurrence === "monthly") {
    return (
      target.getDate() ===
      clampDayOfMonthNode(
        target.getFullYear(),
        target.getMonth(),
        anchorDate.getDate()
      )
    );
  }

  if (reminder.recurrence === "yearly") {
    return (
      target.getMonth() === anchorDate.getMonth() &&
      target.getDate() ===
        clampDayOfMonthNode(
          target.getFullYear(),
          anchorDate.getMonth(),
          anchorDate.getDate()
        )
    );
  }

  return false;
}

const HOURLY_REMINDER_START_HOUR = 8;
const HOURLY_REMINDER_END_HOUR = 21;

function computeDueReminders() {
  const reminders = readReminders();
  const state = readNotifyState();
  const now = new Date();
  const todayStr = ymdLocal(now);

  const due = [];
  let stateChanged = false;

  for (const r of reminders) {
    if (!r || !r.id || !occursOnDate(r, todayStr)) {
      continue;
    }

    const completedDates = Array.isArray(r.completedDates)
      ? r.completedDates
      : [];

    if (completedDates.includes(todayStr)) {
      continue;
    }

    const key = `${r.id}|${todayStr}`;
    const entry = state[key] || {};

    if (r.time && !r.allDay) {
      if (entry.timedAlertFired) {
        continue;
      }

      const parts = String(r.time).split(":").map(Number);

      if (
        parts.length < 2 ||
        !Number.isFinite(parts[0]) ||
        !Number.isFinite(parts[1]) ||
        parts[0] < 0 ||
        parts[0] > 23 ||
        parts[1] < 0 ||
        parts[1] > 59
      ) {
        continue;
      }

      const eventTime = new Date(
        now.getFullYear(),
        now.getMonth(),
        now.getDate(),
        parts[0],
        parts[1],
        0
      );

      const reminderTime = new Date(
        eventTime.getTime() - 60 * 60 * 1000
      );

      if (now >= reminderTime && now < eventTime) {
        due.push({
          id: r.id,
          title: r.title,
          category: r.category,
          message: `In 1 hour — ${r.time}`,
          date: todayStr,
          time: r.time
        });

        state[key] = {
          ...entry,
          timedAlertFired: true
        };

        stateChanged = true;
      }
    } else {
      const hour = now.getHours();

      if (
        hour < HOURLY_REMINDER_START_HOUR ||
        hour > HOURLY_REMINDER_END_HOUR
      ) {
        continue;
      }

      if (entry.lastHourNotified === hour) {
        continue;
      }

      due.push({
        id: r.id,
        title: r.title,
        category: r.category,
        message: "Today — no time set",
        date: todayStr,
        time: null
      });

      state[key] = {
        ...entry,
        lastHourNotified: hour
      };

      stateChanged = true;
    }
  }

  if (stateChanged) {
    writeNotifyState(state);
  }

  return due;
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

app.get("/api/ping", (req, res) => {
  res.json({
    ok: true,
    dataFile: DATA_FILE
  });
});

// ============================================================================
// INTEGRITY CHECK
// ============================================================================

app.get("/api/integrity", (req, res) => {
  try {
    const status = computeIntegrityStatus();

    res.json(status);
  } catch (err) {
    console.error(
      "Integrity check failed:",
      err.message
    );

    res.status(500).json({
      status: "error",
      error: "Integrity check failed."
    });
  }
});

// ============================================================================
// VERSION LIST
// ============================================================================

app.get("/api/versions", (req, res) => {
  try {
    res.json({
      versions: listVersionFiles()
    });
  } catch (err) {
    console.error(
      "Failed to list versions:",
      err.message
    );

    res.status(500).json({
      error: "Failed to list versions."
    });
  }
});

// ============================================================================
// VERSION CONTENT
// ============================================================================

app.get("/api/version-content", (req, res) => {
  try {
    const file = String(req.query.file || "");

    if (!isSafeVersionFilename(file)) {
      return res.status(400).json({
        error: "Invalid version filename."
      });
    }

    const fullPath = path.join(VERSIONS_DIR, file);

    if (!fs.existsSync(fullPath)) {
      return res.status(404).json({
        error: "Version not found."
      });
    }

    const data = JSON.parse(
      fs.readFileSync(fullPath, "utf8")
    );

    res.json({
      data
    });
  } catch (err) {
    console.error(
      "Failed to read version:",
      err.message
    );

    res.status(500).json({
      error: "Failed to read that version."
    });
  }
});

// ============================================================================
// LOAD CURRENT DATA
// ============================================================================

app.get("/api/data", (req, res) => {
  try {
    const integrity = computeIntegrityStatus();

    if (!fs.existsSync(DATA_FILE)) {
      return res.json({
        data: null,
        integrity
      });
    }

    const raw = fs.readFileSync(DATA_FILE, "utf8");
    const data = JSON.parse(raw);

    res.json({
      data,
      integrity
    });
  } catch (err) {
    console.error(
      "Failed to read data file:",
      err.message
    );

    res.status(500).json({
      error: "Failed to read local data file."
    });
  }
});

// ============================================================================
// SAVE DATA
// ============================================================================

app.post("/api/data", (req, res) => {
  let tmpFile = null;

  try {
    const record = readIntegrityRecord() || {
      version: 0,
      hash: null,
      history: []
    };

    const snapshotFile = snapshotCurrentFile(
      record.version || 0
    );

    const json = JSON.stringify(
      req.body,
      null,
      2
    );

    tmpFile = DATA_FILE + ".tmp";

    fs.writeFileSync(
      tmpFile,
      json,
      "utf8"
    );

    fs.renameSync(tmpFile, DATA_FILE);
    tmpFile = null;

    const newHash = sha256(
      Buffer.from(json, "utf8")
    );

    const newVersion = (record.version || 0) + 1;

    const history = [...(record.history || [])];

    if (record.hash) {
      history.unshift({
        version: record.version,
        hash: record.hash,
        file: snapshotFile,
        savedAt: new Date().toISOString()
      });
    }

    writeIntegrityRecord({
      version: newVersion,
      hash: newHash,
      updatedAt: new Date().toISOString(),
      history: history.slice(0, VERSION_CAP)
    });

    console.log(
      `SecureVault data saved. Version ${newVersion}`
    );

    res.json({
      ok: true,
      version: newVersion
    });
  } catch (err) {
    console.error(
      "Failed to write data file:",
      err.message
    );

    try {
      if (tmpFile && fs.existsSync(tmpFile)) {
        fs.unlinkSync(tmpFile);
      }
    } catch (cleanupError) {
      console.error(
        "Failed to clean up temporary data file:",
        cleanupError.message
      );
    }

    res.status(500).json({
      error: "Failed to save local data file."
    });
  }
});

// ============================================================================
// DELETE VAULT
// ============================================================================

app.delete("/api/data", (req, res) => {
  try {
    // Delete reminder index and notification state.
    if (fs.existsSync(REMINDERS_FILE)) {
      fs.unlinkSync(REMINDERS_FILE);
    }

    if (fs.existsSync(NOTIFY_STATE_FILE)) {
      fs.unlinkSync(NOTIFY_STATE_FILE);
    }

    // Delete current vault.
    if (fs.existsSync(DATA_FILE)) {
      fs.unlinkSync(DATA_FILE);
    }

    // Delete integrity record.
    if (fs.existsSync(INTEGRITY_FILE)) {
      fs.unlinkSync(INTEGRITY_FILE);
    }

    // Delete temporary file.
    const tmpFile = DATA_FILE + ".tmp";

    if (fs.existsSync(tmpFile)) {
      fs.unlinkSync(tmpFile);
    }

    // Delete version history.
    listVersionFiles().forEach((versionInfo) => {
      try {
        fs.unlinkSync(
          path.join(VERSIONS_DIR, versionInfo.file)
        );
      } catch {
        // Ignore individual cleanup failures.
      }
    });

    console.log("SecureVault data deleted.");

    res.json({
      ok: true
    });
  } catch (err) {
    console.error(
      "Failed to delete data file:",
      err.message
    );

    res.status(500).json({
      error: "Failed to delete local data file."
    });
  }
});

// ============================================================================
// SYNC REMINDERS
// ============================================================================

// The plaintext index only contains fields required for notifications.
// Reminder notes and locations are not saved in this file.

app.post("/api/reminders", (req, res) => {
  try {
    const incoming = Array.isArray(req.body?.reminders)
      ? req.body.reminders
      : [];

    const allowed = incoming
      .map((r) => ({
        id: String(r?.id ?? ""),
        title: String(r?.title ?? ""),
        date: String(r?.date ?? ""),
        time:
          r?.time == null
            ? null
            : String(r.time),
        allDay: Boolean(r?.allDay),
        category:
          r?.category == null
            ? ""
            : String(r.category),
        recurrence: [
          "none",
          "weekly",
          "monthly",
          "yearly"
        ].includes(r?.recurrence)
          ? r.recurrence
          : "none",
        completedDates: Array.isArray(r?.completedDates)
          ? r.completedDates.filter(
              (d) => typeof d === "string"
            )
          : []
      }))
      .filter(
        (r) =>
          r.id &&
          /^\d{4}-\d{2}-\d{2}$/.test(r.date)
      );

    writeReminders(allowed);

    res.json({
      ok: true,
      count: allowed.length
    });
  } catch (err) {
    console.error(
      "Failed to save reminders:",
      err.message
    );

    res.status(500).json({
      error: "Failed to save reminders."
    });
  }
});

// ============================================================================
// GET DUE REMINDERS
// ============================================================================

app.get("/api/due-reminders", (req, res) => {
  try {
    res.json({
      due: computeDueReminders()
    });
  } catch (err) {
    console.error(
      "Failed to compute due reminders:",
      err.message
    );

    res.status(500).json({
      due: []
    });
  }
});

// ============================================================================
// MANUAL BACKUP
// ============================================================================

app.post("/api/backup", (req, res) => {
  try {
    if (!fs.existsSync(DATA_FILE)) {
      return res.status(400).json({
        error: "No vault file exists yet to back up."
      });
    }

    const stamp = new Date()
      .toISOString()
      .replace(/[:.]/g, "-");

    const backupFile = path.join(
      DATA_DIR,
      `securevault-data.backup-${stamp}.json`
    );

    // The server copies the encrypted vault without decrypting it.
    fs.copyFileSync(DATA_FILE, backupFile);

    console.log("SecureVault backup created:");
    console.log(backupFile);

    res.json({
      ok: true,
      backupFile
    });
  } catch (err) {
    console.error(
      "Failed to create backup:",
      err.message
    );

    res.status(500).json({
      error: "Failed to create backup."
    });
  }
});

// ============================================================================
// RESTORE VERSION
// ============================================================================

app.post("/api/restore-version", (req, res) => {
  let tmpFile = null;

  try {
    const file = String(req.body.file || "");

    if (!isSafeVersionFilename(file)) {
      return res.status(400).json({
        error: "Invalid version filename."
      });
    }

    const source = path.join(VERSIONS_DIR, file);

    if (!fs.existsSync(source)) {
      return res.status(404).json({
        error: "That version no longer exists."
      });
    }

    const record = readIntegrityRecord() || {
      version: 0,
      hash: null,
      history: []
    };

    // Save the current vault before restoring, allowing Undo Restore.
    const undoFile = snapshotCurrentFile(
      record.version || 0
    );

    const restoredBytes = fs.readFileSync(source);

    // Make sure restored data is valid JSON.
    JSON.parse(restoredBytes.toString("utf8"));

    tmpFile = DATA_FILE + ".tmp";

    fs.writeFileSync(tmpFile, restoredBytes);
    fs.renameSync(tmpFile, DATA_FILE);

    tmpFile = null;

    const newHash = sha256(restoredBytes);
    const newVersion = (record.version || 0) + 1;

    const history = [...(record.history || [])];

    if (record.hash) {
      history.unshift({
        version: record.version,
        hash: record.hash,
        file: undoFile,
        savedAt: new Date().toISOString()
      });
    }

    writeIntegrityRecord({
      version: newVersion,
      hash: newHash,
      updatedAt: new Date().toISOString(),
      history: history.slice(0, VERSION_CAP)
    });

    const data = JSON.parse(
      restoredBytes.toString("utf8")
    );

    console.log(
      `SecureVault version restored: ${file}`
    );

    console.log(
      `Undo restore file: ${undoFile || "none"}`
    );

    res.json({
      ok: true,
      data,
      version: newVersion,
      undoFile
    });
  } catch (err) {
    console.error(
      "Failed to restore version:",
      err.message
    );

    try {
      if (tmpFile && fs.existsSync(tmpFile)) {
        fs.unlinkSync(tmpFile);
      }
    } catch (cleanupError) {
      console.error(
        "Failed to clean up temporary data file:",
        cleanupError.message
      );
    }

    res.status(500).json({
      error: "Failed to restore that version."
    });
  }
});

// ============================================================================
// TRUST CHANGES
// ============================================================================

app.post("/api/trust-changes", (req, res) => {
  try {
    if (!fs.existsSync(DATA_FILE)) {
      return res.status(400).json({
        error: "No vault file exists to trust."
      });
    }

    const bytes = fs.readFileSync(DATA_FILE);

    const data = JSON.parse(
      bytes.toString("utf8")
    );

    const record = readIntegrityRecord() || {
      version: 0,
      hash: null,
      history: []
    };

    const newHash = sha256(bytes);
    const newVersion = (record.version || 0) + 1;

    const history = [...(record.history || [])];

    if (record.hash) {
      history.unshift({
        version: record.version,
        hash: record.hash,
        file: null,
        savedAt: new Date().toISOString()
      });
    }

    writeIntegrityRecord({
      version: newVersion,
      hash: newHash,
      updatedAt: new Date().toISOString(),
      history: history.slice(0, VERSION_CAP)
    });

    console.log(
      `Current vault accepted as trusted version ${newVersion}.`
    );

    res.json({
      ok: true,
      data,
      version: newVersion
    });
  } catch (err) {
    console.error(
      "Failed to trust current file:",
      err.message
    );

    res.status(500).json({
      error:
        "That file isn't valid JSON, so it can't be trusted as-is."
    });
  }
});

// ============================================================================
// START SERVER
// ============================================================================

const PORT = process.env.SV_PORT || 4787;

app.listen(PORT, "127.0.0.1", () => {
  console.log(
    `SecureVault local server running at http://localhost:${PORT}`
  );

  console.log(
    `Saving data to: ${DATA_FILE}`
  );

  console.log(
    `Version history: ${VERSIONS_DIR}`
  );
});