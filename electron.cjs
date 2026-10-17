
const {
  app,
  BrowserWindow,
  ipcMain,
  Tray,
  Menu,
  nativeImage,
  screen
} = require("electron");

const path = require("path");
const { spawn } = require("child_process");
const http = require("http");

let mainWindow = null;
let serverProcess = null;
let tray = null;
let isQuitting = false;
let reminderPollingTimer = null;

const reminderWindows = new Map();
const reminderSnoozeTimers = new Map();
const reminderAlarmProcesses = new Map();
const dismissedReminders = new Set();
const shownReminders = new Set();

/* ==========================================================================
   PATHS
   ========================================================================== */

function isPackaged() {
  return app.isPackaged;
}

function getDataDirectory() {
  return path.join(app.getPath("userData"), "SecureVault Data");
}

function getServerPath() {
  return isPackaged()
    ? path.join(process.resourcesPath, "server.js")
    : path.join(app.getAppPath(), "server.js");
}

function getPreloadPath() {
  return path.join(app.getAppPath(), "preload.cjs");
}

function getIndexPath() {
  return path.join(app.getAppPath(), "dist", "index.html");
}

/* ==========================================================================
   LOCAL SERVER
   ========================================================================== */

function startLocalServer() {
  const serverPath = getServerPath();
  const dataDirectory = getDataDirectory();

  console.log("Starting SecureVault local server");
  console.log("Packaged:", isPackaged());
  console.log("Server:", serverPath);
  console.log("Data:", dataDirectory);

  serverProcess = spawn(process.execPath, [serverPath], {
    cwd: path.dirname(serverPath),
    env: {
      ...process.env,
      ELECTRON_RUN_AS_NODE: "1",
      SV_DATA_DIR: dataDirectory,
      SV_PORT: "4787",
      NODE_PATH: path.join(app.getAppPath(), "node_modules")
    },
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"]
  });

  serverProcess.stdout.on("data", (data) => {
    console.log(`[SecureVault Server] ${data.toString().trim()}`);
  });

  serverProcess.stderr.on("data", (data) => {
    console.error(`[SecureVault Server] ${data.toString().trim()}`);
  });

  serverProcess.on("error", (error) => {
    console.error("Failed to start local server:", error);
  });

  serverProcess.on("exit", (code, signal) => {
    console.log(
      `SecureVault server stopped. Code: ${code}, Signal: ${signal}`
    );
    serverProcess = null;
  });
}

function stopLocalServer() {
  if (!serverProcess) return;

  try {
    serverProcess.kill();
  } catch (error) {
    console.error("Failed to stop SecureVault server:", error);
  }

  serverProcess = null;
}

/* ==========================================================================
   HELPERS
   ========================================================================== */

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/* ==========================================================================
   MAIN WINDOW
   ========================================================================== */

function createWindow() {
  if (mainWindow && !mainWindow.isDestroyed()) {
    showMainWindow();
    return;
  }

  const indexPath = getIndexPath();

  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1000,
    minHeight: 700,
    backgroundColor: "#0B0F14",
    show: false,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      preload: getPreloadPath()
    },
    title: "SecureVault"
  });

  mainWindow.loadFile(indexPath).catch((error) => {
    console.error("Failed to load SecureVault:", error);

    if (!mainWindow || mainWindow.isDestroyed()) return;

    mainWindow.loadURL(
      "data:text/html;charset=utf-8," +
        encodeURIComponent(`
          <!DOCTYPE html>
          <html>
          <body style="
            background:#0B0F14;color:white;font-family:Arial;padding:35px
          ">
            <h1>SecureVault failed to load</h1>
            <p>${escapeHtml(error.message)}</p>
            <p>${escapeHtml(indexPath)}</p>
          </body>
          </html>
        `)
    );
  });

  mainWindow.once("ready-to-show", () => {
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.show();
    }
  });

  mainWindow.webContents.on(
    "did-fail-load",
    (_event, errorCode, errorDescription) => {
      console.error(
        "SecureVault failed to load:",
        errorCode,
        errorDescription
      );
    }
  );

  mainWindow.webContents.on("render-process-gone", (_event, details) => {
    console.error("SecureVault renderer stopped:", details);
  });

  mainWindow.on("close", (event) => {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow.hide();
    }
  });

  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

/* ==========================================================================
   WINDOWS HELLO / BIOMETRIC AUTHENTICATION
   ========================================================================== */

function runPowerShell(script) {
  return new Promise((resolve, reject) => {
    const ps = spawn(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script
      ],
      { windowsHide: true }
    );

    let stdout = "";
    let stderr = "";

    ps.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    ps.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    ps.on("error", reject);

    ps.on("close", (code) => {
      const output = stdout.trim();

      if (code !== 0 && !output) {
        reject(
          new Error(
            stderr.trim() || `PowerShell exited with code ${code}`
          )
        );
        return;
      }

      resolve(output);
    });
  });
}

function isSafeBase64(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    /^[A-Za-z0-9+/=\s]+$/.test(value)
  );
}

const AWAIT_HELPER = [
  "function Await-WinRTTask($WinRtTask, $ResultType) {",
  "    $methods = [System.WindowsRuntimeSystemExtensions].GetMethods()",
  "    $asTaskGeneric = $methods |",
  "        Where-Object {",
  "            $_.Name -eq 'AsTask' -and",
  "            $_.IsGenericMethod -and",
  "            $_.GetParameters().Count -eq 1 -and",
  "            $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'",
  "        } |",
  "        Select-Object -First 1",
  "    if ($null -eq $asTaskGeneric) {",
  "        throw 'Unable to find the WinRT AsTask method.'",
  "    }",
  "    $method = $asTaskGeneric.MakeGenericMethod($ResultType)",
  "    $netTask = $method.Invoke($null, @($WinRtTask))",
  "    $netTask.Wait(-1) | Out-Null",
  "    return $netTask.Result",
  "}"
].join("\n");

const FOREGROUND_HELPER = [
  "Add-Type -Name Win32Foreground -Namespace SecureVault -MemberDefinition @'",
  "[DllImport(\"user32.dll\")]",
  "public static extern bool AllowSetForegroundWindow(int dwProcessId);",
  "'@",
  "[SecureVault.Win32Foreground]::AllowSetForegroundWindow(-1) | Out-Null"
].join("\n");

const CHECK_SCRIPT = [
  "$ErrorActionPreference = 'Stop'",
  "try {",
  "    Add-Type -AssemblyName System.Runtime.WindowsRuntime",
  "    [void][Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]",
  "    [void][Windows.Security.Credentials.UI.UserConsentVerifierAvailability,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]",
  AWAIT_HELPER,
  "    $task = [Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()",
  "    $availability = Await-WinRTTask $task ([Windows.Security.Credentials.UI.UserConsentVerifierAvailability])",
  "    Write-Output ('RESULT:' + $availability)",
  "} catch {",
  "    Write-Output ('ERROR:' + $_.Exception.Message)",
  "}"
].join("\n");

function escapePowerShellString(value) {
  return String(value)
    .replace(/`/g, "``")
    .replace(/"/g, '`"')
    .replace(/\$/g, "`$");
}

function verifyThenScript(promptMessage, action) {
  const safePrompt = escapePowerShellString(promptMessage);

  return [
    "$ErrorActionPreference = 'Stop'",
    "try {",
    "    Add-Type -AssemblyName System.Runtime.WindowsRuntime",
    "    [void][Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]",
    "    [void][Windows.Security.Credentials.UI.UserConsentVerifierAvailability,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]",
    "    [void][Windows.Security.Credentials.UI.UserConsentVerificationResult,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]",
    AWAIT_HELPER,
    "    $availabilityTask = [Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()",
    "    $availability = Await-WinRTTask $availabilityTask ([Windows.Security.Credentials.UI.UserConsentVerifierAvailability])",
    "    if ($availability -ne [Windows.Security.Credentials.UI.UserConsentVerifierAvailability]::Available) {",
    "        Write-Output ('UNAVAILABLE:' + $availability)",
    "        exit 0",
    "    }",
    FOREGROUND_HELPER,
    `    $verifyTask = [Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync("${safePrompt}")`,
    "    $result = Await-WinRTTask $verifyTask ([Windows.Security.Credentials.UI.UserConsentVerificationResult])",
    "    if ($result -ne [Windows.Security.Credentials.UI.UserConsentVerificationResult]::Verified) {",
    "        Write-Output ('DENIED:' + $result)",
    "        exit 0",
    "    }",
    action,
    "} catch {",
    "    Write-Output ('ERROR:' + $_.Exception.Message)",
    "}"
  ].join("\n");
}

function protectScript(plainBase64) {
  return verifyThenScript(
    "Set up Windows Hello for SecureVault",
    [
      "Add-Type -AssemblyName System.Security",
      `$bytes = [Convert]::FromBase64String("${plainBase64}")`,
      "$protected = [System.Security.Cryptography.ProtectedData]::Protect(",
      "    $bytes,",
      "    $null,",
      "    [System.Security.Cryptography.DataProtectionScope]::CurrentUser",
      ")",
      'Write-Output ("OK:" + [Convert]::ToBase64String($protected))'
    ].join("\n")
  );
}

function unlockScript(protectedBase64) {
  return verifyThenScript(
    "Unlock SecureVault",
    [
      "Add-Type -AssemblyName System.Security",
      `$bytes = [Convert]::FromBase64String("${protectedBase64}")`,
      "$plain = [System.Security.Cryptography.ProtectedData]::Unprotect(",
      "    $bytes,",
      "    $null,",
      "    [System.Security.Cryptography.DataProtectionScope]::CurrentUser",
      ")",
      'Write-Output ("OK:" + [Convert]::ToBase64String($plain))'
    ].join("\n")
  );
}

function friendlyError(output, fallback) {
  if (output.startsWith("DENIED:")) {
    return "Windows Hello verification wasn't completed.";
  }

  if (output.startsWith("UNAVAILABLE:")) {
    return (
      "Windows Hello isn't available on this PC. " +
      "Set it up in Windows Settings → Accounts → Sign-in options."
    );
  }

  if (output.startsWith("ERROR:")) {
    return output.slice(6).trim() || fallback;
  }

  return fallback;
}

ipcMain.handle("biometric:check", async () => {
  if (process.platform !== "win32") {
    return {
      supported: false,
      reason: "Biometric unlock currently only works on Windows."
    };
  }

  try {
    const output = await runPowerShell(CHECK_SCRIPT);

    if (output.startsWith("RESULT:Available")) {
      return { supported: true, reason: "" };
    }

    return {
      supported: false,
      reason: friendlyError(output, "Windows Hello is not available.")
    };
  } catch (error) {
    console.error("Windows Hello check failed:", error);
    return { supported: false, reason: error.message };
  }
});

ipcMain.handle("biometric:protect", async (_event, base64Bytes) => {
  if (process.platform !== "win32") {
    return {
      ok: false,
      error: "Biometric unlock currently only works on Windows."
    };
  }

  if (!isSafeBase64(base64Bytes)) {
    return { ok: false, error: "Invalid data." };
  }

  try {
    const output = await runPowerShell(protectScript(base64Bytes));

    if (output.startsWith("OK:")) {
      return { ok: true, protected: output.slice(3).trim() };
    }

    return {
      ok: false,
      error: friendlyError(output, "Couldn't set up Windows Hello.")
    };
  } catch (error) {
    console.error("Windows Hello protect failed:", error);
    return { ok: false, error: error.message };
  }
});

ipcMain.handle("biometric:unlock", async (_event, protectedBase64) => {
  if (process.platform !== "win32") {
    return {
      ok: false,
      error: "Biometric unlock currently only works on Windows."
    };
  }

  if (!isSafeBase64(protectedBase64)) {
    return { ok: false, error: "Invalid data." };
  }

  try {
    const output = await runPowerShell(unlockScript(protectedBase64));

    if (output.startsWith("OK:")) {
      return { ok: true, plain: output.slice(3).trim() };
    }

    return {
      ok: false,
      error: friendlyError(output, "Couldn't unlock with Windows Hello.")
    };
  } catch (error) {
    console.error("Windows Hello unlock failed:", error);
    return { ok: false, error: error.message };
  }
});

/* ==========================================================================
   SYSTEM TRAY
   ========================================================================== */

const TRAY_ICON_DATA_URL =
  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGUlEQVR42mPwqfn8nxLMMGrAqAGjBgwXAwDfCLofVt2obQAAAABJRU5ErkJggg==";

function showMainWindow() {
  if (!mainWindow || mainWindow.isDestroyed()) {
    createWindow();
    return;
  }

  if (mainWindow.isMinimized()) {
    mainWindow.restore();
  }

  mainWindow.show();
  mainWindow.focus();
}

function createTray() {
  const icon = nativeImage.createFromDataURL(TRAY_ICON_DATA_URL);

  tray = new Tray(icon);
  tray.setToolTip("SecureVault — running in the background");

  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: "Open SecureVault", click: showMainWindow },
      { type: "separator" },
      {
        label: "Quit SecureVault",
        click: () => {
          isQuitting = true;
          app.quit();
        }
      }
    ])
  );

  tray.on("click", showMainWindow);
}

/* ==========================================================================
   REMINDER ALARM SOUND
   ========================================================================== */

function playReminderSound(reminderKey) {
  if (process.platform !== "win32") return;
  if (reminderAlarmProcesses.has(reminderKey)) return;

  const script = [
    "$ErrorActionPreference = 'Stop'",
    "while ($true) {",
    "  [Console]::Beep(1000, 450)",
    "  Start-Sleep -Milliseconds 100",
    "  [Console]::Beep(1350, 450)",
    "  Start-Sleep -Milliseconds 150",
    "}"
  ].join("\n");

  const alarm = spawn(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", script],
    {
      windowsHide: true,
      stdio: "ignore"
    }
  );

  reminderAlarmProcesses.set(reminderKey, alarm);

  alarm.on("error", (error) => {
    console.warn("Reminder alarm failed:", error.message);
    reminderAlarmProcesses.delete(reminderKey);
  });

  alarm.on("exit", () => {
    if (reminderAlarmProcesses.get(reminderKey) === alarm) {
      reminderAlarmProcesses.delete(reminderKey);
    }
  });
}

function stopReminderSound(reminderKey) {
  const alarm = reminderAlarmProcesses.get(reminderKey);
  if (!alarm) return;

  reminderAlarmProcesses.delete(reminderKey);

  try {
    alarm.kill();
  } catch (error) {
    console.warn("Could not stop reminder alarm:", error.message);
  }
}

/* ==========================================================================
   REMINDER API AND ACTIONS
   ========================================================================== */

function httpGetJson(url) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, { timeout: 5000 }, (res) => {
      let data = "";

      res.on("data", (chunk) => {
        data += chunk;
      });

      res.on("end", () => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          reject(new Error(`HTTP ${res.statusCode}`));
          return;
        }

        try {
          resolve(JSON.parse(data));
        } catch (error) {
          reject(error);
        }
      });
    });

    req.on("timeout", () => {
      req.destroy(new Error("Request timed out"));
    });

    req.on("error", reject);
  });
}

function getReminderKey(reminder) {
  if (reminder.id !== undefined && reminder.id !== null) {
    return `id:${String(reminder.id)}`;
  }

  return [
    String(reminder.title || ""),
    String(reminder.date || ""),
    String(reminder.time || ""),
    String(reminder.message || "")
  ].join("|");
}

function closeReminderPopup(key) {
  const popup = reminderWindows.get(key);

  if (popup && !popup.isDestroyed()) {
    popup.close();
  }

  reminderWindows.delete(key);
}

function dismissReminder(reminder) {
  const key = getReminderKey(reminder);

  stopReminderSound(key);
  dismissedReminders.add(key);

  const timer = reminderSnoozeTimers.get(key);

  if (timer) {
    clearTimeout(timer);
    reminderSnoozeTimers.delete(key);
  }

  closeReminderPopup(key);
}

function snoozeReminder(reminder, seconds = 300) {
  const key = getReminderKey(reminder);

  stopReminderSound(key);
  closeReminderPopup(key);

  const oldTimer = reminderSnoozeTimers.get(key);

  if (oldTimer) {
    clearTimeout(oldTimer);
  }

  const timer = setTimeout(() => {
    reminderSnoozeTimers.delete(key);

    if (isQuitting || dismissedReminders.has(key)) return;

    shownReminders.delete(key);
    showReminderPopup(reminder);
  }, seconds * 1000);

  reminderSnoozeTimers.set(key, timer);
}

/* ==========================================================================
   REMINDER POPUP
   ========================================================================== */

function showReminderPopup(reminder) {
  const key = getReminderKey(reminder);

  if (isQuitting || dismissedReminders.has(key)) return;

  const existing = reminderWindows.get(key);

  if (existing && !existing.isDestroyed()) {
    existing.show();
    existing.focus();
    return;
  }

  const title = escapeHtml(reminder.title || "SecureVault Reminder");
  const message = escapeHtml(reminder.message || "You have a reminder.");

  const { workArea } = screen.getPrimaryDisplay();
  const popupWidth = 410;
  const popupHeight = 390;
  const margin = 16;

  const popup = new BrowserWindow({
    width: popupWidth,
    height: popupHeight,
    x: workArea.x + workArea.width - popupWidth - margin,
    y: workArea.y + workArea.height - popupHeight - margin,
    resizable: false,
    movable: true,
    minimizable: false,
    maximizable: false,
    fullscreenable: false,
    alwaysOnTop: true,
    skipTaskbar: true,
    show: false,
    autoHideMenuBar: true,
    backgroundColor: "#0B0F14",
    title: "SecureVault Reminder",
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });

  reminderWindows.set(key, popup);
  playReminderSound(key);

  popup.webContents.setWindowOpenHandler(({ url }) => {
    try {
      const parsed = new URL(url);

      if (parsed.protocol !== "securevault-reminder:") {
        return { action: "deny" };
      }

      const action = parsed.hostname;

      if (action === "snooze") {
        const seconds = Number(parsed.pathname.replace("/", ""));
        const allowedSeconds = [
          30, 60, 300, 600, 900, 1800, 3600, 86400
        ];

        if (allowedSeconds.includes(seconds)) {
          snoozeReminder(reminder, seconds);
        }
      } else if (action === "dismiss") {
        dismissReminder(reminder);
      } else if (action === "open") {
        stopReminderSound(key);
        closeReminderPopup(key);
        showMainWindow();
      }
    } catch (error) {
      console.error("Reminder action failed:", error);
    }

    return { action: "deny" };
  });

  popup.webContents.on("will-navigate", (event, url) => {
    if (!url.startsWith("data:text/html")) {
      event.preventDefault();
    }
  });

  popup.on("closed", () => {
    if (reminderWindows.get(key) === popup) {
      reminderWindows.delete(key);
    }
  });

  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
      <title>SecureVault Reminder</title>

      <style>
        * { box-sizing: border-box; }

        html, body {
          width: 100%;
          height: 100%;
          margin: 0;
          overflow: hidden;
        }

        body {
          background: #0B0F14;
          color: #F8FAFC;
          font-family: "Segoe UI", Arial, sans-serif;
          padding: 18px 20px 14px;
          display: flex;
          flex-direction: column;
        }

        .header {
          display: flex;
          align-items: center;
          gap: 11px;
          margin-bottom: 18px;
          flex-shrink: 0;
        }

        .icon {
          width: 42px;
          height: 42px;
          flex-shrink: 0;
          display: flex;
          align-items: center;
          justify-content: center;
          border: 1px solid #263C64;
          border-radius: 13px;
          background: #172D50;
          font-size: 21px;
        }

        .brand {
          color: #93C5FD;
          font-size: 11px;
          font-weight: 750;
          letter-spacing: 1.5px;
        }

        .content {
          min-width: 0;
          flex: 1;
          overflow: hidden;
        }

        h2 {
          margin: 0 0 9px;
          color: #FFFFFF;
          font-size: 19px;
          font-weight: 650;
          line-height: 1.4;
          overflow-wrap: anywhere;
          display: -webkit-box;
          -webkit-box-orient: vertical;
          -webkit-line-clamp: 2;
          overflow: hidden;
        }

        .message {
          margin: 0;
          color: #A8B4C7;
          font-size: 13px;
          line-height: 1.5;
          overflow-wrap: anywhere;
          display: -webkit-box;
          -webkit-box-orient: vertical;
          -webkit-line-clamp: 3;
          overflow: hidden;
        }

        .divider {
          height: 1px;
          background: #202A39;
          margin: 14px 0;
          flex-shrink: 0;
        }

        .actions {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 9px;
          flex-shrink: 0;
        }

        button {
          height: 40px;
          border: 1px solid #303C4E;
          border-radius: 9px;
          background: #1A2433;
          color: #E5EAF2;
          font-family: inherit;
          font-size: 12px;
          font-weight: 650;
          cursor: pointer;
        }

        button:hover {
          background: #29374A;
          border-color: #4B607D;
        }

        button:focus-visible {
          outline: 2px solid #60A5FA;
          outline-offset: 2px;
        }

        .open {
          grid-column: 1 / -1;
          height: 42px;
          background: #2563EB;
          border-color: #2563EB;
          color: #FFFFFF;
        }

        .open:hover {
          background: #1D4ED8;
          border-color: #1D4ED8;
        }

        .snooze-menu {
          display: none;
          grid-template-columns: 1fr 1fr;
          gap: 7px;
          margin-top: 9px;
          flex-shrink: 0;
        }

        .snooze-menu.visible {
          display: grid;
        }

        .snooze-menu button {
          height: 32px;
          font-size: 11px;
          background: #111B29;
        }

        .snooze-menu button:hover {
          background: #263A55;
        }

        .footer {
          margin-top: 10px;
          color: #64748B;
          font-size: 10px;
          text-align: center;
          flex-shrink: 0;
        }
      </style>
    </head>

    <body>
      <div class="header">
        <div class="icon">🔔</div>
        <div class="brand">SECUREVAULT REMINDER</div>
      </div>

      <div class="content">
        <h2>${title}</h2>
        <p class="message">${message}</p>
      </div>

      <div class="divider"></div>

      <div class="actions">
        <button id="snooze" type="button">Snooze ▾</button>
        <button id="dismiss" type="button">Dismiss</button>
        <button id="open" class="open" type="button">
          Open SecureVault
        </button>
      </div>

      <div id="snooze-menu" class="snooze-menu">
        <button data-seconds="30" type="button">30 seconds</button>
        <button data-seconds="60" type="button">1 minute</button>
        <button data-seconds="300" type="button">5 minutes</button>
        <button data-seconds="600" type="button">10 minutes</button>
        <button data-seconds="900" type="button">15 minutes</button>
        <button data-seconds="1800" type="button">30 minutes</button>
        <button data-seconds="3600" type="button">1 hour</button>
        <button data-seconds="86400" type="button">1 day</button>
      </div>

      <div class="footer">Your personal reminder · SecureVault</div>

      <script>
        const snoozeButton = document.getElementById("snooze");
        const snoozeMenu = document.getElementById("snooze-menu");

        snoozeButton.addEventListener("click", () => {
          snoozeMenu.classList.toggle("visible");
        });

        snoozeMenu.querySelectorAll("[data-seconds]").forEach((button) => {
          button.addEventListener("click", () => {
            const seconds = button.dataset.seconds;
            window.open("securevault-reminder://snooze/" + seconds);
          });
        });

        document.getElementById("dismiss").addEventListener("click", () => {
          window.open("securevault-reminder://dismiss");
        });

        document.getElementById("open").addEventListener("click", () => {
          window.open("securevault-reminder://open");
        });
      </script>
    </body>
    </html>
  `;

  popup.loadURL(
    "data:text/html;charset=utf-8," + encodeURIComponent(html)
  ).catch((error) => {
    console.error("Failed to load reminder popup:", error);
    stopReminderSound(key);
    closeReminderPopup(key);
  });

  popup.once("ready-to-show", () => {
    if (popup.isDestroyed()) return;

    popup.setAlwaysOnTop(true, "screen-saver");
    popup.show();
    popup.focus();
  });
}

/* ==========================================================================
   REMINDER POLLING
   ========================================================================== */

async function checkDueReminders() {
  try {
    const port = process.env.SV_PORT || "4787";

    const body = await httpGetJson(
      `http://127.0.0.1:${port}/api/due-reminders`
    );

    const due = Array.isArray(body.due) ? body.due : [];

    for (const reminder of due) {
      const key = getReminderKey(reminder);

      if (dismissedReminders.has(key)) continue;
      if (reminderSnoozeTimers.has(key)) continue;
      if (shownReminders.has(key)) continue;

      shownReminders.add(key);
      showReminderPopup(reminder);
    }
  } catch (error) {
    console.warn(
      "Reminder check failed; it will retry:",
      error.message
    );
  }
}

function startReminderPolling() {
  if (reminderPollingTimer) {
    clearInterval(reminderPollingTimer);
  }

  checkDueReminders();
  reminderPollingTimer = setInterval(checkDueReminders, 60 * 1000);
}

/* ==========================================================================
   ELECTRON LIFECYCLE
   ========================================================================== */

app.whenReady().then(async () => {
  try {
    if (process.platform === "win32") {
      app.setAppUserModelId("com.securevault.app");
    }

    startLocalServer();
    createTray();

    await new Promise((resolve) => setTimeout(resolve, 1200));

    createWindow();
    startReminderPolling();
  } catch (error) {
    console.error("SecureVault startup failed:", error);
  }
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  } else {
    showMainWindow();
  }
});

app.on("window-all-closed", () => {
  // Keep running in the system tray so reminders continue.
});

app.on("before-quit", () => {
  isQuitting = true;

  if (reminderPollingTimer) {
    clearInterval(reminderPollingTimer);
    reminderPollingTimer = null;
  }

  for (const timer of reminderSnoozeTimers.values()) {
    clearTimeout(timer);
  }
  reminderSnoozeTimers.clear();

  for (const key of reminderAlarmProcesses.keys()) {
    stopReminderSound(key);
  }

  for (const popup of reminderWindows.values()) {
    if (popup && !popup.isDestroyed()) {
      popup.close();
    }
  }
  reminderWindows.clear();

  if (tray) {
    tray.destroy();
    tray = null;
  }

  stopLocalServer();
});
