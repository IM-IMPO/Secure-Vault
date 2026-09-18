const { app, BrowserWindow, ipcMain } = require("electron");
const path = require("path");
const { spawn } = require("child_process");

let mainWindow = null;
let serverProcess = null;

/* ==========================================================================
   PATHS
   ========================================================================== */

function isPackaged() {
  return app.isPackaged;
}

function getDataDirectory() {
  // Each Windows user gets their own SecureVault data directory.
  return path.join(app.getPath("userData"), "SecureVault Data");
}

function getServerPath() {
  /*
   * Development:
   *   C:\Users\Hate\Downloads\Vault\server.js
   *
   * Installed application:
   *   C:\Users\Hate\AppData\Local\Programs\securevault\resources\server.js
   */
  if (isPackaged()) {
    return path.join(process.resourcesPath, "server.js");
  }

  return path.join(app.getAppPath(), "server.js");
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

  console.log("========================================");
  console.log("Starting SecureVault local server");
  console.log("========================================");
  console.log("Packaged:", isPackaged());
  console.log("Server:", serverPath);
  console.log("Data:", dataDirectory);

  serverProcess = spawn(process.execPath, [serverPath], {
    cwd: path.dirname(serverPath),

    env: {
      ...process.env,

      // Required when Electron itself is being used as the Node runtime.
      ELECTRON_RUN_AS_NODE: "1",

      // Tell server.js where the encrypted SecureVault data belongs.
      SV_DATA_DIR: dataDirectory,

      // Local-only server.
      SV_PORT: "4787",

      /*
       * Because server.js may be placed in resources while the dependencies
       * live inside the Electron application, expose node_modules to Node.
       */
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
  if (!serverProcess) {
    return;
  }

  try {
    serverProcess.kill();
  } catch (error) {
    console.error("Failed to stop SecureVault server:", error);
  }

  serverProcess = null;
}

/* ==========================================================================
   MAIN WINDOW
   ========================================================================== */

function createWindow() {
  const indexPath = getIndexPath();
  const preloadPath = getPreloadPath();

  console.log("========================================");
  console.log("Creating SecureVault window");
  console.log("========================================");
  console.log("HTML:", indexPath);
  console.log("Preload:", preloadPath);

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
      preload: preloadPath
    },

    title: "SecureVault"
  });

  mainWindow.loadFile(indexPath).catch((error) => {
    console.error("Failed to load SecureVault:", error);

    if (!mainWindow || mainWindow.isDestroyed()) {
      return;
    }

    mainWindow.loadURL(
      `data:text/html;charset=utf-8,
      <html>
        <body style="
          background:#0B0F14;
          color:#fff;
          font-family:Arial;
          display:flex;
          align-items:center;
          justify-content:center;
          height:100vh;
        ">
          <div>
            <h1>SecureVault failed to load</h1>
            <p>${escapeHtml(error.message)}</p>
            <p>${escapeHtml(indexPath)}</p>
          </div>
        </body>
      </html>`
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

  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/* ==========================================================================
   WINDOWS HELLO / BIOMETRIC AUTHENTICATION
   ========================================================================== */

/*
 * Windows Hello implementation:
 *
 * 1. UserConsentVerifier displays the Windows Hello prompt.
 * 2. Only after successful verification do we use DPAPI.
 * 3. DPAPI protects the secret using the current Windows user account.
 *
 * Windows only.
 */

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
      {
        windowsHide: true
      }
    );

    let stdout = "";
    let stderr = "";

    ps.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    ps.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    ps.on("error", (error) => {
      reject(error);
    });

    ps.on("close", (code) => {
      const output = stdout.trim();

      if (code !== 0 && !output) {
        reject(
          new Error(
            stderr.trim() ||
              `PowerShell exited with code ${code}`
          )
        );

        return;
      }

      resolve(output);
    });
  });
}

/* --------------------------------------------------------------------------
   Validate Base64 before putting it into PowerShell.
   -------------------------------------------------------------------------- */

function isSafeBase64(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    /^[A-Za-z0-9+/=\s]+$/.test(value)
  );
}

/* --------------------------------------------------------------------------
   WinRT async helper.

   IMPORTANT:
   This uses a normal JavaScript string instead of a JavaScript template
   literal. That avoids the "Unexpected number" error caused by:

       `IAsyncOperation\`1`

   -------------------------------------------------------------------------- */

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

  "    $netTask = $method.Invoke(",
  "        $null,",
  "        @($WinRtTask)",
  "    )",

  "    $netTask.Wait(-1) | Out-Null",

  "    return $netTask.Result",
  "}"
].join("\n");

/* --------------------------------------------------------------------------
   Windows foreground-focus helper.

   Windows may otherwise keep the Windows Hello prompt behind the Electron
   window because PowerShell is a background process. AllowSetForegroundWindow
   lets the next foreground request (the Hello prompt) come to the front.
   -------------------------------------------------------------------------- */

const FOREGROUND_HELPER = [
  "Add-Type -Name Win32Foreground -Namespace SecureVault -MemberDefinition @'",
  "[DllImport(\"user32.dll\")]",
  "public static extern bool AllowSetForegroundWindow(int dwProcessId);",
  "'@",
  "[SecureVault.Win32Foreground]::AllowSetForegroundWindow(-1) | Out-Null"
].join("\n");

/* ==========================================================================
   CHECK WINDOWS HELLO AVAILABILITY
   ========================================================================== */

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

/* ==========================================================================
   WINDOWS HELLO VERIFICATION
   ========================================================================== */

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

/* ==========================================================================
   DPAPI PROTECTION
   ========================================================================== */

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

/* ==========================================================================
   FRIENDLY BIOMETRIC ERRORS
   ========================================================================== */

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

/* ==========================================================================
   BIOMETRIC IPC
   ========================================================================== */

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
      return {
        supported: true,
        reason: ""
      };
    }

    return {
      supported: false,
      reason: friendlyError(
        output,
        "Windows Hello is not available."
      )
    };
  } catch (error) {
    console.error("Windows Hello check failed:", error);

    return {
      supported: false,
      reason: error.message
    };
  }
});

/* ==========================================================================
   BIOMETRIC PROTECT
   ========================================================================== */

ipcMain.handle(
  "biometric:protect",
  async (_event, base64Bytes) => {
    if (process.platform !== "win32") {
      return {
        ok: false,
        error:
          "Biometric unlock currently only works on Windows."
      };
    }

    if (!isSafeBase64(base64Bytes)) {
      return {
        ok: false,
        error: "Invalid data."
      };
    }

    try {
      const output = await runPowerShell(
        protectScript(base64Bytes)
      );

      if (output.startsWith("OK:")) {
        return {
          ok: true,
          protected: output.slice(3).trim()
        };
      }

      return {
        ok: false,
        error: friendlyError(
          output,
          "Couldn't set up Windows Hello."
        )
      };
    } catch (error) {
      console.error("Windows Hello protect failed:", error);

      return {
        ok: false,
        error: error.message
      };
    }
  }
);

/* ==========================================================================
   BIOMETRIC UNLOCK
   ========================================================================== */

ipcMain.handle(
  "biometric:unlock",
  async (_event, protectedBase64) => {
    if (process.platform !== "win32") {
      return {
        ok: false,
        error:
          "Biometric unlock currently only works on Windows."
      };
    }

    if (!isSafeBase64(protectedBase64)) {
      return {
        ok: false,
        error: "Invalid data."
      };
    }

    try {
      const output = await runPowerShell(
        unlockScript(protectedBase64)
      );

      if (output.startsWith("OK:")) {
        return {
          ok: true,
          plain: output.slice(3).trim()
        };
      }

      return {
        ok: false,
        error: friendlyError(
          output,
          "Couldn't unlock with Windows Hello."
        )
      };
    } catch (error) {
      console.error("Windows Hello unlock failed:", error);

      return {
        ok: false,
        error: error.message
      };
    }
  }
);

/* ==========================================================================
   ELECTRON LIFECYCLE
   ========================================================================== */

app.whenReady().then(async () => {
  try {
    startLocalServer();

    // Allow Express to start before React tries to contact it.
    await new Promise((resolve) => {
      setTimeout(resolve, 1200);
    });

    createWindow();
  } catch (error) {
    console.error("SecureVault startup failed:", error);
  }
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

app.on("window-all-closed", () => {
  stopLocalServer();

  if (process.platform !== "darwin") {
    app.quit();
  }
});

app.on("before-quit", () => {
  stopLocalServer();
});