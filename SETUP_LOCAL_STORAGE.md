# SecureVault — running fully locally with real file storage

This version saves every change (passwords, notes, transactions, budgets,
settings, account info) to an actual file on your PC:

  D:\Local Data\securevault-data.json

Nothing is sent over the internet. Two pieces run together on your machine:

  1. A tiny local server (server.js) — reads/writes that file
  2. The React app (SecureVault.jsx) — the UI you already have, now talking
     to that local server instead of browser storage

---

## One-time setup

If you haven't already created the Vite project:

    npm create vite@latest securevault
    cd securevault
    npm install
    npm install lucide-react recharts

Now add the two files from this drop-in:

  - Copy `SecureVault.jsx` over `src/App.jsx`
  - Copy `server.js` into the project root (same folder as `package.json`)

Install what the server needs:

    npm install express cors

## Add npm scripts (optional but convenient)

Open `package.json` and add these two lines inside `"scripts"`:

    "server": "node server.js",
    "dev:all": "concurrently \"npm:server\" \"npm:dev\""

Then install `concurrently` so `dev:all` can run both at once:

    npm install --save-dev concurrently

## Running it

Every time you want to use SecureVault, you need BOTH running:

**Terminal 1 — the local data server:**

    npm run server

You should see:

    SecureVault local server running at http://localhost:4787
    Saving data to: D:\Local Data\securevault-data.json

**Terminal 2 — the app itself:**

    npm run dev

Open the printed localhost URL (usually http://localhost:5173).

(Or, if you added the `dev:all` script above, just run `npm run dev:all`
in one terminal and it starts both.)

## First login

- Default username: `jreyes`
- Default email: `j.reyes@gmail.com`
- Default master password: `changeme123`
- Default PIN: `1234`

Change these immediately from Settings → Account once you're in — they're
checked for real now, so whatever you set there is what the lock screen
will require going forward.

## Where things are checked

- Sidebar (bottom-left) shows a green "Local save: D:\Local Data" dot when
  the server is reachable, or a red "Local server offline" dot if it isn't.
- Settings → Data shows the exact file path currently in use, and has an
  "Erase local data" button that wipes the file and resets to demo data.

## If D:\ doesn't exist on your machine

Open `server.js` and change this line near the top to any folder that does
exist:

    const DATA_DIR = process.env.SV_DATA_DIR || "D:\\Local Data";

For example, to save to your Documents folder instead:

    const DATA_DIR = process.env.SV_DATA_DIR || "C:\\Users\\YourName\\Documents\\SecureVault Data";

## Important honesty note

This is still a front-end prototype's idea of "encryption" — the data file
is plain JSON on disk, not AES-256-GCM ciphertext, and the master
password/PIN checks happen in the browser, not against a hashed value.
It's genuinely local-only and genuinely persists between runs, but it is
not the zero-knowledge, cryptographically-secured system described in the
original spec. Turning this into that would mean adding real password
hashing (e.g. Argon2id) and real client-side encryption (e.g. Web Crypto's
AES-GCM) around the data before it's written to disk — happy to build that
next if you want the real thing instead of the simulation.
