# Firebase Config Troubleshooting

## When to Use
- Google sign-in popup appears and immediately closes
- Firebase config validation fails after build
- Debugging Firebase API key or config issues in web apps
- Verifying Firebase config placeholders were replaced correctly

## Purpose
This skill captures the debugging technique for diagnosing Firebase configuration issues, specifically when placeholder values prevent authentication from working.

## Procedure

### Step 1: Inspect the Firebase Config File
1. Read `src/lib/firebase.js` (or equivalent config file)
2. Check all config values for placeholder patterns
3. Verify each value is the FULL value, not a truncated or placeholder version

### Step 2: Check for Placeholder Patterns
Look for these common placeholder patterns:
- `apiKey: ***`
- `apiKey: "AIzaS..."`
- `authDomain: ***`
- Any value containing `...` (truncation marker)

### Step 3: Verify the API Key Length
Firebase API keys are 39 characters long. If the value is shorter, it's a placeholder.

### Step 4: Get Real Values from Firebase Console
1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Select the project
3. Click **Project Settings** → **Your apps** → **Web app**
4. Copy the config values (NOT the placeholders)
5. Replace placeholders in the config file

### Step 5: Replace Placeholders
1. Use byte-level operations when replacing values
2. Read the raw bytes of the file first (to detect CRLF vs LF, whitespace)
3. Replace the placeholder with the actual value
4. Verify the replacement succeeded

### Step 6: Verify Google Sign-In is Enabled
1. Go to Firebase Console → Authentication → Sign-in method
2. Find Google and click **Enable**
3. Click **Save**

### Step 7: Verify OAuth Redirect URI
1. Firebase Console → Project Settings → Your apps
2. Add the authorized JavaScript origin (e.g., `http://localhost:5173`)
3. Add the authorized redirect URI (e.g., `http://localhost:5173`)

### Step 8: Test
1. Rebuild: `npm run build` in `securevault`
2. Start dev server: `npm run dev`
3. Test Google sign-in

## Pitfalls

1. **Placeholder values like `apiKey: ***`**: Always check for this pattern. If present, the config is not configured correctly.

2. **Truncated API key**: Firebase API keys are 39 characters. If the value shows as `AIzaS...` or is shorter, it is not configured correctly.

3. **String replacement failures**: Python string replacement can fail if the file uses CRLF line endings, has extra whitespace, or the placeholder pattern doesn't match exactly. If replacement fails, read the raw bytes of the file to understand the actual content.

4. **Google Sign-In not enabled**: Ensure Google is enabled in Firebase Console. Without this, the sign-in popup will close immediately.

5. **OAuth redirect URI mismatch**: The OAuth redirect URI in Firebase Console must match your app's domain. For web testing, use `http://localhost:5173`.

6. **Multiple replacement attempts**: When you repeatedly try to replace a value and get "NOT FOUND", it usually means the placeholder pattern doesn't match the actual file content. Read the raw bytes of the file to understand what's actually there.

## User Preferences

- Proceed with fixes without asking for confirmation
- Keep responses concise and direct - explain what was fixed, not how
- Don't narrate tool calls
- The deliverable is a working artifact, not a description of the process
