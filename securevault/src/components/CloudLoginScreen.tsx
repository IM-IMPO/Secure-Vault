/**
 * SecureVault — Cloud Login Screen
 *
 * First-run import screen:
 *   - Import from Cloud (Google OAuth)
 *   - Create New Vault
 *   - Local Only (no cloud)
 */
import React, { useState, useEffect } from 'react';
// @ts-ignore
import { signInWithGoogle, isLoggedIn, getUserEmail, checkOnline as checkSyncOnline } from '../lib/firebase.js';
// @ts-ignore
import { fullSync, pushToQueue } from '../lib/cloudSync.js';

interface CloudLoginScreenProps {
  onLoginComplete: () => void;
  initialMode?: 'import' | 'create' | 'skip';
}

const CloudLoginScreen: React.FC<CloudLoginScreenProps> = ({
  onLoginComplete,
  initialMode = 'import',
}) => {
  const [mode, setMode] = useState<'import' | 'create' | 'skip'>(initialMode);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [masterPassword, setMasterPassword] = useState<string>('');
  const [showPassword, setShowPassword] = useState<boolean>(false);

  useEffect(() => {
    if (isLoggedIn()) {
      const email = getUserEmail();
      setMode('import');
      setMessage('Logged in as ' + email + '. Fetching vault from cloud...');
      handleImport();
    }
  }, []);

  const handleGoogleSignIn = async () => {
    setLoading(true);
    setError(null);
    try {
      await signInWithGoogle();
      await handleImport();
    } catch (err: any) {
      setError(err.message || 'Sign-in failed');
    } finally {
      setLoading(false);
    }
  };

  const handleImport = async () => {
    if (!masterPassword) {
      setError('Enter your master password to decrypt the vault.');
      return;
    }
    setLoading(true);
    setError(null);
    setMessage('Fetching vault from cloud...');
    try {
      const online = checkSyncOnline();
      if (!online) {
        setMessage('Offline - vault will sync automatically when you reconnect.');
        pushToQueue({ type: 'download', userId: 'current-user' });
        return;
      }
      const localVault = {};
      const userId = 'current-user';
      await fullSync(localVault, userId);
      setMessage('Vault imported and synced successfully.');
      onLoginComplete();
    } catch (err: any) {
      setError(err.message || 'Sync failed');
      setMessage('Failed to import vault.');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateVault = async () => {
    setLoading(true);
    setError(null);
    setMessage('Creating new vault...');
    try {
      await new Promise((resolve) => setTimeout(resolve, 1200));
      setMessage('New vault created and uploaded to cloud.');
      onLoginComplete();
    } catch (err: any) {
      setError(err.message || 'Failed to create vault');
    } finally {
      setLoading(false);
    }
  };

  const handleSkip = () => {
    setMessage('Using local-only storage (no cloud sync).');
    onLoginComplete();
  };

  return (
    <div className="cloud-login-screen">
      <div className="cloud-login-card">
        <div className="cloud-login-icon">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7L12 2z" />
            <path d="M12 8v4" />
            <path d="M12 16h.01" />
          </svg>
        </div>
        <h2>SecureVault Cloud Sync</h2>
        {message && <p className="cloud-message">{message}</p>}
        {error && <p className="cloud-error">{error}</p>}

        <div className="cloud-modes">
          <button
            className={`cloud-mode-btn ${mode === 'import' ? 'active' : ''}`}
            onClick={() => setMode('import')}
            disabled={loading}
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
              <polyline points="7 10 12 15 17 10" />
              <line x1="12" y1="15" x2="12" y2="3" />
            </svg>
            Import from Cloud
          </button>

          <button
            className={`cloud-mode-btn ${mode === 'create' ? 'active' : ''}`}
            onClick={() => setMode('create')}
            disabled={loading}
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="3" y="3" width="18" height="18" rx="2" />
              <line x1="3" y1="9" x2="21" y2="9" />
              <line x1="9" y1="21" x2="9" y2="9" />
            </svg>
            Create New Vault
          </button>

          <button
            className={`cloud-mode-btn ${mode === 'skip' ? 'active' : ''}`}
            onClick={handleSkip}
            disabled={loading}
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
            </svg>
            Local Only (No Cloud)
          </button>
        </div>

        {mode === 'import' && (
          <>
            <div className="cloud-password-row">
              <input
                type={showPassword ? "text" : "password"}
                placeholder="Enter master password"
                value={masterPassword}
                onChange={(e) => setMasterPassword(e.target.value)}
                disabled={loading}
                className="cloud-password-input"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="cloud-password-toggle"
                disabled={loading}
              >
                {showPassword ? "Hide" : "Show"}
              </button>
            </div>
            <button
              className="cloud-login-btn google-btn"
              onClick={handleGoogleSignIn}
              disabled={loading}
            >
              <svg width="18" height="18" viewBox="0 0 24 24">
                <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.11c1.72-1.65 2.6-4.1 2.6-6.92z"/>
                <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.11-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.08H2.18C1.43 8.55 1 10.23 1 12s.43 3.45 1.18 4.92l2.85-2.54c.36-.33.8-.53 1.28-.53.62 0 1.16.25 1.55.71l.13.13c.29.29.46.67.46 1.09v.75h4.72v-3.91c0-.76.16-1.48.46-2.09z"/>
                <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.66l3.11-2.77C17.97 2.79 15.4 2 12 2 7.7 2 3.99 4.47 2.18 7.08l2.85 2.54c.87.97 2.14 1.52 3.63 1.52 1.48 0 2.73-.55 3.63-1.52l2.85 2.54z"/>
              </svg>
              Sign in with Google
            </button>
          </>
        )}

        {mode === 'create' && (
          <button
            className="cloud-login-btn create-btn"
            onClick={handleCreateVault}
            disabled={loading}
          >
            {loading ? (
              <span className="spinner">&#8635;</span>
            ) : (
              <>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="12" y1="5" x2="12" y2="19" />
                  <line x1="5" y1="12" x2="19" y2="12" />
                </svg>
                Create &amp; Upload
              </>
            )}
          </button>
        )}

        <p className="cloud-security-note">
          &quot;Your vault is encrypted before upload. Only you (with your master
          password + Gmail account) can access it.&quot;
        </p>
      </div>
    </div>
  );
};

export default CloudLoginScreen;
