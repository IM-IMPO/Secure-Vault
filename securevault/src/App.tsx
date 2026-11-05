/**
 * SecureVault — Main App
 *
 * Integrates:
 *   - CloudLoginScreen (first-run import screen)
 *   - Firebase auth state listener
 *   - Cloud sync status with manual sync trigger
 *
 * Flow:
 *   1. On first launch: show CloudLoginScreen
 *   2. User imports from cloud OR creates new vault OR skips cloud
 *   3. Main app loads with local vault
 *   4. Background sync keeps local + cloud in sync
 *   5. User can manually trigger "Sync now" from the toolbar
 */
import React, { useState, useEffect } from 'react';
// @ts-ignore
import CloudLoginScreen from './components/CloudLoginScreen';
// @ts-ignore
import { isLoggedIn, getUserEmail, signOut } from './lib/firebase.js';
// @ts-ignore
import { watchNetwork, getLastSyncTime, hasPendingSync, fullSync, pushToQueue } from './lib/cloudSync.js';

/**
 * App — SecureVault main component
 *
 * The app starts in "cloud setup" mode if:
 *   - No Firebase user is signed in AND
 *   - No local vault exists AND
 *   - A vault hasn't been created yet
 *
 * Otherwise, the main vault UI loads.
 */
const App: React.FC = () => {
  const [showCloudSetup, setShowCloudSetup] = useState<boolean | null>(null);
  const [syncStatus, setSyncStatus] = useState<string>('initializing');
  const [lastSync, setLastSync] = useState<string | null>(null);
  const [pendingSync, setPendingSync] = useState<boolean>(false);
  const [manualSyncLoading, setManualSyncLoading] = useState<boolean>(false);
  const [syncCount, setSyncCount] = useState<number>(0);
  const [masterPassword, setMasterPassword] = useState<string>('');
  const [showPassword, setShowPassword] = useState<boolean>(false);

  // Check if we should show cloud setup
  useEffect(() => {
    const isAuthReady = isLoggedIn();
    if (!isAuthReady) {
      setShowCloudSetup(true);
    } else {
      setShowCloudSetup(false);
    }
  }, []);

  // Watch network status
  useEffect(() => {
    const unsubscribe = watchNetwork((online: boolean) => {
      setSyncStatus(online ? 'online' : 'offline');
    });
    return () => unsubscribe();
  }, []);

  // Check last sync time and pending sync
  useEffect(() => {
    const last = getLastSyncTime();
    if (last) setLastSync(last);
    setPendingSync(hasPendingSync());
  }, []);

  // Trigger manual sync
  const handleManualSync = async () => {
    setManualSyncLoading(true);
    setSyncCount(c => c + 1);
    try {
      const userId = getUserEmail() ?? 'unknown-user';
      const result = await fullSync({}, userId);
      setLastSync(result?.updatedAt || new Date().toISOString());
      setPendingSync(false);
      setSyncStatus('online');
    } catch (err: any) {
      setSyncStatus('error');
      console.error('Manual sync failed:', err);
    } finally {
      setManualSyncLoading(false);
    }
  };

  // Auto-sync when offline->online transition occurs
  useEffect(() => {
    const handleOnline = () => {
      if (syncStatus === 'online' && hasPendingSync()) {
        pushToQueue({ type: 'auto-sync', retry: true });
      }
    };
    window.addEventListener('online', handleOnline);
    return () => window.removeEventListener('online', handleOnline);
  }, [syncStatus]);

  if (showCloudSetup === true) {
    return (
      <CloudLoginScreen
        onLoginComplete={() => setShowCloudSetup(false)}
        initialMode="import"
      />
    );
  }

  // Show main vault UI (placeholder + sync controls)
  return (
    <div className="sv-root">
      <header className="sv-header">
        <div className="sv-header-left">
          <h1 className="sv-logo">SecureVault</h1>
          <p className="sv-tagline">
            {syncStatus === 'online' ? 'Cloud synced' :
             syncStatus === 'offline' ? 'Offline — will sync soon' :
             'Setting up sync...'}
          </p>
        </div>
        <div className="sv-header-right">
          {lastSync && (
            <span className="sv-sync-time">
              Last sync: {new Date(lastSync).toLocaleString()}
            </span>
          )}
          {pendingSync && <span className="sv-sync-badge">Sync pending</span>}
          <button
            className="sv-sync-btn"
            onClick={handleManualSync}
            disabled={manualSyncLoading || syncStatus === 'offline'}
          >
            {manualSyncLoading ? (
              <span className="sv-spinner">&#8635;</span>
            ) : (
              <>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polyline points="23 4 23 10 17 10" />
                  <polyline points="1 20 1 14 7 14" />
                  <line x1="12" y1="18" x2="21" y2="18" />
                </svg>
                {syncCount > 0 ? `Sync #${syncCount}` : 'Sync now'}
              </>
            )}
          </button>
        </div>
      </header>

      <main className="sv-main">
        <div className="sv-placeholder">
          <h2>Sync Ready</h2>
          <p>
            Your vault is encrypted and stored locally. Use <strong>Sync now</strong>
            to upload it to the cloud. It is only accessible with your Gmail
            account and master password.
          </p>
          <div className="cloud-password-row" style={{ maxWidth: 420, margin: '16px auto' }}>
            <input
              type={showPassword ? 'text' : 'password'}
              placeholder="Enter master password"
              value={masterPassword}
              onChange={(e) => setMasterPassword(e.target.value)}
              disabled={manualSyncLoading}
              className="cloud-password-input"
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="cloud-password-toggle"
              disabled={manualSyncLoading}
            >
              {showPassword ? 'Hide' : 'Show'}
            </button>
          </div>
          <p className="sv-hint">
            {syncStatus === 'offline' && 'No internet connection — will sync automatically when you reconnect.'}
            {syncStatus === 'online' && 'All changes are being synced in the background.'}
          </p>
        </div>
      </main>

      <footer className="sv-footer">
        <p>
          <button
            className="sv-signout-btn"
            onClick={async () => {
              await signOut();
              setShowCloudSetup(true);
            }}
          >
            Sign out
          </button>
        </p>
      </footer>
    </div>
  );
};

export default App;
