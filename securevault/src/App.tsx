import React, { useEffect, useState } from 'react';
import CloudLoginScreen from './components/CloudLoginScreen';
import { getAuthState, getUserEmail, signOut } from './lib/firebase.js';
import { watchNetwork, getLastSyncTime, hasPendingSync, fullSync, pushToQueue } from './lib/cloudSync.js';

const App: React.FC = () => {
  const [authReady, setAuthReady] = useState(false);
  const [firebaseUser, setFirebaseUser] = useState<any>(null);
  const [vaultUnlocked, setVaultUnlocked] = useState(false);
  const [masterPassword, setMasterPassword] = useState('');
  const [syncStatus, setSyncStatus] = useState('initializing');
  const [lastSync, setLastSync] = useState<string | null>(null);
  const [pendingSync, setPendingSync] = useState(false);
  const [manualSyncLoading, setManualSyncLoading] = useState(false);
  const [syncCount, setSyncCount] = useState(0);

  // Firebase login is NOT the same thing as unlocking the vault.
  useEffect(() => {
    const unsubscribe = getAuthState((user: any) => {
      setFirebaseUser(user);
      setAuthReady(true);

      if (!user) {
        setVaultUnlocked(false);
        setMasterPassword('');
      }
    });

    return unsubscribe;
  }, []);

  useEffect(() => {
    const unsubscribe = watchNetwork((online: boolean) => {
      setSyncStatus(online ? 'online' : 'offline');
    });

    return () => unsubscribe();
  }, []);

  useEffect(() => {
    const last = getLastSyncTime();

    if (last) {
      setLastSync(last);
    }

    setPendingSync(hasPendingSync());
  }, []);

  const handleManualSync = async () => {
    if (!masterPassword || !firebaseUser) return;

    setManualSyncLoading(true);
    setSyncCount((c) => c + 1);

    try {
      const userId =
        firebaseUser.uid ||
        getUserEmail() ||
        'unknown-user';

      const result = await fullSync(
        {},
        userId,
        null,
        masterPassword
      );

      setLastSync(
        result?.updatedAt ||
        new Date().toISOString()
      );

      setPendingSync(false);
      setSyncStatus('online');
    } catch (err) {
      console.error('Manual sync failed:', err);
      setSyncStatus('error');
    } finally {
      setManualSyncLoading(false);
    }
  };

  useEffect(() => {
    const handleOnline = () => {
      if (hasPendingSync()) {
        pushToQueue({
          type: 'auto-sync',
          retry: true
        });
      }
    };

    window.addEventListener('online', handleOnline);

    return () => {
      window.removeEventListener('online', handleOnline);
    };
  }, []);

  if (!authReady) {
    return (
      <div className="cloud-login-screen">
        <div className="cloud-login-card">
          <h2>SecureVault</h2>
          <p className="cloud-message">
            Checking your secure session...
          </p>
        </div>
      </div>
    );
  }

  // IMPORTANT:
  // A remembered Google login CANNOT bypass the master password.
  if (!vaultUnlocked) {
    return (
      <CloudLoginScreen
        onLoginComplete={(password: string) => {
          setMasterPassword(password);
          setVaultUnlocked(true);
        }}
      />
    );
  }

  return (
    <div className="sv-root">
      <header className="sv-header">
        <div className="sv-header-left">
          <h1 className="sv-logo">SecureVault</h1>

          <p className="sv-tagline">
            {syncStatus === 'online'
              ? 'Cloud synced'
              : syncStatus === 'offline'
              ? 'Offline — will sync soon'
              : syncStatus === 'error'
              ? 'Sync error'
              : 'Setting up sync...'}
          </p>
        </div>

        <div className="sv-header-right">
          {lastSync && (
            <span className="sv-sync-time">
              Last sync: {new Date(lastSync).toLocaleString()}
            </span>
          )}

          {pendingSync && (
            <span className="sv-sync-badge">
              Sync pending
            </span>
          )}

          <button
            className="sv-sync-btn"
            onClick={handleManualSync}
            disabled={
              manualSyncLoading ||
              syncStatus === 'offline'
            }
          >
            {manualSyncLoading ? (
              <span className="sv-spinner">&#8635;</span>
            ) : (
              `Sync ${syncCount > 0 ? `#${syncCount}` : 'now'}`
            )}
          </button>
        </div>
      </header>

      <main className="sv-main">
        <div className="sv-placeholder">
          <h2>SecureVault Unlocked</h2>

          <p>
            Your vault has been unlocked with your master password.
          </p>
        </div>
      </main>

      <footer className="sv-footer">
        <p>
          <button
            className="sv-signout-btn"
            onClick={async () => {
              await signOut();
              setVaultUnlocked(false);
              setMasterPassword('');
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