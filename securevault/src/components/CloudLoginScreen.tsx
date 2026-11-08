import React, { useEffect, useState } from 'react';
import {
  signInWithGoogle,
  getAuthState,
  getUserEmail
} from '../lib/firebase.js';

interface CloudLoginScreenProps {
  onLoginComplete: (masterPassword: string) => void;
}

const CloudLoginScreen: React.FC<CloudLoginScreenProps> = ({
  onLoginComplete
}) => {
  const [user, setUser] = useState<any>(null);
  const [authReady, setAuthReady] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [masterPassword, setMasterPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  useEffect(() => {
    const unsubscribe = getAuthState((currentUser: any) => {
      setUser(currentUser);
      setAuthReady(true);
      setLoading(false);
    });

    return unsubscribe;
  }, []);

  const handleGoogleSignIn = async () => {
    setLoading(true);
    setError(null);

    try {
      // IMPORTANT:
      // Do NOT unlock the vault here.
      // After Google login, the auth listener will show
      // the Master Password screen.
      await signInWithGoogle();
    } catch (err: any) {
      setError(
        err?.message ||
        'Google sign-in failed. Please try again.'
      );

      setLoading(false);
    }
  };

  const handleUnlock = (
    event: React.FormEvent
  ) => {
    event.preventDefault();

    if (!masterPassword.trim()) {
      setError('Please enter your master password.');
      return;
    }

    setError(null);

    // This is the ONLY place where the vault is unlocked.
    onLoginComplete(masterPassword);
  };

  if (!authReady) {
    return (
      <div className="cloud-login-screen">
        <div className="cloud-login-card">
          <h2>SecureVault</h2>

          <p className="cloud-message">
            Checking your Google session...
          </p>
        </div>
      </div>
    );
  }

  // User has not signed in with Google yet.
  if (!user) {
    return (
      <div className="cloud-login-screen">
        <div className="cloud-login-card">
          <div className="cloud-login-icon">
            🔐
          </div>

          <h2>SecureVault</h2>

          <p className="cloud-message">
            Sign in with your Google account to continue.
          </p>

          {error && (
            <p className="cloud-error">
              {error}
            </p>
          )}

          <button
            className="cloud-login-btn google-btn"
            onClick={handleGoogleSignIn}
            disabled={loading}
          >
            {loading
              ? 'Signing in...'
              : 'Sign in with Google'}
          </button>
        </div>
      </div>
    );
  }

  // User is logged into Google.
  // Now REQUIRE the master password.
  return (
    <div className="cloud-login-screen">
      <div className="cloud-login-card">
        <div className="cloud-login-icon">
          🔐
        </div>

        <h2>SecureVault</h2>

        <p className="cloud-message">
          Signed in as{' '}
          <strong>
            {user.email || getUserEmail()}
          </strong>
        </p>

        <h3>Enter your Master Password</h3>

        <p className="cloud-security-note">
          Google sign-in identifies you, but it does not
          unlock your encrypted vault.
        </p>

        {error && (
          <p className="cloud-error">
            {error}
          </p>
        )}

        <form onSubmit={handleUnlock}>
          <div className="cloud-password-row">
            <input
              type={showPassword ? 'text' : 'password'}
              placeholder="Enter master password"
              value={masterPassword}
              onChange={(e) => {
                setMasterPassword(e.target.value);
                setError(null);
              }}
              autoFocus
              autoComplete="current-password"
              className="cloud-password-input"
            />

            <button
              type="button"
              onClick={() =>
                setShowPassword((v) => !v)
              }
              className="cloud-password-toggle"
            >
              {showPassword ? 'Hide' : 'Show'}
            </button>
          </div>

          <button
            className="cloud-login-btn create-btn"
            type="submit"
            disabled={!masterPassword.trim()}
          >
            Unlock SecureVault
          </button>
        </form>
      </div>
    </div>
  );
};

export default CloudLoginScreen;