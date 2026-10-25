package com.imimpo.securevault;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Biometric unlock for the Android app.
 *
 * The desktop app hands the vault key to Windows Hello and stores whatever it
 * returns. The Android equivalent is an Android Keystore key whose key material
 * only becomes usable after a successful BiometricPrompt, so the vault key is
 * stored as a GCM blob that cannot be decrypted without a live fingerprint or
 * face. That keeps the same shape as the desktop envelope: an encrypted
 * "protectedKey" that means nothing until the OS releases it.
 *
 * Both protect() and unlock() show a prompt and touch the key only inside
 * onAuthenticationSucceeded. A key with setUserAuthenticationRequired(true)
 * refuses to operate until the user has authenticated, so initialising the
 * cipher before the prompt fails — with a UserNotAuthenticatedException whose
 * message is null, which is why every crypto call lives in the callback.
 *
 * IMPORTANT — Android Keystore keys survive app updates and reinstalls. A key
 * created by an older build keeps whatever parameters it was created with, so
 * getKey(create=true) happily returns a key that no longer matches the spec
 * this build wants. That breaks GCM at doFinal (IllegalBlockSizeException)
 * with no error at generation time. Everything therefore keys off
 * KEY_SPEC_VERSION: a mismatch means the stored key is deleted and recreated,
 * and unlock() refuses rather than decrypting with a key it cannot trust.
 */
@CapacitorPlugin(name = "Biometric")
public class BiometricPlugin extends Plugin {

    private static final String TAG = "SecureVault";
    private static final String KEY_ALIAS = "securevault_biometric_key";
    private static final String PREFS = "securevault_biometric";
    private static final String PREF_BLOB = "blob";
    private static final String PREF_IV = "iv";
    private static final String PREF_KEYGEN = "keygen";
    /**
     * Bump whenever the KeyGenParameterSpec changes. Any key created under an
     * older version is discarded rather than reused.
     */
    private static final int KEY_SPEC_VERSION = 2;
    private static final int GCM_TAG_BITS = 128;
    /** 0 = read the stored key back, 1 = wrap a key and store it. */
    private static final int MODE_UNLOCK = 0;
    private static final int MODE_PROTECT = 1;
    /** How long a successful prompt authorises the key for. */
    private static final int AUTH_WINDOW_SECONDS = 30;

    /**
     * Must match the KeyProperties auth type used in getKey(). Only
     * AUTH_BIOMETRIC_STRONG exists there — AUTH_BIOMETRIC_WEAK is a
     * BiometricManager.Authenticators constant, not a KeyProperties one — so a
     * device with only a weak sensor reports "not available" rather than
     * passing the check and then failing when the key refuses to operate.
     */
    private int authenticators() {
        return BiometricManager.Authenticators.BIOMETRIC_STRONG;
    }

    /** "ProviderException" or "ProviderException: no such key", never a bare "null". */
    private String describe(Exception ex) {
        String name = ex.getClass().getSimpleName();
        String msg = ex.getMessage();
        return (msg == null || msg.isEmpty()) ? name : name + ": " + msg;
    }

    /** Class name plus the first stack frames, for the user to report back. */
    private String detail(Exception ex) {
        String trace = Log.getStackTraceString(ex);
        if (trace != null && trace.length() > 500) {
            trace = trace.substring(0, 500) + "...";
        }
        return describe(ex) + "\n" + trace;
    }

    private Cipher newCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    private SharedPreferences prefs() {
        return getContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private boolean keyExists() {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            return ks.containsAlias(KEY_ALIAS);
        } catch (Exception ex) {
            return false;
        }
    }

    private void deleteKey() {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (ks.containsAlias(KEY_ALIAS)) {
                ks.deleteEntry(KEY_ALIAS);
                Log.w(TAG, "deleted a biometric key left by an older build");
            }
        } catch (Exception ex) {
            Log.e(TAG, "failed to delete a stale biometric key", ex);
        }
    }

    /** True when the on-device key was created under the current spec. */
    private boolean keyIsCurrent() {
        return prefs().getInt(PREF_KEYGEN, 0) == KEY_SPEC_VERSION && keyExists();
    }

    private SecretKey getKey(boolean create) throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry(KEY_ALIAS, null);
        if (entry instanceof KeyStore.SecretKeyEntry) {
            return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        }
        if (!create) {
            return null;
        }
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true);

        // A positive window rather than 0 or -1: those are rejected by some
        // Android versions, and the key has to stay usable from the moment the
        // prompt succeeds into the cipher call that follows it.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(AUTH_WINDOW_SECONDS, KeyProperties.AUTH_BIOMETRIC_STRONG);
        } else {
            builder.setUserAuthenticationValidityDurationSeconds(AUTH_WINDOW_SECONDS);
        }

        generator.init(builder.build());
        return generator.generateKey();
    }

    private void persist(String blobB64, String ivB64) {
        prefs().edit()
            .putString(PREF_BLOB, blobB64)
            .putString(PREF_IV, ivB64)
            .putInt(PREF_KEYGEN, KEY_SPEC_VERSION)
            .apply();
    }

    private String readPref(String name) {
        return prefs().getString(name, null);
    }

    @PluginMethod
    public void check(PluginCall call) {
        JSObject res = new JSObject();
        int code;
        try {
            code = BiometricManager.from(getActivity()).canAuthenticate(authenticators());
        } catch (Exception ex) {
            Log.e(TAG, "biometric check failed", ex);
            call.reject("Couldn't check biometric availability: " + describe(ex), ex);
            return;
        }
        res.put("supported", code == BiometricManager.BIOMETRIC_SUCCESS);
        res.put(
            "reason",
            code == BiometricManager.BIOMETRIC_SUCCESS ? ""
                : code == BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE ? "No biometric hardware on this device."
                : code == BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ? "Biometric hardware is unavailable right now."
                : code == BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ? "No fingerprint or face is enrolled. Add one in Android Settings, then try again."
                : code == BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED ? "A security update is required before biometrics can be used."
                : "Biometrics aren't available on this device."
        );
        call.resolve(res);
    }

    /**
     * Wraps the caller's vault key. Generating the Keystore key needs no
     * authentication, but encrypting with it does — so the prompt is shown here
     * too, and the cipher work happens after it succeeds.
     */
    @PluginMethod
    public void protect(PluginCall call) {
        call.save();
        final String keyB64 = call.getString("key");
        if (keyB64 == null || keyB64.isEmpty()) {
            call.reject("No key was supplied to protect.");
            return;
        }
        // A key left behind by an older build keeps its original parameters and
        // makes GCM fail at doFinal. Discard it rather than reuse it.
        if (!keyIsCurrent()) {
            deleteKey();
            try {
                getKey(true);
            } catch (Exception ex) {
                Log.e(TAG, "creating biometric key failed", ex);
                call.reject("Couldn't create the device key: " + detail(ex), ex);
                return;
            }
        }
        FragmentActivity activity = hostActivity(call);
        if (activity == null) {
            return;
        }
        prompt(activity, keyB64, null, null, MODE_PROTECT, 0, call);
    }

    @PluginMethod
    public void clear(PluginCall call) {
        try {
            prefs().edit().clear().apply();
            deleteKey();
            call.resolve(new JSObject().put("ok", true));
        } catch (Exception ex) {
            Log.e(TAG, "clearing protected key failed", ex);
            call.reject("Couldn't clear the protected key: " + detail(ex), ex);
        }
    }

    @PluginMethod
    public void unlock(PluginCall call) {
        call.save();
        if (!keyIsCurrent()) {
            call.reject(
                "Biometric unlock needs to be set up again: the device key on this phone was created by an older version. Turn biometric unlock off and on again in Settings."
            );
            return;
        }
        String blobB64 = readPref(PREF_BLOB);
        String ivB64 = readPref(PREF_IV);
        if (blobB64 == null || ivB64 == null) {
            call.reject("No biometric-protected key is stored on this device.");
            return;
        }
        FragmentActivity activity = hostActivity(call);
        if (activity == null) {
            return;
        }
        prompt(activity, null, blobB64, ivB64, MODE_UNLOCK, 0, call);
    }

    private FragmentActivity hostActivity(PluginCall call) {
        if (getActivity() instanceof FragmentActivity) {
            return (FragmentActivity) getActivity();
        }
        call.reject("Biometric unlock needs an activity that can host a prompt.");
        return null;
    }

    private void prompt(final FragmentActivity activity, final String plainB64, final String blobB64,
                        final String ivB64, final int mode, final int attempt, final PluginCall call) {
        BiometricPrompt prompt = new BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            new BiometricPrompt.AuthenticationCallback() {
                @Override
                public void onAuthenticationError(int code, CharSequence message) {
                    // ERROR_NEGATIVE_BUTTON / ERROR_USER_CANCELED are the user
                    // backing out, which is not a failure of the feature.
                    call.reject("Biometric prompt dismissed: " + message);
                }

                @Override
                public void onAuthenticationFailed() {
                    // One rejected finger or face. The prompt stays up and keeps
                    // accepting retries, so this must not reject the call.
                }

                @Override
                public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                    try {
                        Cipher cipher = newCipher();
                        if (mode == MODE_PROTECT) {
                            cipher.init(Cipher.ENCRYPT_MODE, getKey(false));
                            byte[] encrypted = cipher.doFinal(Base64.decode(plainB64, Base64.NO_WRAP));
                            String storedBlob = Base64.encodeToString(encrypted, Base64.NO_WRAP);
                            String storedIv = Base64.encodeToString(cipher.getIV(), Base64.NO_WRAP);

                            // Prove the blob is usable before reporting success:
                            // a key that encrypts but cannot decrypt back must
                            // not be persisted.
                            Cipher verify = newCipher();
                            verify.init(
                                Cipher.DECRYPT_MODE,
                                getKey(false),
                                new GCMParameterSpec(GCM_TAG_BITS, Base64.decode(storedIv, Base64.NO_WRAP))
                            );
                            verify.doFinal(Base64.decode(storedBlob, Base64.NO_WRAP));

                            persist(storedBlob, storedIv);
                            call.resolve(new JSObject().put("ok", true));
                        } else {
                            cipher.init(
                                Cipher.DECRYPT_MODE,
                                getKey(false),
                                new GCMParameterSpec(GCM_TAG_BITS, Base64.decode(ivB64, Base64.NO_WRAP))
                            );
                            byte[] plain = cipher.doFinal(Base64.decode(blobB64, Base64.NO_WRAP));
                            call.resolve(
                                new JSObject()
                                    .put("ok", true)
                                    .put("plain", Base64.encodeToString(plain, Base64.NO_WRAP))
                            );
                        }
                    } catch (Exception ex) {
                        Log.e(TAG, "biometric crypto failed (mode " + mode + ", attempt " + attempt + ")", ex);
                        if (attempt < 1 && isRetryable(ex)) {
                            prompt(activity, plainB64, blobB64, ivB64, mode, attempt + 1, call);
                        } else {
                            // A protect failure must not leave a blob that
                            // cannot be decrypted, so drop it.
                            if (mode == MODE_PROTECT) {
                                prefs().edit().clear().apply();
                            }
                            call.reject(
                                (mode == MODE_PROTECT ? "Couldn't store the protected key: " : "Biometric unlock failed: ")
                                    + detail(ex),
                                ex
                            );
                        }
                    }
                }
            }
        );

        BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock SecureVault")
            .setSubtitle("Confirm it's you")
            .setNegativeButtonText("Use master password")
            .setAllowedAuthenticators(authenticators())
            .build();

        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                prompt.authenticate(info);
            }
        });
    }

    private boolean isRetryable(Exception ex) {
        String name = ex.getClass().getName();
        return name.contains("UserNotAuthenticated")
            || name.contains("InvalidKeyException")
            || name.contains("KeyPermanentlyInvalidatedException");
    }
}
