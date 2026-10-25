package com.imimpo.securevault;

import android.os.Bundle;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        // Registered before super.onCreate so it lands in the bridge's initial
        // plugin list rather than being attached to an already-created bridge.
        registerPlugin(BiometricPlugin.class);
        super.onCreate(savedInstanceState);
    }
}
