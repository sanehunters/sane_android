package com.sanehunters.probe;

import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * The one evidence channel every component of the probe writes through.
 *
 * WHY A FILE: some stock OEM builds drop app-level Log.i from logcat entirely, and a busy logcat ring
 * buffer rotates within minutes. A PROBE| line that only went to logcat can vanish while the exploit
 * worked, and the model then records a negative. Every line is therefore mirrored, without any
 * permission, to the app's own external-files directory:
 *     /sdcard/Android/data/com.sanehunters.probe/files/probe-<session>.log
 * Pull it with:  adb pull /sdcard/Android/data/com.sanehunters.probe/files/ $E/logs/probe/
 */
public final class Probe {
    public static final String TAG = "PROBE";
    private static final String SESSION = new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.ROOT).format(new Date());
    private static File file;

    private Probe() {}

    /** Appends one PROBE| line to logcat and to the session file. Returns the line for on-screen use. */
    public static synchronized String log(Context ctx, String line) {
        Log.i(TAG, line);
        try {
            File f = file(ctx);
            if (f != null) {
                try (FileOutputStream o = new FileOutputStream(f, true)) { o.write((line + "\n").getBytes("UTF-8")); }
            }
        } catch (Throwable t) { Log.i(TAG, "PROBE|log|mirror_failed=" + t); }
        return line;
    }

    /** The mirror path, or null when no external-files dir exists on this build (then logcat is the only channel). */
    public static synchronized File file(Context ctx) {
        if (file == null && ctx != null) {
            File dir = ctx.getExternalFilesDir(null);
            if (dir != null) file = new File(dir, "probe-" + SESSION + ".log");
        }
        return file;
    }
}
