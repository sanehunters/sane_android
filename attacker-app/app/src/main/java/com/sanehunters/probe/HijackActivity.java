package com.sanehunters.probe;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

/**
 * D04 task-affinity test. Disabled by default: enable the <activity> block in the manifest and set
 * taskAffinity to the victim package. When the victim's task is resumed, a back-stack entry from another
 * package appearing in `dumpsys activity activities` is the observable; this screen only labels itself.
 */
public class HijackActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        TextView t = new TextView(this);
        t.setText("probe · HijackActivity (task-affinity test screen)\nIf you see this inside the victim's task, record dumpsys activity activities.");
        setContentView(t);
        Probe.log(this, "PROBE|hijack|resumed=true|task=" + getTaskId() + "|affinity=" + getApplicationInfo().taskAffinity);
    }
}
