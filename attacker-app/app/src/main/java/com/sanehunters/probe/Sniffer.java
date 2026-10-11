package com.sanehunters.probe;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * D05 implicit-broadcast test receiver. Disabled by default: enable the <receiver> block in the manifest
 * with the action the victim sends implicitly. Records every extra of a received implicit broadcast.
 */
public class Sniffer extends BroadcastReceiver {
    @Override public void onReceive(Context ctx, Intent i) {
        Log.i("PROBE", "PROBE|sniff|action=" + i.getAction() + "|data=" + i.getData());
        if (i.getExtras() != null)
            for (String k : i.getExtras().keySet()) Log.i("PROBE", "PROBE|sniff|extra=" + k + "|value=" + String.valueOf(i.getExtras().get(k)));
    }
}
