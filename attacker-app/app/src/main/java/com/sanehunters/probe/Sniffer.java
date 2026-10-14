package com.sanehunters.probe;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/**
 * D05 implicit-broadcast receiver. Used at RUNTIME by MainActivity's `sniff` step
 * (registerReceiver + RECEIVER_EXPORTED): since API 26 the system never delivers an implicit broadcast to a
 * manifest-declared receiver, so a manifest entry for an implicit action records nothing by construction.
 * The commented manifest block exists only for EXPLICIT or ordered broadcasts aimed at us by component name.
 * Records every extra of every received broadcast; the `sniff` step ends with a positive-control broadcast
 * to ourselves, so `received` is never read as a negative when the instrument itself did not fire.
 */
public class Sniffer extends BroadcastReceiver {
    volatile int received = 0;
    volatile boolean controlSeen = false;
    private final Context owner;

    public Sniffer() { this(null); }          // manifest instantiation (explicit/ordered tests only)
    public Sniffer(Context owner) { this.owner = owner; }

    @Override public void onReceive(Context ctx, Intent i) {
        Context c = owner != null ? owner : ctx;
        received++;
        boolean control = i.hasExtra("probe_control");
        if (control) controlSeen = true;
        Probe.log(c, "PROBE|sniff|action=" + i.getAction() + "|data=" + i.getData() + "|package=" + i.getPackage()
                + "|control=" + control + "|flags=0x" + Integer.toHexString(i.getFlags())
                + (isOrderedBroadcast() ? "|ordered=true" : ""));
        if (i.getExtras() != null)
            for (String k : i.getExtras().keySet())
                Probe.log(c, "PROBE|sniff|extra=" + k + "|value=" + String.valueOf(i.getExtras().get(k)) + (control ? "" : " (CANDIDATE: an implicit broadcast reached a zero-permission app)"));
    }
}
