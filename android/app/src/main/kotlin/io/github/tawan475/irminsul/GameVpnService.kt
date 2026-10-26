package io.github.tawan475.irminsul

import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.util.Log
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * A VPN for the game alone: only [GAME_PACKAGE] is routed into the tunnel,
 * and the native forwarder sends its traffic on unchanged while copying the
 * game's KCP packets into a pcap file in the app's files folder.
 *
 * IPv4 only for now: an IPv6 route would make the stack accept connections
 * the phone may have no IPv6 to carry, so the game's IPv6 (if any) bypasses.
 */
class GameVpnService : VpnService() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "onStartCommand action=${intent?.action}")
        when (intent?.action) {
            ACTION_STOP -> stopVpn()
            else -> startVpn()
        }
        return START_NOT_STICKY
    }

    private fun startVpn() {
        if (NativeBridge.stats().isNotEmpty()) return
        val builder = Builder()
            .setSession("Irminsul")
            .setMtu(1500)
            .addAddress("10.111.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addAllowedApplication(GAME_PACKAGE)
        // The underlying network's resolvers, reached directly by the
        // forwarder (this app is outside the tunnel).
        val connectivity = getSystemService(ConnectivityManager::class.java)
        val dns = connectivity.getLinkProperties(connectivity.activeNetwork)?.dnsServers
            ?.filter { it is java.net.Inet4Address }.orEmpty()
        if (dns.isEmpty()) builder.addDnsServer("1.1.1.1") else dns.forEach { builder.addDnsServer(it) }

        val tun = builder.establish() ?: run {
            Log.e(TAG, "establish() returned null (VPN not prepared?)")
            return
        }
        val stamp = SimpleDateFormat("yyyy-MM-dd_HH-mm-ss", Locale.ROOT).format(Date())
        val pcap = File(filesDir, "game-$stamp.pcap")
        val fd = tun.detachFd()
        if (NativeBridge.start(fd, pcap.path) != 0) {
            Log.e(TAG, "native start failed")
            stopSelf()
            return
        }
        lastPcap = pcap.path
        Log.i(TAG, "VPN up for $GAME_PACKAGE, dns=$dns, pcap=${pcap.path}")
    }

    private fun stopVpn() {
        NativeBridge.stop()
        stopSelf()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    override fun onDestroy() {
        NativeBridge.stop()
        super.onDestroy()
    }

    companion object {
        const val GAME_PACKAGE = "com.miHoYo.GenshinImpact"
        const val ACTION_STOP = "io.github.tawan475.irminsul.STOP"
        private const val TAG = "irminsul"

        @Volatile
        var lastPcap: String? = null
    }
}
