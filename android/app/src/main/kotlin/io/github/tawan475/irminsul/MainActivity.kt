package io.github.tawan475.irminsul

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/** Phase 0 spike screen: Start/Stop and the forwarder's counters. */
class MainActivity : Activity() {
    private lateinit var status: TextView
    private val ticker = Handler(Looper.getMainLooper())
    private val tick = object : Runnable {
        override fun run() {
            val stats = NativeBridge.stats()
            status.text = if (stats.isEmpty()) "Stopped\n${GameVpnService.lastPcap ?: ""}"
            else "Running\n${GameVpnService.lastPcap}\n\n${stats.replace(' ', '\n')}"
            ticker.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = (16 * resources.displayMetrics.density).toInt()
        status = TextView(this).apply { textSize = 16f }
        val start = Button(this).apply {
            text = "Start VPN"
            setOnClickListener { requestVpn() }
        }
        val stop = Button(this).apply {
            text = "Stop VPN"
            setOnClickListener {
                startService(Intent(this@MainActivity, GameVpnService::class.java).setAction(GameVpnService.ACTION_STOP))
            }
        }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad * 3, pad, pad)
            addView(start)
            addView(stop)
            addView(status)
        })
    }

    private fun requestVpn() {
        val consent = VpnService.prepare(this)
        Log.i("irminsul", "Start tapped, consent needed: ${consent != null}")
        if (consent != null) startActivityForResult(consent, REQUEST_VPN) else startVpn()
    }

    @Deprecated("Activity result API is androidx; the spike has no dependencies")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        Log.i("irminsul", "VPN consent result: $resultCode")
        if (requestCode == REQUEST_VPN && resultCode == RESULT_OK) startVpn()
    }

    private fun startVpn() {
        val started = startService(Intent(this, GameVpnService::class.java))
        Log.i("irminsul", "startService -> $started")
    }

    override fun onResume() {
        super.onResume()
        ticker.post(tick)
    }

    override fun onPause() {
        ticker.removeCallbacks(tick)
        super.onPause()
    }

    private companion object {
        const val REQUEST_VPN = 1
    }
}
