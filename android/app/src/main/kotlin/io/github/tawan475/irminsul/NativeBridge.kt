package io.github.tawan475.irminsul

/** The Rust forwarder in `android/native` (libirminsul_android.so). */
object NativeBridge {
    init {
        System.loadLibrary("irminsul_android")
    }

    /** Takes ownership of [fd] (a detached tun descriptor). 0 on success. */
    external fun start(fd: Int, pcapPath: String): Int

    external fun stop()

    /** One line of counters, or "" when not running. */
    external fun stats(): String
}
