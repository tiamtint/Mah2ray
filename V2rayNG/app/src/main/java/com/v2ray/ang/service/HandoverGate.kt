package com.v2ray.ang.service

/**
 * PattNG: whether a handover of a [NetworkMonitor] may still begin, from its register() to its unregister().
 *
 * A handover claims its start under the gate's lock ([whileOpen]), and [close] takes the same lock, so none begins once
 * close() has returned. The work a claim lets through runs outside the lock, for as long as it takes: a stop on the main
 * thread waits at most for a claim under way, never for a reload.
 */
internal class HandoverGate {
    private val lock = Any()
    private var open = false

    /** Whether a claim would be let through now; a claim itself goes by [whileOpen]. */
    val isOpen: Boolean
        get() = synchronized(lock) { open }

    fun open() {
        synchronized(lock) { open = true }
    }

    /** Closes the gate: a claim under way ends first, and none is let through once this has returned. */
    fun close() {
        synchronized(lock) { open = false }
    }

    /** [claim], run under the lock while the gate is open, and what it returns; null once the gate is closed. Keep it short. */
    fun <T> whileOpen(claim: () -> T): T? = synchronized(lock) { if (open) claim() else null }

    /**
     * Runs [work] once [claim] has said yes under the lock, while the gate is open, and says whether it ran: a handover
     * claimed before [close] has returned goes on; none is claimed after.
     */
    fun runClaimed(claim: () -> Boolean, work: () -> Unit): Boolean {
        if (whileOpen(claim) != true) return false
        work()
        return true
    }
}
