package com.v2ray.ang.service

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class HandoverGateTest {

    @Test
    fun aHandoverIsLetThroughOnlyBetweenRegisterAndUnregister() {
        val gate = HandoverGate()
        assertFalse(gate.isOpen)
        assertNull(gate.whileOpen { "reload" })
        gate.open()
        assertTrue(gate.isOpen)
        assertEquals("reload", gate.whileOpen { "reload" })
        gate.close()
        assertFalse(gate.isOpen)
        assertNull(gate.whileOpen { "reload" })
    }

    @Test
    fun unregisterWaitsForAClaimUnderWayAndLetsNoneThroughOnceItHasReturned() {
        val gate = HandoverGate().apply { open() }
        val claiming = CountDownLatch(1)
        val claimMayEnd = CountDownLatch(1)
        val claimer = thread { gate.whileOpen { claiming.countDown(); claimMayEnd.await(5, TimeUnit.SECONDS) } }
        assertTrue(claiming.await(5, TimeUnit.SECONDS))

        val closed = CountDownLatch(1)
        val closer = thread {
            gate.close()
            closed.countDown()
        }
        // The claim that began first ends first: close() waits for it.
        assertFalse(closed.await(200, TimeUnit.MILLISECONDS))
        claimMayEnd.countDown()
        assertTrue(closed.await(5, TimeUnit.SECONDS))
        claimer.join(5_000)
        closer.join(5_000)
        // A handover that comes after close() has returned begins nothing.
        assertNull(gate.whileOpen { "reload" })
    }

    @Test
    fun aHandoverIsHandledOnlyOnceClaimedWhileTheGateIsOpen() {
        val gate = HandoverGate()
        val handled = mutableListOf<String>()
        // Before register(): neither claimed nor handled.
        assertFalse(gate.runClaimed({ error("not claimed while closed") }) { handled += "before" })
        gate.open()
        // A claim that says no: not handled.
        assertFalse(gate.runClaimed({ false }) { handled += "refused" })
        assertTrue(gate.runClaimed({ true }) { handled += "claimed" })
        gate.close()
        assertFalse(gate.runClaimed({ error("not claimed once closed") }) { handled += "after" })
        assertEquals(listOf("claimed"), handled)
    }
}
