package com.v2ray.ang.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.DataInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class SocksAnswersTest {

    /** A listener bound and not served, as a core's own is until its tunnel is up: the kernel queues what connects. */
    private fun quietListener() = ServerSocket(0, 50, InetAddress.getLoopbackAddress())

    /** The connections queued on [listener] so far, taken from it once no more come within [waitMs]. */
    private fun takeQueued(listener: ServerSocket, waitMs: Int = 300): List<Socket> {
        val taken = mutableListOf<Socket>()
        listener.soTimeout = waitMs
        while (true) {
            try {
                taken += listener.accept()
            } catch (_: SocketTimeoutException) {
                return taken
            }
        }
    }

    /** Answers the greeting [client] sent, as a SOCKS5 server does. */
    private fun answer(client: Socket) {
        val input = DataInputStream(client.getInputStream())
        input.readByte()
        repeat(input.readUnsignedByte()) { input.readByte() }
        client.getOutputStream().write(byteArrayOf(5, 0))
    }

    @Test
    fun aQuietListenerIsAskedOverOneConnectionUntilItAnswers() {
        // Long enough for the server thread below to answer the question's new connection on a busy machine.
        val answers = SocksAnswers(waitMs = 1_000)
        quietListener().use { listener ->
            repeat(2) { assertFalse(answers.answers(listener.localPort)) }
            // One connection waits in the listener's queue, not one for each question.
            val queued = takeQueued(listener)
            assertEquals(1, queued.size)
            // The tunnel comes up: it answers the waiting greeting, and serves the new connection the next question makes.
            queued.single().use { client ->
                answer(client)
                val server = thread(isDaemon = true) {
                    runCatching {
                        listener.soTimeout = 5_000
                        listener.accept().use(::answer)
                    }
                }
                assertTrue(answers.answers(listener.localPort))
                server.join(5_000)
            }
            assertEquals(0, takeQueued(listener).size)
        }
    }

    @Test
    fun anAnswerThatWaitedDoesNotOutliveItsServer() {
        val answers = SocksAnswers(waitMs = 100)
        val port: Int
        quietListener().use { listener ->
            port = listener.localPort
            assertFalse(answers.answers(port))
            // The core answers the waiting greeting, then ends, and its listener with it.
            takeQueued(listener).single().use(::answer)
        }
        assertFalse(answers.answers(port))
    }

    @Test
    fun anAnswerThatWaitedDoesNotSpeakForTheNextCoreOnThePort() {
        val answers = SocksAnswers(waitMs = 100)
        val port: Int
        quietListener().use { listener ->
            port = listener.localPort
            assertFalse(answers.answers(port))
            takeQueued(listener).single().use(::answer)
        }
        // A new core binds the port and says nothing yet, as a test's core does while its tunnel comes up.
        ServerSocket().use { next ->
            next.reuseAddress = true
            next.bind(InetSocketAddress(InetAddress.getLoopbackAddress(), port), 50)
            assertFalse(answers.answers(port))
        }
    }

    @Test
    fun aConnectionTheServerEndedIsAskedAnew() {
        // Long enough for the server thread below to answer the question's new connection on a busy machine.
        val answers = SocksAnswers(waitMs = 1_000)
        quietListener().use { listener ->
            assertFalse(answers.answers(listener.localPort))
            // The core that held it ends it, and the listener is served from then on.
            takeQueued(listener).single().close()
            val server = thread(isDaemon = true) {
                runCatching {
                    listener.soTimeout = 5_000
                    listener.accept().use(::answer)
                }
            }
            assertTrue(answers.answers(listener.localPort))
            server.join(5_000)
        }
    }

    @Test
    fun aServedListenerAnswersAtOnce() {
        val answers = SocksAnswers(waitMs = 1_000)
        ServerSocket(0, 50, InetAddress.getLoopbackAddress()).use { listener ->
            val server = thread(isDaemon = true) { runCatching { listener.accept().use(::answer) } }
            assertTrue(answers.answers(listener.localPort))
            server.join(5_000)
        }
    }

    @Test
    fun anInterruptedThreadThatAsksMeanwhileTakesNoAnswer() {
        val answers = SocksAnswers(waitMs = 1_000)
        quietListener().use { listener ->
            val port = listener.localPort
            // A first question waits for its answer...
            val first = thread { answers.answers(port) }
            Thread.sleep(200)
            // ... and a thread asking meanwhile, interrupted, gives up as a timeout does, rather than throwing.
            var reply: Boolean? = null
            var stillInterrupted = false
            val second = thread {
                Thread.currentThread().interrupt()
                reply = answers.answers(port)
                stillInterrupted = Thread.currentThread().isInterrupted
            }
            second.join(5_000)
            first.join(5_000)
            assertEquals(false, reply)
            assertTrue(stillInterrupted)
        }
    }

    @Test
    fun onlyAWholeAnswerOfASocksServerCounts() {
        val answers = SocksAnswers(waitMs = 1_000)
        fun replyingWith(reply: ByteArray): Boolean = ServerSocket(0, 50, InetAddress.getLoopbackAddress()).use { listener ->
            val server = thread(isDaemon = true) {
                runCatching {
                    listener.accept().use { client ->
                        client.getInputStream().read(ByteArray(3))
                        client.getOutputStream().write(reply)
                    }
                }
            }
            answers.answers(listener.localPort).also { server.join(5_000) }
        }
        assertTrue(replyingWith(byteArrayOf(5, 0)))
        // "None of the methods offered is acceptable" is a SOCKS5 server's answer as well.
        assertTrue(replyingWith(byteArrayOf(5, 0xFF.toByte())))
        // Another client's greeting, as two probes connected to each other read it: the version, then a count.
        assertFalse(replyingWith(byteArrayOf(5, 1, 0)))
        assertFalse(replyingWith(byteArrayOf(4, 0)))
    }

    @Test
    fun anAnswerThatBeganIsNotWaitedOnForItsRest() {
        // Long enough for the server thread below to write the version on a busy machine.
        val answers = SocksAnswers(waitMs = 1_000)
        ServerSocket(0, 50, InetAddress.getLoopbackAddress()).use { listener ->
            var closedByTheProbe = false
            val server = thread(isDaemon = true) {
                runCatching {
                    listener.accept().use { client ->
                        client.getInputStream().read(ByteArray(3))
                        // The version, and then nothing: a server that answers so is not waited on again.
                        client.getOutputStream().write(byteArrayOf(5))
                        client.soTimeout = 5_000
                        closedByTheProbe = client.getInputStream().read() == -1
                    }
                }
            }
            assertFalse(answers.answers(listener.localPort))
            server.join(5_000)
            assertTrue(closedByTheProbe)
        }
    }

    @Test
    fun aConnectionToItselfIsTold() {
        val loopback = InetAddress.getLoopbackAddress()
        assertTrue(SocksAnswers.isSelfConnect(InetSocketAddress(loopback, 40_000), InetSocketAddress(loopback, 40_000)))
        assertFalse(SocksAnswers.isSelfConnect(InetSocketAddress(loopback, 40_000), InetSocketAddress(loopback, 40_001)))
        assertFalse(SocksAnswers.isSelfConnect(null, null))
    }

    @Test
    fun aPortNothingListensOnAnswersNothing() {
        val answers = SocksAnswers(waitMs = 100)
        val closedPort = ServerSocket(0).use { it.localPort }
        assertFalse(answers.answers(closedPort))
        assertFalse(answers.answers(closedPort))
    }

    @Test
    fun questionsAskedTogetherShareOneConnection() {
        val answers = SocksAnswers(waitMs = 300)
        quietListener().use { listener ->
            val pool = Executors.newFixedThreadPool(8)
            try {
                val replies = List(8) { pool.submit<Boolean> { answers.answers(listener.localPort) } }
                    .map { it.get(10, TimeUnit.SECONDS) }
                assertTrue(replies.none { it })
            } finally {
                pool.shutdownNow()
            }
            assertEquals(1, takeQueued(listener).size)
        }
    }
}
