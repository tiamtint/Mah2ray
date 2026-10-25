package com.v2ray.ang.ui.server

import com.v2ray.ang.R
import com.v2ray.ang.core.AetherCoreManager
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.fmt.AetherFmt
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class AetherProblemsTest {

    /** An Aether profile carrying [text] as its command, or built from its settings without one. */
    private fun profile(text: String? = null) = ProfileItem.create(EConfigType.AETHER).apply { aetherCommand = text }

    private val listenerProblems = setOf(
        AetherFmt.Problem.LISTEN_PORT_TAKEN,
        AetherFmt.Problem.LISTEN_PORT_SHARED,
        AetherFmt.Problem.LISTEN_PORT_INVALID,
        AetherFmt.Problem.LISTEN_ADDRESS_INVALID,
        AetherFmt.Problem.LISTEN_ADDRESS_UNREACHABLE,
    )

    @Test
    fun eachProblemHasItsMessage() {
        val plain = mapOf(
            AetherFmt.Problem.INVALID_MASQUE_SNI to R.string.aether_invalid_masque_sni,
            AetherFmt.Problem.INVALID_PEER to R.string.aether_invalid_endpoint,
            AetherFmt.Problem.INVALID_HOP to R.string.aether_invalid_hop,
            AetherFmt.Problem.SHARED_HOP to R.string.aether_same_hop,
            AetherFmt.Problem.INVALID_FRAGMENT to R.string.aether_invalid_fragment,
            AetherFmt.Problem.INVALID_DNS to R.string.aether_invalid_dns,
            AetherFmt.Problem.INVALID_EXIT_LOC to R.string.aether_invalid_exit_loc,
            AetherFmt.Problem.INVALID_ECH_DNS to R.string.aether_invalid_ech_dns,
            AetherFmt.Problem.INVALID_ECH_DOMAIN to R.string.aether_invalid_ech_domain,
            AetherFmt.Problem.PSIPHON_NEEDS_MASQUE to R.string.aether_psiphon_needs_masque,
            AetherFmt.Problem.NEXT_PORT_TAKEN to R.string.aether_next_port_taken,
            AetherFmt.Problem.TOR_NEEDS_MASQUE to R.string.aether_tor_needs_masque,
            AetherFmt.Problem.TOR_PSIPHON_CONFLICT to R.string.aether_tor_psiphon_conflict,
            AetherFmt.Problem.TOR_BRIDGES_MISSING to R.string.aether_tor_bridges_missing,
            AetherFmt.Problem.INVALID_COMMAND to R.string.aether_invalid_command,
        )
        plain.forEach { (problem, id) -> assertEquals(EditorMessage(id), messageOfAetherProblem(problem, profile(), emptySet(), 10819), problem.name) }
        // Every other problem is about the listeners of a command, below.
        assertEquals(AetherFmt.Problem.entries.toSet() - listenerProblems, plain.keys)
    }

    @Test
    fun aMessageAboutTheListenersOfACommandNamesThePortOrTheOption() {
        val taken = profile("aether --wg --bind 127.0.0.1:20808 --http-proxy 127.0.0.1:10808")
        assertEquals(
            EditorMessage(R.string.aether_listen_port_taken, 10808),
            messageOfAetherProblem(AetherFmt.Problem.LISTEN_PORT_TAKEN, taken, setOf(10808), 10819),
        )
        val shared = profile("aether --wg --bind 127.0.0.1:20808 --http-proxy 127.0.0.1:20808")
        assertEquals(
            EditorMessage(R.string.aether_listen_port_shared, 20808),
            messageOfAetherProblem(AetherFmt.Problem.LISTEN_PORT_SHARED, shared, emptySet(), 10819),
        )
        val noPort = profile("aether --wg --bind 127.0.0.1:70000")
        assertEquals(
            EditorMessage(R.string.aether_listen_port_invalid, 70000),
            messageOfAetherProblem(AetherFmt.Problem.LISTEN_PORT_INVALID, noPort, emptySet(), 10819),
        )
        val noAddress = profile("aether --wg --tor --tor-bind 127.0.0.1:20808 --bind localhost:20809")
        assertEquals(
            EditorMessage(R.string.aether_listen_address_invalid, "--bind"),
            messageOfAetherProblem(AetherFmt.Problem.LISTEN_ADDRESS_INVALID, noAddress, emptySet(), 10819),
        )
        val unreachable = profile("aether --wg --tor --tor-bind [::1]:20808")
        assertEquals(
            EditorMessage(R.string.aether_listen_address_unreachable, AetherCoreManager.TOR_BIND),
            messageOfAetherProblem(AetherFmt.Problem.LISTEN_ADDRESS_UNREACHABLE, unreachable, emptySet(), 10819),
        )
    }

    @Test
    fun withNothingElseToNameAMessageNamesTheListenPort() {
        // A profile built from its settings listens on the listen port alone, and has no command to name another.
        val settings = profile()
        assertEquals(
            EditorMessage(R.string.aether_listen_port_taken, 20808),
            messageOfAetherProblem(AetherFmt.Problem.LISTEN_PORT_TAKEN, settings, emptySet(), 20808),
        )
        assertEquals(
            EditorMessage(R.string.aether_listen_port_shared, 20808),
            messageOfAetherProblem(AetherFmt.Problem.LISTEN_PORT_SHARED, settings, emptySet(), 20808),
        )
        assertEquals(
            EditorMessage(R.string.aether_listen_port_invalid, 20808),
            messageOfAetherProblem(AetherFmt.Problem.LISTEN_PORT_INVALID, settings, emptySet(), 20808),
        )
        assertEquals(
            EditorMessage(R.string.aether_listen_address_invalid, ""),
            messageOfAetherProblem(AetherFmt.Problem.LISTEN_ADDRESS_INVALID, profile("   "), emptySet(), 20808),
        )
        assertEquals(
            EditorMessage(R.string.aether_listen_address_unreachable, ""),
            messageOfAetherProblem(AetherFmt.Problem.LISTEN_ADDRESS_UNREACHABLE, settings, emptySet(), 20808),
        )
    }
}
