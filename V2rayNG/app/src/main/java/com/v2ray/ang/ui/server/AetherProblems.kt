package com.v2ray.ang.ui.server

import androidx.annotation.StringRes
import com.v2ray.ang.R
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.fmt.AetherFmt

/** PattNG: a message of the Aether editor: the string resource [id], with [argument] in it when it names one. */
internal data class EditorMessage(@StringRes val id: Int, val argument: Any? = null)

/**
 * PattNG: the message the Aether editor shows for [problem], which [AetherFmt.normalize] found in [config] with
 * [takenPorts] held, on the Aether listen port [listenPort]. Those about the listeners of a command name the port, or the
 * option, they are about; the listen port where nothing else is to be named.
 */
internal fun messageOfAetherProblem(problem: AetherFmt.Problem, config: ProfileItem, takenPorts: Set<Int>, listenPort: Int): EditorMessage =
    when (problem) {
        AetherFmt.Problem.INVALID_MASQUE_SNI -> EditorMessage(R.string.aether_invalid_masque_sni)
        AetherFmt.Problem.INVALID_PEER -> EditorMessage(R.string.aether_invalid_endpoint)
        AetherFmt.Problem.INVALID_HOP -> EditorMessage(R.string.aether_invalid_hop)
        AetherFmt.Problem.SHARED_HOP -> EditorMessage(R.string.aether_same_hop)
        AetherFmt.Problem.INVALID_FRAGMENT -> EditorMessage(R.string.aether_invalid_fragment)
        AetherFmt.Problem.INVALID_DNS -> EditorMessage(R.string.aether_invalid_dns)
        AetherFmt.Problem.INVALID_EXIT_LOC -> EditorMessage(R.string.aether_invalid_exit_loc)
        AetherFmt.Problem.INVALID_ECH_DNS -> EditorMessage(R.string.aether_invalid_ech_dns)
        AetherFmt.Problem.INVALID_ECH_DOMAIN -> EditorMessage(R.string.aether_invalid_ech_domain)
        AetherFmt.Problem.LISTEN_PORT_TAKEN ->
            EditorMessage(R.string.aether_listen_port_taken, AetherFmt.takenListenPort(config, takenPorts, listenPort) ?: listenPort)
        AetherFmt.Problem.LISTEN_PORT_SHARED ->
            EditorMessage(R.string.aether_listen_port_shared, AetherFmt.sharedListenPort(config, listenPort) ?: listenPort)
        AetherFmt.Problem.LISTEN_PORT_INVALID ->
            EditorMessage(R.string.aether_listen_port_invalid, AetherFmt.invalidListenPort(config, listenPort) ?: listenPort)
        AetherFmt.Problem.LISTEN_ADDRESS_INVALID ->
            EditorMessage(R.string.aether_listen_address_invalid, AetherFmt.invalidListener(config, listenPort).orEmpty())
        AetherFmt.Problem.LISTEN_ADDRESS_UNREACHABLE ->
            EditorMessage(R.string.aether_listen_address_unreachable, AetherFmt.unreachableListener(config, listenPort).orEmpty())
        AetherFmt.Problem.PSIPHON_NEEDS_MASQUE -> EditorMessage(R.string.aether_psiphon_needs_masque)
        AetherFmt.Problem.NEXT_PORT_TAKEN -> EditorMessage(R.string.aether_next_port_taken)
        AetherFmt.Problem.TOR_NEEDS_MASQUE -> EditorMessage(R.string.aether_tor_needs_masque)
        AetherFmt.Problem.TOR_PSIPHON_CONFLICT -> EditorMessage(R.string.aether_tor_psiphon_conflict)
        AetherFmt.Problem.TOR_BRIDGES_MISSING -> EditorMessage(R.string.aether_tor_bridges_missing)
        AetherFmt.Problem.INVALID_COMMAND -> EditorMessage(R.string.aether_invalid_command)
    }
