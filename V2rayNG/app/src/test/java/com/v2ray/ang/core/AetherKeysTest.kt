package com.v2ray.ang.core

import com.v2ray.ang.AppResources
import com.v2ray.ang.enums.AetherFingerprint
import com.v2ray.ang.enums.AetherKeyKind
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class AetherKeysTest {

    private fun valueAfter(arguments: List<String>, flag: String): String? =
        arguments.lastIndexOf(flag).takeIf { it >= 0 }?.let { arguments.getOrNull(it + 1) }

    /** The number of each TLS 1.2 suite by the name BoringSSL gives it, for the ones the fingerprints name. */
    private val suiteIds = mapOf(
        "ECDHE-ECDSA-AES128-GCM-SHA256" to 0xc02b,
        "ECDHE-RSA-AES128-GCM-SHA256" to 0xc02f,
        "ECDHE-ECDSA-AES256-GCM-SHA384" to 0xc02c,
        "ECDHE-RSA-AES256-GCM-SHA384" to 0xc030,
        "ECDHE-ECDSA-CHACHA20-POLY1305" to 0xcca9,
        "ECDHE-RSA-CHACHA20-POLY1305" to 0xcca8,
        "ECDHE-RSA-AES128-SHA" to 0xc013,
        "ECDHE-RSA-AES256-SHA" to 0xc014,
        "ECDHE-ECDSA-AES128-SHA" to 0xc009,
        "ECDHE-ECDSA-AES256-SHA" to 0xc00a,
        "ECDHE-ECDSA-AES128-SHA256" to 0xc023,
        "ECDHE-RSA-AES128-SHA256" to 0xc027,
        "AES128-GCM-SHA256" to 0x009c,
        "AES256-GCM-SHA384" to 0x009d,
        "AES128-SHA" to 0x002f,
        "AES256-SHA" to 0x0035,
    )

    /** The number of each TLS 1.2 suite by the name Xray's cipherSuites takes, Go's, for the ones its presets name. */
    private val xraySuiteIds = mapOf(
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" to 0xc02b,
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" to 0xc02f,
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" to 0xc02c,
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" to 0xc030,
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" to 0xcca9,
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" to 0xcca8,
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" to 0xc013,
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" to 0xc014,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" to 0xc00a,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" to 0xc023,
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256" to 0xc027,
        "TLS_RSA_WITH_AES_128_GCM_SHA256" to 0x009c,
        "TLS_RSA_WITH_AES_256_GCM_SHA384" to 0x009d,
        "TLS_RSA_WITH_AES_128_CBC_SHA" to 0x002f,
        "TLS_RSA_WITH_AES_256_CBC_SHA" to 0x0035,
    )

    /** The TLS 1.2 suites of a ClientHello's cipher_suites in hex, GREASE and the TLS 1.3 suites left out. */
    private fun tls12Of(captured: String): List<Int> =
        captured.chunked(4).map { it.toInt(16) }.filter { it and 0x0f0f != 0x0a0a && it !in 0x1301..0x1305 }

    private fun suitesOf(fingerprint: AetherFingerprint): List<Int> = fingerprint.ciphers.split(':').map(suiteIds::getValue)

    /** The number of each group by the name BoringSSL gives it, for every group it has (boring 5.3, with its post-quantum patch). */
    private val groupIds = mapOf(
        "P-256" to 0x0017,
        "P-384" to 0x0018,
        "P-521" to 0x0019,
        "X25519" to 0x001d,
        "X25519MLKEM768" to 0x11ec,
        "MLKEM1024" to 0x0202,
        "X25519Kyber768Draft00" to 0x6399,
        "P256Kyber768Draft00" to 0xfe32,
    )

    /** The number of each TLS 1.3 suite by its standard name. */
    private val tls13Ids = mapOf(
        "TLS_AES_128_GCM_SHA256" to 0x1301,
        "TLS_AES_256_GCM_SHA384" to 0x1302,
        "TLS_CHACHA20_POLY1305_SHA256" to 0x1303,
    )

    /** The TLS 1.3 suites of a ClientHello's cipher_suites in hex, in order. */
    private fun tls13Of(captured: String): List<Int> = captured.chunked(4).map { it.toInt(16) }.filter { it in 0x1301..0x1305 }

    /** The groups of a ClientHello's supported_groups in hex that BoringSSL has, in order: GREASE and the rest left out. */
    private fun capturedGroups(captured: String): List<Int> =
        captured.chunked(4).map { it.toInt(16) }.filter { it in groupIds.values }

    private fun groupsOf(fingerprint: AetherFingerprint): List<Int> = fingerprint.groups.split(':').map(groupIds::getValue)

    /** Whether `value` is a GREASE value (RFC 8701). */
    private fun grease(value: Int): Boolean = value and 0x0f0f == 0x0a0a && value shr 8 == value and 0xff

    /** The number of each signature algorithm by the name BoringSSL gives it, for every one it has (boring 5.3). */
    private val sigalgIds = mapOf(
        "rsa_pkcs1_sha1" to 0x0201,
        "rsa_pkcs1_sha256" to 0x0401,
        "rsa_pkcs1_sha384" to 0x0501,
        "rsa_pkcs1_sha512" to 0x0601,
        "ecdsa_sha1" to 0x0203,
        "ecdsa_secp256r1_sha256" to 0x0403,
        "ecdsa_secp384r1_sha384" to 0x0503,
        "ecdsa_secp521r1_sha512" to 0x0603,
        "rsa_pss_rsae_sha256" to 0x0804,
        "rsa_pss_rsae_sha384" to 0x0805,
        "rsa_pss_rsae_sha512" to 0x0806,
        "ed25519" to 0x0807,
        "mldsa44" to 0x0904,
        "mldsa65" to 0x0905,
        "mldsa87" to 0x0906,
    )

    /** The signature algorithms of a ClientHello's signature_algorithms in hex that BoringSSL has, in order: GREASE and the rest left out. */
    private fun capturedSigalgs(captured: String): List<Int> =
        captured.chunked(4).map { it.toInt(16) }.filter { it in sigalgIds.values }

    private fun sigalgsOf(fingerprint: AetherFingerprint): List<Int> = fingerprint.sigalgs.split(':').map(sigalgIds::getValue)

    /** The number of each certificate compression algorithm (RFC 8879) by its name. */
    private val certCompressionIds = mapOf("zlib" to 1, "brotli" to 2, "zstd" to 3)

    /** The algorithms of a ClientHello's compress_certificate in hex, after the byte of their length. */
    private fun capturedCompression(captured: String): List<Int> = captured.drop(2).chunked(4).map { it.toInt(16) }

    private fun compressionOf(fingerprint: AetherFingerprint): List<Int> =
        fingerprint.certCompression!!.split(':').map(certCompressionIds::getValue)

    /** Trust anchor IDs in dotted decimal as trust_anchors carries them, in hex: each ID's arcs in base 128, after its length. */
    private fun trustAnchorsHex(ids: String): String = ids.split(':').joinToString("") { id ->
        val bytes = id.split('.').flatMap { arc ->
            var value = arc.toLong()
            val base128 = mutableListOf((value and 0x7f).toInt())
            value = value shr 7
            while (value > 0) {
                base128.add(0x80 or (value and 0x7f).toInt())
                value = value shr 7
            }
            base128.reversed()
        }
        "%02x".format(bytes.size) + bytes.joinToString("") { "%02x".format(it) }
    }

    @Test
    fun eachFingerprintOffersTheTls12SuitesOfItsCapturedClientHello() {
        // The ClientHellos captured with Wireshark. Chrome's, eaea130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035,
        // comes from Chrome's own rule, which BoringSSL orders by the phone's AES instructions as it does the TLS 1.3
        // suites: these twelve with them, ChaCha20 first without (both seen on boring 5.2.0). So Chrome names its rule,
        // as Chromium sets it, and keeps GREASE.
        assertEquals("ALL:!aPSK:!ECDSA+SHA1:!3DES", AetherFingerprint.CHROME.ciphers)
        // Chrome 120's, baba130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035, comes from the same rule: the same suites in
        // the same order.
        assertEquals(AetherFingerprint.CHROME.ciphers, AetherFingerprint.CHROME_120.ciphers)
        assertEquals(tls12Of("eaea130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035"), tls12Of("baba130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035"))
        assertEquals(tls12Of("130113031302c02bc02fcca9cca8c02cc030c013c014009c009d002f0035"), suitesOf(AetherFingerprint.FIREFOX))
        // Python's first ten, with c00a and c014 (AES-256-CBC with SHA-1) in place of c024 and c028 (with SHA-384),
        // which BoringSSL does not have; its four DHE suites after them are left out.
        val nearest = mapOf(0xc024 to 0xc00a, 0xc028 to 0xc014)
        assertEquals(
            tls12Of("130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b0067").take(10).map { nearest[it] ?: it },
            suitesOf(AetherFingerprint.SEMI_PYTHON)
        )
        // Go lists its TLS 1.3 suites last, which BoringSSL cannot do; its TLS 1.2 suites are all there.
        assertEquals(tls12Of("c02bc02fc02cc030cca9cca8c009c013c00ac014130113021303"), suitesOf(AetherFingerprint.GO))
    }

    @Test
    fun eachFingerprintOffersTheGroupsOfItsCapturedClientHelloThatBoringSslHas() {
        // The supported_groups of the ClientHellos captured in October 2026. Chrome's and Chrome 120's lead with a GREASE
        // value, and Chrome 120's has no post-quantum group; Python's
        // also lists X448, ffdhe2048 and ffdhe3072, and Go's SecP256r1MLKEM768 and SecP384r1MLKEM1024, none of which
        // BoringSSL has.
        assertEquals(capturedGroups("5a5a11ec001d00170018"), groupsOf(AetherFingerprint.CHROME))
        assertEquals(capturedGroups("5a5a001d00170018"), groupsOf(AetherFingerprint.CHROME_120))
        assertEquals(capturedGroups("11ec001d001700180019"), groupsOf(AetherFingerprint.FIREFOX))
        assertEquals(capturedGroups("11ec001d0017001e0018001901000101"), groupsOf(AetherFingerprint.SEMI_PYTHON))
        assertEquals(capturedGroups("11ec11eb11ed001d001700180019"), groupsOf(AetherFingerprint.GO))
    }

    @Test
    fun eachFingerprintOffersTheTls13OrderAndTheKeySharesOfItsCapturedClientHello() {
        // Firefox and Python list their TLS 1.3 suites in an order of their own, which their fingerprints name.
        fun named(list: String?) = list!!.split(':').map(tls13Ids::getValue)
        assertEquals(tls13Of("130113031302c02bc02fcca9cca8c02cc030c013c014009c009d002f0035"), named(AetherFingerprint.FIREFOX.tls13Ciphers))
        assertEquals(
            tls13Of("130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b0067"),
            named(AetherFingerprint.SEMI_PYTHON.tls13Ciphers)
        )
        // Chrome's and Go's are BoringSSL's own order, by the machine's AES instructions, as their captures on a PC
        // with them show; a fixed list would keep AES-GCM first where they go ChaCha20 first.
        assertEquals(listOf(0x1301, 0x1302, 0x1303), tls13Of("eaea130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035"))
        assertEquals(listOf(0x1301, 0x1302, 0x1303), tls13Of("c02bc02fc02cc030cca9cca8c009c013c00ac014130113021303"))
        assertEquals(listOf(0x1301, 0x1302, 0x1303), tls13Of("baba130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035"))
        assertNull(AetherFingerprint.CHROME.tls13Ciphers)
        assertNull(AetherFingerprint.CHROME_120.tls13Ciphers)
        assertNull(AetherFingerprint.GO.tls13Ciphers)

        // Firefox's key_share carries X25519MLKEM768, X25519 and P-256; the others carry the two BoringSSL sends, the
        // first group and the first that is not post-quantum.
        assertEquals(listOf(0x11ec, 0x001d, 0x0017), AetherFingerprint.FIREFOX.keyShares!!.split(':').map(groupIds::getValue))
        for (fingerprint in listOf(AetherFingerprint.CHROME, AetherFingerprint.CHROME_120, AetherFingerprint.SEMI_PYTHON, AetherFingerprint.GO)) {
            assertNull(fingerprint.keyShares, fingerprint.type)
        }
    }

    @Test
    fun eachFingerprintOffersTheSignatureAlgorithmsOfItsCapturedClientHelloThatBoringSslHas() {
        // The signature_algorithms of the ClientHellos captured in October 2026. Chrome's leads with a GREASE value,
        // which greaseSigalgs gives, then ML-DSA; Python's also lists Ed448, the brainpool curves, RSA-PSS with PSS keys,
        // SHA-224 and DSA, none of which BoringSSL has.
        val captured = mapOf(
            AetherFingerprint.CHROME to "2a2a09040905090604030804040105030805050108060601",
            AetherFingerprint.CHROME_120 to "04030804040105030805050108060601",
            AetherFingerprint.FIREFOX to "04030503060308040805080604010501060102030201",
            AetherFingerprint.SEMI_PYTHON to
                "09050906090404030503060308070808081a081b081c0809080a080b080408050806040105010601030303010302040205020602",
            AetherFingerprint.GO to "0904090509060804040308070805080604010501060105030603",
        )
        assertEquals(AetherFingerprint.entries.toSet(), captured.keys)
        for ((fingerprint, hex) in captured) {
            assertEquals(capturedSigalgs(hex), sigalgsOf(fingerprint), fingerprint.type)
            assertEquals(grease(hex.take(4).toInt(16)), fingerprint.greaseSigalgs, fingerprint.type)
        }
        // Only Python's list loses algorithms to BoringSSL: the others keep every one of theirs, GREASE aside.
        for (fingerprint in AetherFingerprint.entries - AetherFingerprint.SEMI_PYTHON) {
            val all = captured.getValue(fingerprint).chunked(4).map { it.toInt(16) }.filterNot(::grease)
            assertEquals(all, sigalgsOf(fingerprint), fingerprint.type)
        }
    }

    @Test
    fun eachFingerprintSendsTheExtensionsOfItsCapturedClientHelloThatBoringSslCanSend() {
        // The types of the extensions of the ClientHellos captured in October 2026, in their order.
        val captured = mapOf(
            AetherFingerprint.CHROME to "aaaa0000000aca34002d001700330005000b0012000dfe0d12e0002bff0144cd00230010001bcaca",
            AetherFingerprint.CHROME_120 to "eaea00230010002b0000000b000a000dfe0d001b00124469ff010017002d003300053a3a",
            AetherFingerprint.FIREFOX to "00000017ff01000a000b00100005002200120033002b000d001c001bfe0d",
            AetherFingerprint.SEMI_PYTHON to "ff010000000b000a0023001000160017000d002b002d0033",
            AetherFingerprint.GO to "0000000bff01001700120005000a000d00320010002b0033",
        )
        assertEquals(AetherFingerprint.entries.toSet(), captured.keys)
        for ((fingerprint, types) in captured) {
            val all = types.chunked(4).map { it.toInt(16) }
            val sent = all.filterNot(::grease).toSet()
            val name = fingerprint.type
            assertEquals(all.any(::grease), fingerprint.grease, name)
            assertEquals(0x0005 in sent, fingerprint.ocspStapling, name)
            assertEquals(0x0012 in sent, fingerprint.sct, name)
            assertEquals(0x0023 in sent, fingerprint.sessionTicket, name)
            assertEquals(0x001b in sent, fingerprint.certCompression != null, name)
            // An ECH where there is no key to offer is a GREASE one; Chrome's and Firefox's captures went with
            // Cloudflare's key, Chrome 120's with a GREASE one.
            assertEquals(0xfe0d in sent, fingerprint.echGrease, name)
            assertEquals(0xca34 in sent, fingerprint.trustAnchors != null, name)
            assertEquals(0x12e0 in sent, fingerprint.serverPadding != null, name)
            val alps = when {
                0x44cd in sent -> "new"
                0x4469 in sent -> "old"
                else -> null
            }
            assertEquals(alps, fingerprint.alps, name)
        }

        // What they carry: compress_certificate, trust_anchors after the two bytes of its length, server_padding.
        assertEquals(capturedCompression("020002"), compressionOf(AetherFingerprint.CHROME))
        assertEquals(capturedCompression("020002"), compressionOf(AetherFingerprint.CHROME_120))
        assertEquals(capturedCompression("06000100020003"), compressionOf(AetherFingerprint.FIREFOX))
        val trustAnchors = "00b80582df1302010582df1302060582df13020d0582df13020e0582df13020f0582df1302120582df1302130582df130214" +
            "08839a648c9b2d010708839a648c9b2d010808839a648c9b2d010908839a648c9b2d010a08839a648c9b2d010b08839a648c9b2d010c" +
            "08839a648c9b2d010d08839a648c9b2d011208839a648c9b2d011304d679090104d679090404d679090504d679090604d679090704d6" +
            "79090804d679090a04d679090b04d679090c04d679090d04d679090f"
        assertEquals(trustAnchors.drop(4), trustAnchorsHex(AetherFingerprint.CHROME.trustAnchors!!))
        assertEquals(trustAnchors.take(4).toInt(16) * 2, trustAnchors.drop(4).length)
        assertEquals("1770".toInt(16), AetherFingerprint.CHROME.serverPadding)

        // Chrome has sent its extensions in a new order on each handshake since its version 110, Chrome 120 too;
        // Firefox, Python and Go keep one order, which no capture shows alone.
        assertEquals(
            listOf(AetherFingerprint.CHROME, AetherFingerprint.CHROME_120),
            AetherFingerprint.entries.filter { it.permuteExtensions }
        )
    }

    @Test
    fun theKeysPageGivesTheCoreEveryOptionOfTheFingerprint() {
        for (fingerprint in AetherFingerprint.entries) {
            val arguments = AetherKeys.arguments(AetherKeysSettings(fingerprint = fingerprint))
            val name = fingerprint.type
            assertEquals(fingerprint.ciphers, valueAfter(arguments, "--tls-ciphers"), name)
            assertEquals(fingerprint.tls13Ciphers, valueAfter(arguments, "--tls13-ciphers"), name)
            assertEquals(fingerprint.groups, valueAfter(arguments, "--tls-groups"), name)
            assertEquals(fingerprint.keyShares, valueAfter(arguments, "--tls-key-shares"), name)
            assertEquals(fingerprint.sigalgs, valueAfter(arguments, "--tls-sigalgs"), name)
            assertEquals(fingerprint.certCompression, valueAfter(arguments, "--tls-cert-compression"), name)
            assertEquals(fingerprint.alps, valueAfter(arguments, "--tls-alps"), name)
            assertEquals(fingerprint.trustAnchors, valueAfter(arguments, "--tls-trust-anchors"), name)
            assertEquals(fingerprint.serverPadding?.toString(), valueAfter(arguments, "--tls-server-padding"), name)
            assertEquals(!fingerprint.grease, "--disable-grease" in arguments, name)
            assertEquals(fingerprint.greaseSigalgs, "--enable-grease-sigalgs" in arguments, name)
            assertEquals(fingerprint.echGrease, "--enable-ech-grease" in arguments, name)
            assertEquals(!fingerprint.ocspStapling, "--disable-ocsp-stapling" in arguments, name)
            assertEquals(!fingerprint.sct, "--disable-sct" in arguments, name)
            assertEquals(!fingerprint.sessionTicket, "--disable-session-ticket" in arguments, name)
            assertEquals(!fingerprint.permuteExtensions, "--disable-extension-permutation" in arguments, name)
        }
    }

    @Test
    fun eachCipherSuitesPresetOffersTheTls12SuitesOfTheAetherFingerprintOfTheSameClient() {
        // The lists the cipherSuites field of the other protocols offers, as the app's resources give them.
        val presets = AppResources.stringArray("cipher_suites_preset_names")
            .zip(AppResources.stringArray("cipher_suites_preset_values")).toMap()
        fun presetSuites(name: String) = presets.getValue(name).split(':').map(xraySuiteIds::getValue)
        assertEquals(suitesOf(AetherFingerprint.FIREFOX), presetSuites("real-firefox-cipherSuites"))
        assertEquals(tls12Of("130113031302c02bc02fcca9cca8c02cc030c013c014009c009d002f0035"), presetSuites("real-firefox-cipherSuites"))
        assertEquals(suitesOf(AetherFingerprint.SEMI_PYTHON), presetSuites("semi-python-cipherSuites"))
    }

    @Test
    fun onlyChromeSendsGrease() {
        assertTrue(AetherFingerprint.CHROME.grease)
        assertTrue(AetherFingerprint.CHROME_120.grease)
        assertFalse(AetherFingerprint.FIREFOX.grease)
        assertFalse(AetherFingerprint.SEMI_PYTHON.grease)
        assertFalse(AetherFingerprint.GO.grease)
        // Chrome of today alone sends one among its signature algorithms as well; Chrome 120 did not.
        assertEquals(listOf(AetherFingerprint.CHROME), AetherFingerprint.entries.filter { it.greaseSigalgs })
    }

    @Test
    fun eachFingerprintNamesItsSuitesItsGroupsAndItsSignatureAlgorithms() {
        // Each is named, so that the core's defaults cannot change it. What the core sends unless told otherwise (GREASE,
        // OCSP, signed certificate timestamps, the session ticket, a new order of the extensions on each handshake) a
        // fingerprint without it turns off; what the core leaves out unless told otherwise, a fingerprint with it turns
        // on. The TLS 1.3 order and the key shares are named where they are not BoringSSL's.
        val groups = "X25519MLKEM768:X25519:P-256:P-384:P-521"
        val chromeEight = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:" +
            "rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512"
        assertEquals(
            listOf(
                "--tls-ciphers", "ALL:!aPSK:!ECDSA+SHA1:!3DES",
                "--tls-groups", "X25519MLKEM768:X25519:P-256:P-384",
                "--tls-sigalgs", "mldsa44:mldsa65:mldsa87:$chromeEight",
                "--tls-cert-compression", "brotli",
                "--tls-alps", "new",
                "--tls-trust-anchors", AetherFingerprint.CHROME.trustAnchors,
                "--tls-server-padding", "6000",
                "--enable-grease-sigalgs",
                "--enable-ech-grease",
            ),
            AetherFingerprint.CHROME.arguments,
        )
        assertEquals(
            listOf(
                "--tls-ciphers", "ALL:!aPSK:!ECDSA+SHA1:!3DES",
                "--tls-groups", "X25519:P-256:P-384",
                "--tls-sigalgs", chromeEight,
                "--tls-cert-compression", "brotli",
                "--tls-alps", "old",
                "--enable-ech-grease",
            ),
            AetherFingerprint.CHROME_120.arguments,
        )
        assertEquals(
            listOf(
                "--tls-ciphers", AetherFingerprint.FIREFOX.ciphers,
                "--tls13-ciphers", "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
                "--tls-groups", groups,
                "--tls-key-shares", "X25519MLKEM768:X25519:P-256",
                "--tls-sigalgs", "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:rsa_pss_rsae_sha256:" +
                    "rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512:ecdsa_sha1:" +
                    "rsa_pkcs1_sha1",
                "--tls-cert-compression", "zlib:brotli:zstd",
                "--disable-grease",
                "--enable-ech-grease",
                "--disable-session-ticket",
                "--disable-extension-permutation",
            ),
            AetherFingerprint.FIREFOX.arguments,
        )
        assertEquals(
            listOf(
                "--tls-ciphers", AetherFingerprint.SEMI_PYTHON.ciphers,
                "--tls13-ciphers", "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256",
                "--tls-groups", groups,
                "--tls-sigalgs", "mldsa65:mldsa87:mldsa44:ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:" +
                    "ecdsa_secp521r1_sha512:ed25519:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:" +
                    "rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512",
                "--disable-grease",
                "--disable-ocsp-stapling",
                "--disable-sct",
                "--disable-extension-permutation",
            ),
            AetherFingerprint.SEMI_PYTHON.arguments,
        )
        assertEquals(
            listOf(
                "--tls-ciphers", AetherFingerprint.GO.ciphers,
                "--tls-groups", groups,
                "--tls-sigalgs", "mldsa44:mldsa65:mldsa87:rsa_pss_rsae_sha256:ecdsa_secp256r1_sha256:ed25519:" +
                    "rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512:" +
                    "ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512",
                "--disable-grease",
                "--disable-session-ticket",
                "--disable-extension-permutation",
            ),
            AetherFingerprint.GO.arguments,
        )
    }

    @Test
    fun theFingerprintListNamesEveryFingerprintInItsOrder() {
        // The dropdowns of the Aether editor and of the WARP keys page, read from the app's resources as the unit tests
        // run in the module's folder.
        assertEquals(AetherFingerprint.entries.map { it.type }, AppResources.stringArray("aether_fingerprint_values"))
        assertEquals(listOf("Chrome", "Chrome 120", "Firefox", "Semi-Python", "Go"), AppResources.stringArray("aether_fingerprint_entries"))
        assertEquals(AetherFingerprint.SEMI_PYTHON, AetherFingerprint.fromString("semi-python"))
    }

    @Test
    fun theDefaultsGetEveryKeyTheWayTheCoreCallsTheApiWithChromesRule() {
        // No address, server name or host: the core's own, api.devices.cloudflare.com, then api.cloudflareclient.com
        // when that one does not serve the call.
        assertEquals(
            listOf("--register", "all") + AetherFingerprint.CHROME.arguments,
            AetherKeys.arguments(AetherKeysSettings())
        )
        assertEquals(
            "aether --register all --tls-ciphers ALL:!aPSK:!ECDSA+SHA1:!3DES --tls-groups X25519MLKEM768:X25519:P-256:P-384 " +
                "--tls-sigalgs ${AetherFingerprint.CHROME.sigalgs} --tls-cert-compression brotli --tls-alps new " +
                "--tls-trust-anchors ${AetherFingerprint.CHROME.trustAnchors} --tls-server-padding 6000 " +
                "--enable-grease-sigalgs --enable-ech-grease",
            AetherKeys.builtCommand(AetherKeysSettings())
        )
        // A plain exit-node.
        assertEquals(AetherExit(), AetherKeysSettings().exit)
    }

    @Test
    fun aKindStoredBeforeWireGuardOverMasqueKeepsItsKeys() {
        // The page stored the type of the protocol; WARP-in-WARP's keys are still both WireGuard hops' ones.
        assertEquals(AetherKeyKind.GOOL, AetherKeyKind.fromString("gool"))
        assertEquals("gool-classic", AetherKeyKind.GOOL.register)
        assertEquals(AetherKeyKind.WG_OVER_MASQUE, AetherKeyKind.fromString("wg-over-masque"))
        assertEquals(AetherKeyKind.ALL, AetherKeyKind.fromString(null))
    }

    @Test
    fun eachKindRegistersItsKeysAndReadsBack() {
        for (kind in AetherKeyKind.entries) {
            val arguments = AetherKeys.arguments(AetherKeysSettings(kind = kind))
            assertEquals(listOf("--register", kind.register), arguments.take(2))
            assertEquals(kind, AetherKeys.kindOf(arguments))
        }
    }

    @Test
    fun theKindIsReadAsTheCoreReadsIt() {
        assertEquals(AetherKeyKind.WIREGUARD, AetherKeys.kindOf(listOf("--register", "WireGuard")))
        assertEquals(AetherKeyKind.WIREGUARD, AetherKeys.kindOf(listOf("--register", "warp")))
        assertEquals(AetherKeyKind.GOOL, AetherKeys.kindOf(listOf("--register", "warp-in-warp")))
        assertEquals(AetherKeyKind.GOOL, AetherKeys.kindOf(listOf("--register", " wiw ")))
        assertEquals(AetherKeyKind.GOOL, AetherKeys.kindOf(listOf("--register", "gool-classic")))
        // gool is what the core's --gool runs, WireGuard over MASQUE.
        assertEquals(AetherKeyKind.WG_OVER_MASQUE, AetherKeys.kindOf(listOf("--register", "gool")))
        assertEquals(AetherKeyKind.WG_OVER_MASQUE, AetherKeys.kindOf(listOf("--register", "WG-over-MASQUE")))
        assertEquals(AetherKeyKind.MIM, AetherKeys.kindOf(listOf("--register", "masque-in-masque")))
        // The last one counts.
        assertEquals(AetherKeyKind.MASQUE, AetherKeys.kindOf(listOf("--register", "all", "--register", "masque")))
        assertNull(AetherKeys.kindOf(listOf("--register", "everything")))
        assertNull(AetherKeys.kindOf(listOf("--register")))
        assertNull(AetherKeys.kindOf(listOf("--protocol", "wg")))
    }

    @Test
    fun echAsksForTheKeyWhereTheSettingsSayAndKeepsTheDefaultsForBlanks() {
        val ech = AetherKeys.arguments(AetherKeysSettings(ech = true, echDns = "https://1.1.1.1/dns-query", echDomain = " example.com "))
        assertEquals("auto", valueAfter(ech, "--ech"))
        assertEquals("https://1.1.1.1/dns-query", valueAfter(ech, "--ech-dns"))
        assertEquals("example.com", valueAfter(ech, "--ech-domain"))

        val defaults = AetherKeys.arguments(AetherKeysSettings(ech = true, echDns = " ", echDomain = ""))
        assertEquals("udp://1.1.1.1", valueAfter(defaults, "--ech-dns"))
        assertEquals("cloudflare-ech.com", valueAfter(defaults, "--ech-domain"))

        // Off, nothing about ECH goes along, whatever the fields hold.
        assertFalse(AetherKeys.arguments(AetherKeysSettings(echDns = "tcp://8.8.8.8")).any { it.startsWith("--ech") })
    }

    @Test
    fun aBlankApiAddressLeavesTheCoresOwn() {
        assertFalse("--api-address" in AetherKeys.arguments(AetherKeysSettings(enrollAddress = "  ")))
        assertEquals("188.114.97.6:443", valueAfter(AetherKeys.arguments(AetherKeysSettings(enrollAddress = " 188.114.97.6:443 ")), "--api-address"))
    }

    @Test
    fun theApiFieldsOfferTheTwoNamesOfTheApiAndStartBlank() {
        // The dropdowns of the API address, server name and host, read from the app's resources: the name the core goes
        // by first, then the other one.
        assertEquals(listOf("api.devices.cloudflare.com", "api.cloudflareclient.com"), AppResources.stringArray("aether_api_name_options"))
        // None of them is chosen until one is picked or written: blank is the core's own.
        val defaults = AetherKeysSettings()
        assertEquals(listOf("", "", ""), listOf(defaults.enrollAddress, defaults.apiSni, defaults.apiHost))
        // Each name picked goes to the core as it is.
        for (name in AppResources.stringArray("aether_api_name_options")) {
            val picked = AetherKeysSettings(enrollAddress = name, apiSni = name, apiHost = name)
            assertNull(AetherKeys.problem(picked), name)
            val arguments = AetherKeys.arguments(picked)
            assertEquals(listOf(name, name, name), listOf("--api-address", "--api-sni", "--api-host").map { valueAfter(arguments, it) })
        }
    }

    @Test
    fun theApiServerNameAndHostGoTrimmedAndBlankLeavesTheCoresOwn() {
        val blank = AetherKeys.arguments(AetherKeysSettings(apiSni = " ", apiHost = ""))
        assertFalse("--api-sni" in blank)
        assertFalse("--api-host" in blank)
        val given = AetherKeys.arguments(
            AetherKeysSettings(enrollAddress = "162.159.137.105", apiSni = " api.cloudflareclient.com ", apiHost = "api.cloudflareclient.com ")
        )
        // Each one apart, after the address, as the core takes them; the same name for both, as Cloudflare wants.
        assertEquals(
            listOf(
                "--register", "all",
                "--api-address", "162.159.137.105",
                "--api-sni", "api.cloudflareclient.com",
                "--api-host", "api.cloudflareclient.com",
            ) + AetherFingerprint.CHROME.arguments,
            given
        )
        // One alone leaves the others to the core.
        val hostOnly = AetherKeys.arguments(AetherKeysSettings(apiHost = "api.cloudflareclient.com"))
        assertEquals("api.cloudflareclient.com", valueAfter(hostOnly, "--api-host"))
        assertFalse("--api-sni" in hostOnly)
        assertFalse("--api-address" in hostOnly)
    }

    @Test
    fun theRequestAddressIsWhatTheCoreTakes() {
        for (address in listOf(
            "api.cloudflareclient.com", "api.cloudflareclient.com:443", "api.cloudflareclient.com.", "188.114.97.6",
            "188.114.97.6:2053", "2606:4700::1", "[2606:4700::1]", "[2606:4700::1]:8443", "[188.114.97.6]:443",
        )) {
            assertTrue(AetherKeys.isEnrollAddress(address), address)
        }
        for (address in listOf(
            "", "-x", "--upstream", "a b", "188.114.97.6:0", "188.114.97.6:65536", "188.114.97.6:", ":443",
            "188.114.97.6:4a3", "2606:4700::1:", "[2606:4700::1", "[2606:4700::1]:", "https://api.cloudflareclient.com",
            "api.-cloudflareclient.com",
            // An IPv6 address takes brackets before a port.
            "1:2:3:4:5:6:7:8:443",
        )) {
            assertFalse(AetherKeys.isEnrollAddress(address), address)
        }
    }

    @Test
    fun eachProblemIsFoundAndNothingElse() {
        val fine = AetherKeysSettings()
        assertNull(AetherKeys.problem(fine))
        assertEquals(AetherKeys.Problem.INVALID_ENROLL_ADDRESS, AetherKeys.problem(fine.copy(enrollAddress = "-x")))
        assertNull(AetherKeys.problem(fine.copy(enrollAddress = "")))
        // The server name and the host are domain names, as the core takes them, though no label starts or ends with
        // '-', which the core would take, so that no value reads as an option; blank, the core's own.
        for (name in listOf("", "  ", "api.devices.cloudflare.com", " api.cloudflareclient.com. ")) {
            assertNull(AetherKeys.problem(fine.copy(apiSni = name)), name)
            assertNull(AetherKeys.problem(fine.copy(apiHost = name)), name)
        }
        for (name in listOf("162.159.137.105", "2606:4700:7::a29f:8969", "https://api.devices.cloudflare.com", "api.devices.cloudflare.com:443", "-x", "a b")) {
            assertEquals(AetherKeys.Problem.INVALID_API_SNI, AetherKeys.problem(fine.copy(apiSni = name)), name)
            assertEquals(AetherKeys.Problem.INVALID_API_HOST, AetherKeys.problem(fine.copy(apiHost = name)), name)
        }
        // The ECH fields count while ECH is on.
        assertNull(AetherKeys.problem(fine.copy(echDns = "dns.google")))
        assertEquals(AetherKeys.Problem.INVALID_ECH_DNS, AetherKeys.problem(fine.copy(ech = true, echDns = "dns.google")))
        assertEquals(AetherKeys.Problem.INVALID_ECH_DOMAIN, AetherKeys.problem(fine.copy(ech = true, echDomain = "-x")))
        assertNull(AetherKeys.problem(fine.copy(ech = true, echDns = "", echDomain = "")))
        assertEquals(AetherKeys.Problem.INVALID_FINAL_MASK, AetherKeys.problem(fine.copy(finalMask = "{not json")))
        assertNull(AetherKeys.problem(fine.copy(finalMask = """{"tcp": []}""", dialMode = "anything")))
    }

    @Test
    fun aCommandWrittenByHandRunsAsWritten() {
        val settings = AetherKeysSettings(enrollAddress = "-x", command = "aether --register wg --tor-reverse")
        assertTrue(AetherKeys.isCustom(settings))
        assertEquals(listOf("--register", "wg", "--tor-reverse"), AetherKeys.runArguments(settings))
        // The settings it replaces do not count; what it registers does, and so does the exit-node it dials out through.
        assertNull(AetherKeys.problem(settings))
        assertEquals(AetherKeys.Problem.INVALID_COMMAND, AetherKeys.problem(settings.copy(command = "aether --protocol wg")))
        assertEquals(AetherKeys.Problem.INVALID_COMMAND, AetherKeys.problem(settings.copy(command = "--register every")))
        assertEquals(AetherKeys.Problem.INVALID_FINAL_MASK, AetherKeys.problem(settings.copy(finalMask = "[")))

        // The command the settings give, or none, is no command of its own.
        val built = AetherKeysSettings(kind = AetherKeyKind.MIM)
        assertFalse(AetherKeys.isCustom(built.copy(command = " " + AetherKeys.builtCommand(built) + " ")))
        assertFalse(AetherKeys.isCustom(built.copy(command = "")))
        assertEquals(AetherKeys.arguments(built), AetherKeys.runArguments(built.copy(command = AetherKeys.builtCommand(built))))
    }

    @Test
    fun anExitNodeTakesABlankFinalMaskOrAJsonObject() {
        assertTrue(AetherExit.takesFinalMask(null))
        assertTrue(AetherExit.takesFinalMask(" "))
        assertTrue(AetherExit.takesFinalMask("""{"tcp": []}"""))
        assertFalse(AetherExit.takesFinalMask("[]"))
        assertFalse(AetherExit.takesFinalMask("{not json"))
        assertFalse(AetherExit.takesFinalMask("ForceIP"))
    }

    @Test
    fun theFragmentSendsTheClientHelloOfTheApiInPiecesShapedAsSet() {
        val on = AetherKeysSettings(fragment = true)
        assertEquals(
            listOf("--register", "all", "--fragment") + AetherFingerprint.CHROME.arguments,
            AetherKeys.arguments(on)
        )
        val shaped = AetherKeys.arguments(on.copy(fragmentSize = " 16 - 8 ", fragmentDelay = "5"))
        assertEquals("8-16", valueAfter(shaped, "--fragment-size"))
        assertEquals("5", valueAfter(shaped, "--fragment-delay"))
        // Off, the sizes are kept, but nothing of them reaches the core, and no flag says off: the core takes none.
        val off = AetherKeys.arguments(on.copy(fragment = false, fragmentSize = "8", fragmentDelay = "5"))
        assertFalse("--fragment" in off)
        assertFalse("--no-fragment" in off)
        assertFalse("--fragment-size" in off)
        assertFalse("--fragment-delay" in off)
        // A size or a delay that is no number or range stops the run, only while fragmenting is on.
        assertEquals(AetherKeys.Problem.INVALID_FRAGMENT, AetherKeys.problem(on.copy(fragmentSize = "0")))
        assertEquals(AetherKeys.Problem.INVALID_FRAGMENT, AetherKeys.problem(on.copy(fragmentDelay = "x")))
        assertNull(AetherKeys.problem(on.copy(fragmentSize = "8-16", fragmentDelay = "2-10")))
        assertNull(AetherKeys.problem(on.copy(fragment = false, fragmentSize = "0")))
    }

    @Test
    fun aProfileAsTheExitNodeLeavesTheFinalMaskAndTheDialModeOutOfUse() {
        val noded = AetherKeysSettings(exitNode = "germany", finalMask = """{"tcp": []}""", dialMode = "ForceIP")
        assertEquals(AetherExit(node = "germany"), noded.exit)
        assertEquals(AetherExit(node = "germany"), noded.copy(exitNode = " germany ").exit)
        assertNull(AetherKeys.problem(noded))
        // A broken finalMask is refused all the same, as the Aether page refuses it: none is kept for freedom.
        assertEquals(AetherKeys.Problem.INVALID_FINAL_MASK, AetherKeys.problem(noded.copy(finalMask = "{not json")))
        assertEquals(AetherKeys.Problem.INVALID_FINAL_MASK, AetherKeys.problem(noded.copy(exitNode = "", finalMask = "{not json")))
        assertEquals(AetherExit(dialMode = "ForceIP"), noded.copy(exitNode = " ", finalMask = "").exit)
        // The exit-node is Xray's, so the command of the run stays as it was.
        assertEquals(AetherKeys.arguments(AetherKeysSettings()), AetherKeys.arguments(AetherKeysSettings(exitNode = "germany")))
    }

    @Test
    fun theExitNodeTakesTheFinalMaskAndTheDialMode() {
        val settings = AetherKeysSettings(finalMask = """{"tcp": []}""", dialMode = "ForceIP")
        assertEquals(AetherExit("""{"tcp": []}""", "ForceIP"), settings.exit)
        assertEquals(AetherExit(), settings.copy(finalMask = " ", dialMode = "").exit)
    }
}
