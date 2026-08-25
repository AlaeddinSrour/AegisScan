"""Versioned offline OpenWrt advisory catalog sourced from official notices."""

from __future__ import annotations


CATALOG_VERSION = 2

# Release bounds are half-open: affected_from <= release < fixed_in. Entries
# intentionally require a selected firmware package; source availability alone
# is not evidence that a component is deployed.
OPENWRT_ADVISORIES: tuple[dict[str, object], ...] = (
    {
        "cve": "CVE-2019-5101",
        "packages": ("libustream-mbedtls", "libustream-openssl", "libustream-wolfssl"),
        "affected_from": "18.06.0",
        "fixed_in": "18.06.5",
        "severity": "HIGH",
        "summary": "ustream-ssl certificate parsing can disclose process memory.",
        "source": "https://openwrt.org/advisory/2019-11-05-3",
    },
    {
        "cve": "CVE-2019-5102",
        "packages": ("libustream-mbedtls", "libustream-openssl", "libustream-wolfssl"),
        "affected_from": "18.06.0",
        "fixed_in": "18.06.5",
        "severity": "HIGH",
        "summary": "ustream-ssl certificate handling can disclose process memory.",
        "source": "https://openwrt.org/advisory/2019-11-05-3",
    },
    {
        "cve": "CVE-2019-19945",
        "packages": ("uhttpd",),
        "affected_from": "18.06.0",
        "fixed_in": "18.06.6",
        "severity": "HIGH",
        "summary": "uhttpd can access invalid memory while processing crafted HTTP POST data.",
        "source": "https://openwrt.org/advisory/2020-01-13-1",
    },
    {
        "cve": "CVE-2020-7248",
        "packages": ("libubox",),
        "affected_from": "18.06.0",
        "fixed_in": "18.06.7",
        "severity": "HIGH",
        "summary": "libubox can disclose tagged binary data during JSON serialization.",
        "source": "https://openwrt.org/advisory/2020-01-31-2",
    },
    {
        "cve": "CVE-2020-8597",
        "packages": ("ppp",),
        "affected_from": "18.06.0",
        "fixed_in": "18.06.8",
        "severity": "CRITICAL",
        "summary": "PPP EAP packet processing contains a remotely reachable buffer overflow.",
        "source": "https://openwrt.org/advisory/2020-02-21-1",
    },
    {
        "cve": "CVE-2020-11752",
        "packages": ("relayd",),
        "affected_from": "18.06.0",
        "fixed_in": "18.06.9",
        "severity": "HIGH",
        "summary": "relayd can read out of bounds and potentially overflow a heap buffer.",
        "source": "https://openwrt.org/advisory/2020-05-06-2",
    },
)

# Kernel bounds come from the OpenWrt 18.06.3 security changelog. Matching is
# deliberately restricted to the exact stable series named by OpenWrt rather
# than extrapolating from generic Linux CPE ranges.
OPENWRT_KERNEL_ADVISORIES: tuple[dict[str, object], ...] = (
    {
        "cve": "CVE-2019-11477",
        "fixed_versions": {"4.9": "4.9.182", "4.14": "4.14.127"},
        "severity": "HIGH",
        "summary": (
            "A remotely supplied TCP SACK sequence can trigger an integer overflow "
            "and denial of service in the retransmission queue."
        ),
        "source": "https://openwrt.org/releases/18.06/changelog-18.06.3",
    },
    {
        "cve": "CVE-2019-11478",
        "fixed_versions": {"4.9": "4.9.182", "4.14": "4.14.127"},
        "severity": "HIGH",
        "summary": (
            "A remote peer can fragment the TCP retransmission queue and exhaust "
            "resources by sending crafted SACK sequences."
        ),
        "source": "https://openwrt.org/releases/18.06/changelog-18.06.3",
    },
    {
        "cve": "CVE-2019-11479",
        "fixed_versions": {"4.9": "4.9.182", "4.14": "4.14.127"},
        "severity": "HIGH",
        "summary": (
            "A remote peer can force excessive TCP retransmission fragmentation by "
            "advertising a very small MSS, causing denial of service."
        ),
        "source": "https://openwrt.org/releases/18.06/changelog-18.06.3",
    },
)

OPENWRT_EOL_SERIES: tuple[dict[str, str], ...] = (
    {
        "series": "18.06",
        "source": "https://openwrt.org/advisory/2022-10-17-1",
    },
)
