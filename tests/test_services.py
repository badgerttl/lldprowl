import asyncio
import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from scapy.all import Dot1Q, Ether, LLC, SNAP
from scapy.contrib.cdp import (
    CDPAddrRecordIPv4,
    CDPMsgCapabilities,
    CDPMsgDeviceID,
    CDPMsgMgmtAddr,
    CDPMsgNativeVLAN,
    CDPMsgPlatform,
    CDPMsgPortID,
    CDPMsgSoftwareVersion,
    CDPv2_HDR,
)
from scapy.contrib.lldp import (
    LLDPDUChassisID,
    LLDPDUEndOfLLDPDU,
    LLDPDUGenericOrganisationSpecific,
    LLDPDUPortDescription,
    LLDPDUPortID,
    LLDPDUSystemCapabilities,
    LLDPDUSystemDescription,
    LLDPDUSystemName,
    LLDPDUTimeToLive,
)

import config
import interface_state
import lldp_service
import log_store
import ping_service


class ConfigTests(unittest.TestCase):
    def test_config_round_trip_is_atomic_and_preserves_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            config_dir = Path(directory)
            with (
                patch.object(config, "CONFIG_DIR", config_dir),
                patch.object(config, "CONFIG_PATH", config_dir / "config.json"),
            ):
                config.save_config({"interface": "eth0", "ping_targets": ["1.1.1.1"]})
                self.assertEqual(config.get_interface(), "eth0")
                self.assertEqual(config.get_ping_targets(), ["1.1.1.1"])
                parsed = json.loads((config_dir / "config.json").read_text())
                self.assertEqual(parsed["interface"], "eth0")

    def test_invalid_or_missing_interface_is_unselected(self):
        with tempfile.TemporaryDirectory() as directory:
            config_dir = Path(directory)
            with (
                patch.object(config, "CONFIG_DIR", config_dir),
                patch.object(config, "CONFIG_PATH", config_dir / "config.json"),
            ):
                self.assertEqual(config.get_interface(), "")
                config.save_config({"interface": "../../bad", "ping_targets": []})
                self.assertEqual(config.get_interface(), "")

    def test_platform_interface_names_allow_spaces_but_not_paths(self):
        self.assertTrue(config.is_valid_interface_name("Ethernet 2"))
        self.assertTrue(config.is_valid_interface_name("Wi-Fi"))
        self.assertFalse(config.is_valid_interface_name("../eth0"))
        self.assertFalse(config.is_valid_interface_name("bad/name"))


class PingTests(unittest.IsolatedAsyncioTestCase):
    def test_ping_target_validation_rejects_options_and_bad_addresses(self):
        self.assertTrue(ping_service._valid_ip("192.168.1.1"))
        self.assertTrue(ping_service._valid_ip("switch-1.example"))
        self.assertFalse(ping_service._valid_ip("999.1.1.1"))
        self.assertFalse(ping_service._valid_ip("-f"))
        self.assertFalse(ping_service._valid_ip("host name"))

    def test_platform_specific_arguments(self):
        with patch.object(ping_service.sys, "platform", "linux"):
            self.assertEqual(
                ping_service._ping_args("1.1.1.1", "eth0"),
                ["ping", "-c", "1", "-W", "2", "-I", "eth0", "1.1.1.1"],
            )
        with patch.object(ping_service.sys, "platform", "darwin"):
            self.assertEqual(
                ping_service._ping_args("1.1.1.1", "en0"),
                ["ping", "-c", "1", "-W", "2000", "-b", "en0", "1.1.1.1"],
            )
        with patch.object(ping_service.sys, "platform", "win32"):
            self.assertEqual(
                ping_service._ping_args("1.1.1.1", "Ethernet"),
                ["ping", "-n", "1", "-w", "2000", "1.1.1.1"],
            )

    async def test_missing_ping_binary_is_a_failed_check_not_an_exception(self):
        with patch(
            "asyncio.create_subprocess_exec",
            new=AsyncMock(side_effect=FileNotFoundError),
        ):
            self.assertFalse(await ping_service._ping_one("127.0.0.1"))

    async def test_ping_targets_are_checked(self):
        with (
            patch.object(config, "get_ping_targets", return_value=["a", "b"]),
            patch.object(config, "get_interface", return_value="eth0"),
            patch.object(ping_service, "_ping_one", new=AsyncMock(return_value=True)),
        ):
            results = await ping_service.run_ping()
        self.assertEqual(set(results), {"a", "b"})
        self.assertTrue(all(item["success"] for item in results.values()))

    async def test_concurrent_ping_requests_share_one_batch(self):
        started = asyncio.Event()
        release = asyncio.Event()

        async def delayed_ping(_target, _interface):
            started.set()
            await release.wait()
            return True

        with (
            patch.object(config, "get_ping_targets", return_value=["a", "b"]),
            patch.object(config, "get_interface", return_value="eth0"),
            patch.object(
                ping_service, "_ping_one", new=AsyncMock(side_effect=delayed_ping)
            ) as ping_mock,
        ):
            first = asyncio.create_task(ping_service.run_ping())
            await started.wait()
            second = asyncio.create_task(ping_service.run_ping())
            release.set()
            first_result, second_result = await asyncio.gather(first, second)
        self.assertEqual(first_result, second_result)
        self.assertEqual(ping_mock.await_count, 2)


class InterfaceHelpersTests(unittest.TestCase):
    def test_network_calculations(self):
        self.assertEqual(interface_state._prefix_to_netmask(24), "255.255.255.0")
        self.assertEqual(
            interface_state._network_address("192.168.4.22", "255.255.255.0"),
            "192.168.4.0",
        )


class LogStoreTests(unittest.TestCase):
    def test_snapshot_round_trip_and_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.csv"
            with (
                patch.object(log_store, "LOG_PATH", path),
                patch.object(config, "CONFIG_DIR", Path(directory)),
            ):
                log_store.append_snapshot(
                    {
                        "timestamp": "2026-01-01 00:00:00",
                        "protocol": "LLDP",
                        "system_name": "switch-1",
                        "vlan_name": "Users",
                        "observed_vlan_tags": "42, 200",
                        "ping_results": "1.1.1.1:pass, gateway:fail",
                        "notes": "rack A",
                    }
                )
                rows, total = log_store.read_log_page()
                self.assertEqual(total, 1)
                self.assertEqual(rows[0]["system_name"], "switch-1")
                self.assertEqual(rows[0]["vlan_name"], "Users")
                self.assertEqual(rows[0]["observed_vlan_tags"], "42, 200")
                self.assertEqual(
                    rows[0]["ping_results"], "1.1.1.1:pass, gateway:fail"
                )
                self.assertEqual(rows[0]["protocol"], "LLDP")
                self.assertTrue(log_store.delete_entry_at_index(0))
                self.assertEqual(log_store.read_log_page()[1], 0)

    def test_filters_search_all_rows_and_preserve_delete_index(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.csv"
            with (
                patch.object(log_store, "LOG_PATH", path),
                patch.object(config, "CONFIG_DIR", Path(directory)),
            ):
                entries = [
                    {
                        "timestamp": "2026-01-01 00:00:00",
                        "protocol": "LLDP",
                        "system_name": "access-one",
                        "ping_results": "gateway:pass",
                    },
                    {
                        "timestamp": "2026-02-01 00:00:00",
                        "protocol": "CDP",
                        "system_name": "core-cisco",
                        "ping_results": "gateway:fail",
                        "notes": "datacenter",
                    },
                    {
                        "timestamp": "2026-03-01 00:00:00",
                        "protocol": "LLDP",
                        "system_name": "access-two",
                        "ping_results": "gateway:fail",
                    },
                ]
                for entry in entries:
                    log_store.append_snapshot(entry)
                rows, total = log_store.read_log_page(
                    query="datacenter", protocol="CDP", ping="fail"
                )
                self.assertEqual(total, 1)
                self.assertEqual(rows[0]["system_name"], "core-cisco")
                self.assertEqual(rows[0]["_source_index"], 1)
                dated, dated_total = log_store.read_log_page(
                    date_from="2026-02-01", date_to="2026-02-28"
                )
                self.assertEqual(dated_total, 1)
                self.assertEqual(dated[0]["protocol"], "CDP")

    def test_append_migrates_legacy_csv_and_infers_lldp(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.csv"
            legacy_fields = [field for field in log_store.FIELDNAMES if field != "protocol"]
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=legacy_fields)
                writer.writeheader()
                writer.writerow(
                    {
                        **{field: "" for field in legacy_fields},
                        "timestamp": "2025-01-01 00:00:00",
                        "type": "snapshot",
                        "system_name": "legacy-switch",
                    }
                )
            with (
                patch.object(log_store, "LOG_PATH", path),
                patch.object(config, "CONFIG_DIR", Path(directory)),
            ):
                log_store.append_snapshot(
                    {
                        "timestamp": "2026-01-01 00:00:00",
                        "protocol": "CDP",
                        "system_name": "new-switch",
                    }
                )
                rows, total = log_store.read_log_page()
            self.assertEqual(total, 2)
            self.assertEqual([row["protocol"] for row in rows], ["CDP", "LLDP"])
            with open(path, "r", newline="", encoding="utf-8") as f:
                self.assertEqual(next(csv.reader(f)), log_store.FIELDNAMES)

    def test_read_failures_are_reported_instead_of_looking_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.csv"
            path.write_text(",".join(log_store.FIELDNAMES) + "\n")
            with (
                patch.object(log_store, "LOG_PATH", path),
                patch("builtins.open", side_effect=PermissionError("denied")),
            ):
                log_store._invalidate_cache()
                with self.assertLogs(log_store.logger, level="ERROR"):
                    with self.assertRaises(log_store.LogReadError):
                        log_store.read_log_page()

    def test_unchanged_history_uses_the_row_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.csv"
            with (
                patch.object(log_store, "LOG_PATH", path),
                patch.object(config, "CONFIG_DIR", Path(directory)),
            ):
                log_store.append_snapshot(
                    {
                        "timestamp": "2026-01-01 00:00:00",
                        "protocol": "LLDP",
                        "system_name": "cached-switch",
                    }
                )
                log_store._invalidate_cache()
                first = log_store.read_log_page()
                with patch("builtins.open", side_effect=AssertionError("cache miss")):
                    second = log_store.read_log_page()
            self.assertEqual(first, second)


class DiscoveryParserTests(unittest.TestCase):
    def test_lldp_packet_maps_to_common_neighbor_fields(self):
        packet = (
            Ether(
                dst="01:80:c2:00:00:0e",
                src="00:11:22:33:44:55",
                type=0x88CC,
            )
            / LLDPDUChassisID(
                subtype=4, id=bytes.fromhex("001122334455")
            )
            / LLDPDUPortID(subtype=5, id=b"GigabitEthernet1/0/1")
            / LLDPDUTimeToLive(ttl=120)
            / LLDPDUSystemName(system_name=b"access-switch")
            / LLDPDUPortDescription(description=b"User port")
            / LLDPDUSystemDescription(description=b"Switch OS")
            / LLDPDUGenericOrganisationSpecific(
                org_code=lldp_service.ORG_IEEE_802_1,
                subtype=lldp_service.PORT_VLAN_ID_SUBTYPE,
                data=b"\x00\x2a",
            )
            / LLDPDUGenericOrganisationSpecific(
                org_code=lldp_service.ORG_IEEE_802_1,
                subtype=lldp_service.VLAN_NAME_SUBTYPE,
                data=b"\x00\x2a\x05Users",
            )
            / LLDPDUSystemCapabilities(
                mac_bridge_available=1,
                mac_bridge_enabled=1,
                router_available=1,
                router_enabled=1,
            )
            / LLDPDUEndOfLLDPDU()
        )
        parsed = lldp_service._parse_lldp_packet(Ether(bytes(packet)))
        self.assertEqual(parsed["protocol"], "LLDP")
        self.assertEqual(parsed["system_name"], "access-switch")
        self.assertEqual(parsed["port_id"], "GigabitEthernet1/0/1")
        self.assertEqual(parsed["switch_mac"], "00:11:22:33:44:55")
        self.assertEqual(parsed["vlan_id"], "42")
        self.assertEqual(parsed["vlan_name"], "Users")
        self.assertEqual(parsed["caps"], "Bridge, Router")

    def test_tagged_frames_are_accumulated_on_the_current_neighbor(self):
        lldp_service.clear_current()
        discovery = (
            Ether(
                dst="01:80:c2:00:00:0e",
                src="00:11:22:33:44:55",
                type=0x8100,
            )
            / Dot1Q(vlan=42, type=0x88CC)
            / LLDPDUChassisID(
                subtype=4, id=bytes.fromhex("001122334455")
            )
            / LLDPDUPortID(subtype=5, id=b"Gi1/0/1")
            / LLDPDUTimeToLive(ttl=120)
            / LLDPDUEndOfLLDPDU()
        )
        lldp_service._on_packet(Ether(bytes(discovery)))
        lldp_service._on_packet(
            Ether() / Dot1Q(vlan=200) / b"observed traffic"
        )
        current = lldp_service.get_current()
        self.assertEqual(current["observed_vlan_tags"], "42, 200")

    def test_cdp_packet_maps_to_common_neighbor_fields(self):
        packet = (
            Ether(dst="01:00:0c:cc:cc:cc", src="00:11:22:33:44:55")
            / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
            / SNAP(OUI=0x00000C, code=0x2000)
            / CDPv2_HDR(
                msg=[
                    CDPMsgDeviceID(val=b"core-cisco"),
                    CDPMsgPortID(iface=b"GigabitEthernet1/0/24"),
                    CDPMsgCapabilities(cap=0x09),
                    CDPMsgPlatform(val=b"cisco C9300"),
                    CDPMsgSoftwareVersion(val=b"IOS-XE 17.12"),
                    CDPMsgNativeVLAN(vlan=42),
                    CDPMsgMgmtAddr(
                        addr=[CDPAddrRecordIPv4(addr="10.20.30.40")]
                    ),
                ]
            )
        )
        parsed = lldp_service._parse_cdp_packet(Ether(bytes(packet)))
        self.assertEqual(parsed["protocol"], "CDP")
        self.assertEqual(parsed["system_name"], "core-cisco")
        self.assertEqual(parsed["port_id"], "GigabitEthernet1/0/24")
        self.assertEqual(parsed["management_address"], "10.20.30.40")
        self.assertEqual(parsed["vlan_id"], "42")
        self.assertEqual(parsed["switch_mac"], "00:11:22:33:44:55")
        self.assertEqual(parsed["caps"], "Router, Switch")
        self.assertIn("cisco C9300", parsed["system_description"])


class SnifferLifecycleTests(unittest.TestCase):
    def tearDown(self):
        lldp_service.stop_sniff()

    def test_sniffer_can_be_stopped_immediately_after_start(self):
        class FakeSniffer:
            def __init__(self, **kwargs):
                self.kwargs = kwargs
                self.running = False
                self.exception = None
                self.stop_calls = 0

            def start(self):
                self.running = True

            def stop(self, join=True):
                self.stop_calls += 1
                self.running = False

            def join(self, timeout=None):
                self.running = False

        with (
            patch.object(config, "get_interface", return_value="eth0"),
            patch.object(lldp_service, "AsyncSniffer", side_effect=FakeSniffer)
            as sniffer_factory,
        ):
            lldp_service.start_sniff()
            lldp_service.stop_sniff()
        self.assertFalse(lldp_service.is_sniffing())
        capture_filter = sniffer_factory.call_args.kwargs["filter"]
        self.assertIn("0x88cc", capture_filter)
        self.assertIn("01:00:0c:cc:cc:cc", capture_filter)


if __name__ == "__main__":
    unittest.main()
