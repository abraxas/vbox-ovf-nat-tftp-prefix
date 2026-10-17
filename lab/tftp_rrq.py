#!/usr/bin/env python3
"""Gadget of VirtualBox 7.2.20 OVF NAT TFTP prefix leftover.

Pin: Oracle VM VirtualBox OSS 7.2.20 peel f2792cf44f663989818507e36d3db5f978523c5e.

Does not boot VirtualBox. Reimplements:

* Settings.cpp:9654-9682 import sanitizers (serial RawFile, shared folders,
  NVRAM path, ExtraData). TFTP fields are not in that list.
* ApplianceImplImport.cpp:6147-6151 i_importVBoxMachine call site.
* ConsoleImplConfigCommon.cpp:2286-2292 CFGM insert of TFTPPrefix/EnableTFTP.
* DrvNAT.cpp:1656-1665 EnableTFTP plus TFTPPrefix default "".
* libslirp slirp.c:698 g_strdup so empty prefix stays non-NULL.
* libslirp tftp.c:353-407 tftp_handle_rrq NULL disable, prefix+'/'+name,
  ../ reject, then a read-only open of the built path (RTFileOpen analog).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

TFTP_FILENAME_MAX = 512  # libslirp-4.9.3/src/tftp.h:23
PIN = "VirtualBox OSS 7.2.20"
PIN_PEEL = "f2792cf44f663989818507e36d3db5f978523c5e"
WITNESS = "VBOX-OVF-NAT-TFTP-PREFIX-WITNESS"
ORACLE_DIR = Path("/oracle")
ORACLE_PATH = ORACLE_DIR / WITNESS
CONTROL_PREFIX = "/work/tftp"
CONTROL_BOOT = "boot.pxe"

# Settings.cpp:9654-9682. Cited so the lab can grep that TFTP is absent.
SANITIZE_IMPORTED_SERIAL_PORTS_SRC = """
void MachineConfigFile::sanitizeImportedSerialPorts()
{
    for (SerialPortsList::iterator it = hardwareMachine.llSerialPorts.begin();
            it != hardwareMachine.llSerialPorts.end();
            ++it)
    {
        SerialPort &port = *it;
        if (port.portMode == PortMode_RawFile)
        {
            port.portMode = PortMode_Disconnected;
            port.strPath.setNull();
        }
    }
}
"""

SANITIZE_SHARED_FOLDER_SETTINGS_SRC = """
void MachineConfigFile::sanitizeSharedFolderSettings()
{
    hardwareMachine.llSharedFolders.clear();
}
"""

SANITIZE_IMPORTED_NVRAM_SETTINGS_SRC = """
void MachineConfigFile::sanitizeImportedNvramSettings()
{
    hardwareMachine.nvramSettings.strNvramPath.setNull();
}
"""

SANITIZE_IMPORTED_EXTRA_DATA_SRC = """
void MachineConfigFile::sanitizeImportedExtraData()
{
    mapExtraDataItems.clear();
}
"""

# ApplianceImplImport.cpp:6147-6151
IMPORT_VBOX_MACHINE_SANITIZE_SRC = """
    config.sanitizeImportedSerialPorts();
    config.sanitizeSharedFolderSettings();
    config.sanitizeImportedNvramSettings();
    if (!m->optListImport.contains(ImportOptions_KeepExtraData))
        config.sanitizeImportedExtraData();
"""

SANITIZER_BODIES: tuple[str, ...] = (
    SANITIZE_IMPORTED_SERIAL_PORTS_SRC,
    SANITIZE_SHARED_FOLDER_SETTINGS_SRC,
    SANITIZE_IMPORTED_NVRAM_SETTINGS_SRC,
    SANITIZE_IMPORTED_EXTRA_DATA_SRC,
    IMPORT_VBOX_MACHINE_SANITIZE_SRC,
)

TFTP_TOKENS: tuple[str, ...] = ("TFTP", "strTFTPPrefix", "fEnableTFTP")


class PortMode(Enum):
    """VBox PortMode_T. sanitizeImportedSerialPorts only clears RawFile."""

    DISCONNECTED = "Disconnected"
    HOST_PIPE = "HostPipe"
    RAW_FILE = "RawFile"


@dataclass
class SerialPort:
    port_mode: PortMode
    path: str | None


@dataclass
class SharedFolder:
    name: str
    host_path: str


@dataclass
class NatEngine:
    """vbox:Machine NAT blob. Settings.cpp:4873, 4888-4894."""

    f_enable_tftp: bool
    str_tftp_prefix: str
    str_tftp_boot_file: str = ""
    str_tftp_next_server: str = ""


@dataclass
class MachineConfig:
    extra_data: dict[str, str]
    shared_folders: list[SharedFolder]
    serial_ports: list[SerialPort]
    nvram_path: str | None
    nat: NatEngine


@dataclass(frozen=True)
class CfgmNat:
    enable_tftp: bool
    tftp_prefix: str | None


@dataclass(frozen=True)
class RrqResult:
    disabled: bool
    rejected: bool
    path: str | None
    data: bytes | None
    opened: bool
    error: str


def g_strdup(value: str | None) -> str | None:
    """libslirp glib.h:177-182. NULL in, NULL out; empty string stays non-NULL."""

    if value is not None:
        return str(value)
    return None


def sanitizer_mentions_tftp() -> list[str]:
    """Assert the pin sanitizer bodies never name TFTP fields."""

    hits: list[str] = []
    for body in SANITIZER_BODIES:
        for token in TFTP_TOKENS:
            if token in body:
                hits.append(token)
    return hits


def sanitize_imported_serial_ports(config: MachineConfig) -> None:
    # Settings.cpp:9654-9667
    for port in config.serial_ports:
        if port.port_mode is PortMode.RAW_FILE:
            port.port_mode = PortMode.DISCONNECTED
            port.path = None


def sanitize_shared_folder_settings(config: MachineConfig) -> None:
    # Settings.cpp:9669-9672
    config.shared_folders.clear()


def sanitize_imported_nvram_settings(config: MachineConfig) -> None:
    # Settings.cpp:9674-9677
    config.nvram_path = None


def sanitize_imported_extra_data(config: MachineConfig) -> None:
    # Settings.cpp:9679-9682
    config.extra_data.clear()


def import_vbox_machine(config: MachineConfig, *, keep_extra_data: bool = False) -> None:
    """ApplianceImplImport.cpp:6147-6151. Never touches nat.strTFTPPrefix / fEnableTFTP."""

    sanitize_imported_serial_ports(config)
    sanitize_shared_folder_settings(config)
    sanitize_imported_nvram_settings(config)
    if not keep_extra_data:
        sanitize_imported_extra_data(config)


def hostile_ovf_machine(*, tftp_prefix: str) -> MachineConfig:
    """vbox:Machine NAT enable-tftp plus TFTP/@prefix, plus fields the sanitizer does clear."""

    return MachineConfig(
        extra_data={"VBoxInternal/PDM/FailMountOnError": "1"},
        shared_folders=[SharedFolder(name="hosthome", host_path="/home/victim")],
        serial_ports=[
            SerialPort(port_mode=PortMode.RAW_FILE, path="/tmp/imported-uart.log"),
        ],
        nvram_path="/tmp/imported.nvram",
        nat=NatEngine(f_enable_tftp=True, str_tftp_prefix=tftp_prefix),
    )


def console_cfgm_from_nat(nat: NatEngine) -> CfgmNat:
    """ConsoleImplConfigCommon.cpp:2286-2292.

    TFTPPrefix is inserted only when non-empty; EnableTFTP is always inserted.
    """

    prefix: str | None = None
    if nat.str_tftp_prefix != "":
        prefix = nat.str_tftp_prefix
    return CfgmNat(enable_tftp=nat.f_enable_tftp, tftp_prefix=prefix)


def drv_nat_tftp_prefix(cfg: CfgmNat) -> str | None:
    """DrvNAT.cpp:1656-1665 then slirp.c:698 g_strdup.

    EnableTFTP default in DrvNAT is true for old VMs. This lab always inserts
    EnableTFTP from the imported NAT blob. TFTPPrefix default is "".
    slirpCfg is zeroed, so a disabled engine leaves tftp_path NULL.
    """

    if not cfg.enable_tftp:
        return None
    raw = "" if cfg.tftp_prefix is None else cfg.tftp_prefix
    return g_strdup(raw)


class TftpPrefixServer:
    """libslirp tftp_handle_rrq path builder plus a read-only open of the result."""

    def __init__(self, tftp_prefix: str | None) -> None:
        self.tftp_prefix = tftp_prefix
        self.opens: list[str] = []

    def handle_rrq(self, guest_name: str) -> RrqResult:
        # tftp.c:353-357 unspecified prefix means service disabled (NULL only).
        if self.tftp_prefix is None:
            return RrqResult(
                disabled=True,
                rejected=False,
                path=None,
                data=None,
                opened=False,
                error="Access violation",
            )

        prefix = self.tftp_prefix
        if len(guest_name) >= TFTP_FILENAME_MAX:
            return RrqResult(
                disabled=False,
                rejected=True,
                path=None,
                data=None,
                opened=False,
                error="Access violation",
            )

        # tftp.c:364-370 prepend tftp_prefix, then '/', then guest name.
        built = prefix + "/" + guest_name
        req_fname = built[len(prefix) + 1 :]

        # tftp.c:398-407 reject ../ and a trailing slash. Empty prefix is allowed.
        if "../" in req_fname or (req_fname.endswith("/") if req_fname else False):
            return RrqResult(
                disabled=False,
                rejected=True,
                path=built,
                data=None,
                opened=False,
                error="Access violation",
            )

        self.opens.append(built)
        try:
            fd = os.open(built, os.O_RDONLY)
        except OSError as exc:
            return RrqResult(
                disabled=False,
                rejected=False,
                path=built,
                data=None,
                opened=False,
                error=f"File not found:{exc.errno}",
            )
        try:
            data = os.read(fd, 4096)
        finally:
            os.close(fd)
        return RrqResult(
            disabled=False,
            rejected=False,
            path=built,
            data=data,
            opened=True,
            error="",
        )
