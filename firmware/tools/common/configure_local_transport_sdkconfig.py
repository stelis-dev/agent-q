#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path


LOCAL_TRANSPORT_CONFIG = {
    "CONFIG_BT_ENABLED": "y",
    "CONFIG_BT_NIMBLE_ENABLED": "y",
    "CONFIG_BT_NIMBLE_MEM_ALLOC_MODE_INTERNAL": "n",
    "CONFIG_BT_NIMBLE_MEM_ALLOC_MODE_EXTERNAL": "y",
    "CONFIG_BT_NIMBLE_MEM_ALLOC_MODE_DEFAULT": "n",
    "CONFIG_BT_NIMBLE_ROLE_CENTRAL": "n",
    "CONFIG_BT_NIMBLE_ROLE_PERIPHERAL": "y",
    "CONFIG_BT_NIMBLE_ROLE_BROADCASTER": "y",
    "CONFIG_BT_NIMBLE_ROLE_OBSERVER": "n",
    "CONFIG_BT_NIMBLE_GATT_CLIENT": "n",
    "CONFIG_BT_NIMBLE_GATT_SERVER": "y",
    "CONFIG_BT_NIMBLE_SECURITY_ENABLE": "n",
    "CONFIG_BT_NIMBLE_HS_PVCY": "n",
    "CONFIG_MBEDTLS_HKDF_C": "y",
    "CONFIG_SPIRAM_ALLOW_BSS_SEG_EXTERNAL_MEMORY": "y",
    "CONFIG_BT_NIMBLE_MAX_BONDS": "1",
    "CONFIG_BT_NIMBLE_MAX_CONNECTIONS": "1",
    "CONFIG_BT_NIMBLE_MAX_CCCDS": "2",
    "CONFIG_BT_NIMBLE_ATT_PREFERRED_MTU": "128",
    "CONFIG_BT_NIMBLE_ATT_MAX_PREP_ENTRIES": "4",
    "CONFIG_BT_NIMBLE_MSYS_1_BLOCK_COUNT": "8",
    "CONFIG_BT_NIMBLE_MSYS_1_BLOCK_SIZE": "256",
    "CONFIG_BT_NIMBLE_MSYS_2_BLOCK_COUNT": "8",
    "CONFIG_BT_NIMBLE_MSYS_2_BLOCK_SIZE": "320",
    "CONFIG_BT_NIMBLE_TRANSPORT_ACL_FROM_LL_COUNT": "8",
    "CONFIG_BT_NIMBLE_TRANSPORT_ACL_SIZE": "255",
    "CONFIG_BT_NIMBLE_TRANSPORT_EVT_COUNT": "12",
    "CONFIG_BT_NIMBLE_TRANSPORT_EVT_DISCARD_COUNT": "2",
    "CONFIG_BT_NIMBLE_50_FEATURE_SUPPORT": "n",
    "CONFIG_BT_NIMBLE_PROX_SERVICE": "n",
    "CONFIG_BT_NIMBLE_ANS_SERVICE": "n",
    "CONFIG_BT_NIMBLE_CTS_SERVICE": "n",
    "CONFIG_BT_NIMBLE_HTP_SERVICE": "n",
    "CONFIG_BT_NIMBLE_IPSS_SERVICE": "n",
    "CONFIG_BT_NIMBLE_TPS_SERVICE": "n",
    "CONFIG_BT_NIMBLE_IAS_SERVICE": "n",
    "CONFIG_BT_NIMBLE_LLS_SERVICE": "n",
    "CONFIG_BT_NIMBLE_SPS_SERVICE": "n",
    "CONFIG_BT_NIMBLE_HR_SERVICE": "n",
    "CONFIG_BT_NIMBLE_BAS_SERVICE": "n",
    "CONFIG_BT_NIMBLE_DIS_SERVICE": "n",
    "CONFIG_BT_NIMBLE_DTM_MODE_TEST": "n",
    "CONFIG_BT_CTRL_BLE_MAX_ACT": "2",
    "CONFIG_BT_CTRL_BLE_SCAN": "n",
    "CONFIG_BT_CTRL_BLE_SECURITY_ENABLE": "n",
    "CONFIG_BT_CTRL_DTM_ENABLE": "n",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Apply the current local-transport ESP-IDF build contract."
    )
    parser.add_argument("--malloc-always-internal", type=int, required=True)
    parser.add_argument("--malloc-reserve-internal", type=int, required=True)
    parser.add_argument("--prefer-network-psram", action="store_true")
    parser.add_argument("config", nargs="+")
    args = parser.parse_args()
    if args.malloc_always_internal < 0 or args.malloc_reserve_internal < 0:
        parser.error("memory values must be non-negative")
    return args


def apply_config(config_path: Path, values: dict[str, str]) -> None:
    if not config_path.exists():
        return
    if config_path.is_symlink() or not config_path.is_file():
        raise SystemExit(f"Refusing to write through non-regular config path: {config_path}")

    lines = config_path.read_text().splitlines()
    for key, value in values.items():
        desired = f"# {key} is not set" if value == "n" else f"{key}={value}"
        updated: list[str] = []
        replaced = False
        for line in lines:
            if line.startswith(f"{key}=") or line == f"# {key} is not set":
                if not replaced:
                    updated.append(desired)
                    replaced = True
                continue
            updated.append(line)
        if not replaced:
            updated.append(desired)
        lines = updated
    config_path.write_text("\n".join(lines) + "\n")


def main() -> None:
    args = parse_args()
    values = dict(LOCAL_TRANSPORT_CONFIG)
    values["CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL"] = str(args.malloc_always_internal)
    values["CONFIG_SPIRAM_MALLOC_RESERVE_INTERNAL"] = str(args.malloc_reserve_internal)
    values["CONFIG_SPIRAM_TRY_ALLOCATE_WIFI_LWIP"] = (
        "y" if args.prefer_network_psram else "n"
    )
    for raw_path in args.config:
        apply_config(Path(raw_path), values)


if __name__ == "__main__":
    main()
