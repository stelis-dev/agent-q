#!/usr/bin/env python3
"""Send a USB JSONL display-signal request and verify the device YES/NO response."""

from __future__ import annotations

import argparse
import glob
import json
import os
import select
import sys
import termios
import time
import uuid


DEFAULT_TIMEOUT_SECONDS = 30.0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Send one display_signal request over USB serial and wait for a physical YES/NO response."
    )
    parser.add_argument("--port", help="Serial port path. If omitted, a single USB modem/ACM port is auto-selected.")
    parser.add_argument("--message", default="Request received", help="Short message to show on the device screen.")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS, help="Response timeout in seconds.")
    parser.add_argument(
        "--expect",
        choices=("yes", "no", "any"),
        default="yes",
        help="Expected physical response. Defaults to yes.",
    )
    parser.add_argument("--verbose", action="store_true", help="Print ignored non-matching serial lines.")
    args = parser.parse_args()

    port = args.port or autodetect_port()
    request_id = f"usb-test-{uuid.uuid4().hex[:12]}"
    request = {
        "id": request_id,
        "version": 1,
        "type": "display_signal",
        "params": {
            "message": args.message,
        },
    }

    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        configure_serial(fd)
        drain_serial(fd)
        os.write(fd, (json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8"))
        response = read_response(fd, request_id, args.timeout, args.verbose)
    finally:
        os.close(fd)

    print(json.dumps(response, ensure_ascii=False, sort_keys=True))
    if response_matches_expectation(response, args.expect):
        return 0
    return 1


def response_matches_expectation(response: dict[str, object], expected: str) -> bool:
    if response.get("version") != 1 or response.get("type") != "display_signal_result":
        return False
    if expected == "any":
        return response.get("status") in ("approved", "rejected")
    if expected == "yes":
        return response.get("status") == "approved"
    return response.get("status") == "rejected"


def autodetect_port() -> str:
    candidates: list[str] = []
    for pattern in (
        "/dev/cu.usbmodem*",
        "/dev/ttyACM*",
        "/dev/serial/by-id/*",
    ):
        candidates.extend(glob.glob(pattern))

    candidates = sorted(dict.fromkeys(candidates))
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise SystemExit("No USB serial port found. Pass --port /path/to/port.")
    raise SystemExit("Multiple USB serial ports found. Pass --port explicitly:\n" + "\n".join(candidates))


def configure_serial(fd: int) -> None:
    attrs = termios.tcgetattr(fd)
    attrs[0] &= ~(termios.BRKINT | termios.ICRNL | termios.INPCK | termios.ISTRIP | termios.IXON)
    attrs[1] &= ~termios.OPOST
    attrs[2] |= termios.CS8 | termios.CLOCAL | termios.CREAD
    attrs[3] &= ~(termios.ECHO | termios.ICANON | termios.IEXTEN | termios.ISIG)
    attrs[4] = termios.B115200
    attrs[5] = termios.B115200
    attrs[6][termios.VMIN] = 0
    attrs[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, attrs)


def drain_serial(fd: int) -> None:
    deadline = time.monotonic() + 0.25
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.02)
        if not ready:
            continue
        try:
            if not os.read(fd, 4096):
                return
        except BlockingIOError:
            return


def read_response(fd: int, request_id: str, timeout_seconds: float, verbose: bool) -> dict[str, object]:
    deadline = time.monotonic() + timeout_seconds
    buffer = b""
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.05)
        if not ready:
            continue
        try:
            chunk = os.read(fd, 4096)
        except BlockingIOError:
            continue
        if not chunk:
            continue
        buffer += chunk
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            if not text.startswith("{"):
                if verbose:
                    print(f"ignored: {text}", file=sys.stderr)
                continue
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                if verbose:
                    print(f"ignored invalid json: {text}", file=sys.stderr)
                continue
            if parsed.get("id") == request_id:
                return parsed
            if verbose:
                print(f"ignored json: {text}", file=sys.stderr)

    raise SystemExit(f"Timed out waiting for response id {request_id}. Press YES or NO on the device screen.")


if __name__ == "__main__":
    raise SystemExit(main())
