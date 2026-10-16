"""Native-friendly Gandon-PRO Python plugin example.

The Win32 host understands the small stdout protocol:
  action=<menu title> during --gandon-load
  status=<message> or navigate=<address> during --gandon-action
"""

import argparse
import os


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gandon-load", action="store_true")
    parser.add_argument("--gandon-action")
    parser.add_argument("--binary", default="")
    parser.add_argument("--address", default="0x0")
    args = parser.parse_args()

    if args.gandon_load:
        print("action=Binary Summary")
        return

    if args.gandon_action == "Binary Summary":
        if not args.binary:
            print("status=No binary is loaded.")
            return
        try:
            size = os.path.getsize(args.binary)
            print(f"status={os.path.basename(args.binary)} | {size:,} bytes | current {args.address}")
        except OSError as exc:
            print(f"status=Could not read binary: {exc}")


if __name__ == "__main__":
    main()
