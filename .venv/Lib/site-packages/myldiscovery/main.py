#!/usr/bin/env python
# coding: utf-8

import argparse
import logging

from rich import print_json
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from myldiscovery import autodiscover

LOGGER = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-j", "--json", action="store_true", default=False)
    parser.add_argument("-d", "--debug", action="store_true", default=False)
    parser.add_argument(
        "-u", "--username", required=False, help="Username (Exchange only)"
    )
    parser.add_argument(
        "-p", "--password", required=False, help="Password (Exchange only)"
    )
    parser.add_argument("EMAIL")
    return parser.parse_args()


def main():
    console = Console()
    args = parse_args()

    logging.basicConfig(
        handlers=[RichHandler(console=console, show_time=False)],
        level=logging.DEBUG if args.debug else logging.INFO,
    )
    LOGGER.debug(args)

    try:
        res = autodiscover(
            args.EMAIL, username=args.username, password=args.password
        )
        if args.json:
            print_json(data=res)
        else:
            table = Table(
                expand=True,
                show_header=True,
                header_style="bold",
                show_lines=False,
                box=None,
            )
            table.add_column("Service", style="red")
            table.add_column("Host", style="blue")
            table.add_column("Port", style="green")
            table.add_column("Encryption", style="yellow")
            for svc in ["imap", "smtp"]:
                table.add_row(
                    svc,
                    res[svc]["server"],
                    str(res[svc]["port"]),
                    "starttls" if res[svc]["starttls"] else "tls",
                )
            console.print(table)
    except Exception:
        console.print_exception(show_locals=True)


if __name__ == "__main__":
    main()
