import argparse
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from modules.scanner import ShadowScanCore
from modules.secrets import SecretFinder
from modules.bruteforce import DirectoryBruter

console = Console()


def main():
    parser = argparse.ArgumentParser(
        prog="shadowscan",
        description="ShadowScan Pro: Advanced Modular Reconnaissance Framework"
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-t", "--threads", type=int, default=40, help="Number of concurrent threads")
    parser.add_argument("-s", "--secrets", action="store_true", help="Enable Secret Finder (JS Scraper)")
    parser.add_argument("-b", "--brute", action="store_true", help="Enable Directory Brute-force")
    parser.add_argument("-o", "--output", help="Custom output JSON filename")
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: WARNING)"
    )
    args = parser.parse_args()

    # Wire up logging — previously all logger.* calls were silently discarded
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(levelname)-8s %(message)s"
    )

    console.print(
        f"\n[bold red]SHADOWSCAN PRO[/bold red] | Target: [yellow]{args.domain}[/yellow]",
        justify="center"
    )
    console.print(
        f"[*] Threads: {args.threads} | Modules: Core"
        + (" + Secrets" if args.secrets else "")
        + (" + Brute" if args.brute else ""),
        style="dim"
    )
    console.print("-" * 65)

    # --- Core Scanner ---
    scanner = ShadowScanCore(args.domain, args.threads)
    scanner.run()

    if not scanner.results:
        console.print("[bold red][!] No live hosts found. Exiting.[/bold red]")
        return

    live_hosts = list(scanner.results.keys())

    # --- Secrets Module: run all hosts in parallel ---
    if args.secrets:
        console.print("\n[bold cyan][*] Launching Secret Finder Module...[/bold cyan]")
        finder = SecretFinder()

        def run_secrets(host):
            return host, finder.scan_url(host)

        with ThreadPoolExecutor(max_workers=min(args.threads, len(live_hosts))) as ex:
            for host, secrets in ex.map(run_secrets, live_hosts):
                scanner.results[host]["secrets"] = secrets
                if secrets:
                    console.print(f"[bold green][!] SECRETS on {host}:[/bold green]")
                    for s in secrets:
                        console.print(f"    |_ {s['type']}: {s['value']}")

    # --- Brute Force Module: run all hosts in parallel ---
    if args.brute:
        console.print("\n[bold yellow][*] Launching Directory Brute-force Module...[/bold yellow]")
        bruter = DirectoryBruter()

        def run_brute(host):
            return host, bruter.scan(host)

        with ThreadPoolExecutor(max_workers=min(10, len(live_hosts))) as ex:
            for host, paths in ex.map(run_brute, live_hosts):
                scanner.results[host]["directories"] = paths
                if paths:
                    console.print(f"[bold green][!] PATHS on {host}:[/bold green]")
                    for p in paths:
                        console.print(f"    |_ {p['path']} [{p['status']}] ({p['size']}B)")

    # --- Save Report ---
    output_file = args.output or f"scan_{args.domain.replace('.', '_')}.json"
    try:
        with open(output_file, "w") as f:
            json.dump(scanner.results, f, indent=4)
        console.print(f"\n[bold white][+] Report saved: {output_file}[/bold white]")
    except OSError as e:
        console.print(f"\n[bold red][!] Could not save report: {e}[/bold red]")


if __name__ == "__main__":
    main()
