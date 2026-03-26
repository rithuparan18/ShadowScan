import argparse
import json
import os
from rich.console import Console
from rich.table import Table
from modules.scanner import ShadowScanCore
from modules.secrets import SecretFinder
from modules.bruteforce import DirectoryBruter

console = Console()

def main():
    # 1. Argument Parser Configuration
    parser = argparse.ArgumentParser(
        prog="shadowscan", 
        description="ShadowScan Pro: Advanced Modular Reconnaissance Framework"
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-t", "--threads", type=int, default=40, help="Number of concurrent threads")
    parser.add_argument("-s", "--secrets", action="store_true", help="Enable Secret Finder (JS Scraper)")
    parser.add_argument("-b", "--brute", action="store_true", help="Enable Directory Brute-force")
    parser.add_argument("-o", "--output", help="Custom output JSON filename")

    args = parser.parse_args()

    # 2. UI Banner
    console.print(f"\n[bold red]SHADOWSCAN PRO[/bold red] | Target: [yellow]{args.domain}[/yellow]", justify="center")
    console.print(f"[*] Threads: {args.threads} | Active Modules: Core" + 
                  (" + Secrets" if args.secrets else "") + 
                  (" + Brute" if args.brute else ""), style="dim")
    console.print("-" * 65)

    # 3. Execution: Core Scanner (Subdomains + Ports + Banners)
    scanner = ShadowScanCore(args.domain, args.threads)
    scanner.run()

    # 4. Execution: Post-Scan Modules
    if args.secrets:
        console.print("\n[bold cyan][*] Launching Secret Finder Module...[/bold cyan]")
        finder = SecretFinder()
        for host in scanner.results.keys():
            secrets = finder.scan_url(host)
            # Merge findings into the scanner results dictionary
            scanner.results[host]["secrets"] = secrets
            if secrets:
                console.print(f"[bold green][!] SECRETS DISCOVERED on {host}:[/bold green]")
                for s in secrets:
                    console.print(f"    |_ {s['type']}: {s['value']}")

    if args.brute:
        console.print("\n[bold yellow][*] Launching Directory Brute-force Module...[/bold yellow]")
        bruter = DirectoryBruter()
        for host in scanner.results.keys():
            paths = bruter.scan(host)
            # Merge findings into the scanner results dictionary
            scanner.results[host]["directories"] = paths
            if paths:
                console.print(f"[bold green][!] HIDDEN PATHS FOUND on {host}:[/bold green]")
                for p in paths:
                    console.print(f"    |_ {p['path']} (Status: {p['status']})")

    # 5. Data Persistence: Save Final Combined Report
    output_file = args.output if args.output else f"scan_{args.domain.replace('.', '_')}.json"
    try:
        with open(output_file, "w") as f:
            json.dump(scanner.results, f, indent=4)
        console.print(f"\n[bold white][+] Full intelligence report saved to: {output_file}[/bold white]")
    except Exception as e:
        console.print(f"\n[bold red][!] Error saving report: {e}[/bold red]")

if __name__ == "__main__":
    main()
