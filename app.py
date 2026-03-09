#!/usr/bin/env python3
# app.py - Threat Intelligence Feed Aggregator CLI
# Main entry point for the tool

import sys
import argparse
from feed_collector import FeedCollector
from indicator_parser import IndicatorParser
from analyzer import ThreatAnalyzer
from utils import Colors, colorize

VERSION = "1.0.0"

def print_banner():
    banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║     _____ _                    _     _____      _       _    ║
║    |_   _| |__  _ __ ___  __ _| |_  |_   _|_ _ | |_ ___| |   ║
║      | | | '_ \| '__/ _ \/ _` | __|   | |/ _` || __/ _ \ |   ║
║      | | | | | | | |  __/ (_| | |_    | | (_| || ||  __/ |   ║
║      |_| |_| |_|_|  \___|\__,_|\__|   |_|\__,_| \__\___|_|   ║
║                                                              ║
║          THREAT INTELLIGENCE FEED AGGREGATOR                 ║
║                    v{VERSION}                                   ║
╚══════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


def run_collection(use_live=False):
    """Main workflow: collect -> parse -> analyze -> report"""
    
    # Step 1: Collect feeds
    print(colorize("\n[PHASE 1] Collecting Threat Intelligence...", Colors.YELLOW))
    collector = FeedCollector(use_sample_data=not use_live)
    feeds = collector.collect_all()
    
    if not feeds:
        print(colorize("[!] No feeds collected. Check your configuration.", Colors.RED))
        return
    
    # show any errors
    errors = collector.get_errors()
    if errors:
        print(colorize("\n[!] Some feeds had errors:", Colors.YELLOW))
        for err in errors:
            print(f"    - {err}")
    
    # Step 2: Parse indicators
    print(colorize("\n[PHASE 2] Parsing Threat Indicators...", Colors.YELLOW))
    parser = IndicatorParser()
    
    for feed in feeds:
        source = feed['source']
        if feed['type'] == 'json':
            parser.parse_json_feed(feed['data'], source)
        else:
            parser.parse_text_feed(feed['data'], source)
    
    indicators = parser.get_normalized_indicators()
    total = parser.get_total_count()
    print(f"[+] Extracted {total} unique indicators")
    
    # Step 3: Analyze
    print(colorize("\n[PHASE 3] Analyzing Threats...", Colors.YELLOW))
    analyzer = ThreatAnalyzer()
    analyzer.analyze(indicators)
    
    # Step 4: Generate report
    print(colorize("\n[PHASE 4] Generating Report...", Colors.YELLOW))
    report = analyzer.generate_report()
    print(report)


def interactive_menu():
    """Simple menu for interactive use"""
    while True:
        print(colorize("\n[OPTIONS]", Colors.GREEN))
        print("  1. Run with sample data (demo mode)")
        print("  2. Run with live feeds (requires API keys)")
        print("  3. Exit")
        
        try:
            choice = input(colorize("\nSelect option: ", Colors.CYAN)).strip()
            
            if choice == '1':
                run_collection(use_live=False)
            elif choice == '2':
                print(colorize("\n[*] Attempting live feed collection...", Colors.YELLOW))
                print("    Note: Set API keys as environment variables:")
                print("    - ABUSEIPDB_KEY")
                print("    - OTX_KEY")
                print("    - VT_KEY")
                run_collection(use_live=True)
            elif choice == '3':
                print(colorize("\nGoodbye! Stay vigilant.", Colors.CYAN))
                sys.exit(0)
            else:
                print(colorize("Invalid option, try again.", Colors.RED))
        
        except KeyboardInterrupt:
            print(colorize("\n\nInterrupted. Exiting...", Colors.YELLOW))
            sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description='Threat Intelligence Feed Aggregator - Collect and analyze threat data'
    )
    parser.add_argument('--live', action='store_true', 
                        help='Use live API feeds instead of sample data')
    parser.add_argument('--no-banner', action='store_true',
                        help='Skip the banner')
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    
    args = parser.parse_args()
    
    if not args.no_banner:
        print_banner()
    
    # if --live flag passed, run directly
    if args.live:
        run_collection(use_live=True)
    else:
        # otherwise show menu
        interactive_menu()


if __name__ == '__main__':
    main()
