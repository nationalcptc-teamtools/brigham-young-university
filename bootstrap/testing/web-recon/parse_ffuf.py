#!/usr/bin/env python3
import glob
import json
import os
import sys

def main():
    if len(sys.argv) > 1:
        path = sys.argv[1]
    else:
        # Fallback: search for ffuf json files in recon_output/ or current directory
        matches = glob.glob("recon_output/*_ffuf.json") or glob.glob("*_ffuf.json")
        if not matches:
            print("Usage: python3 parse_ffuf.py <path_to_ffuf.json>", file=sys.stderr)
            sys.exit(1)
        path = matches[0]
        print(f"[*] No file path provided. Using found file: {path}\n")

    if not os.path.exists(path):
        print(f"Error: File not found: {path}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
    except Exception as e:
        print(f"Error loading JSON from {path}: {e}", file=sys.stderr)
        sys.exit(1)

    results = d.get("results", [])
    print(f"Total results: {len(results)}\n")
    print(f"{'STATUS':<8} {'SIZE':<10} {'WORDS':<8} URL")
    print("-" * 70)
    for r in sorted(results, key=lambda x: (x.get("status", 0), x.get("length", 0))):
        status = r.get("status", "?")
        length = r.get("length", "?")
        words = r.get("words", 0)
        url = r.get("url", "?")
        print(f"{status:<8} {length:<10} {words:<8} {url}")

if __name__ == "__main__":
    main()
