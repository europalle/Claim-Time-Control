import re
import csv
import os
import sys
import argparse
from datetime import datetime
from difflib import SequenceMatcher
from dataclasses import dataclass
from typing import List, Optional
from collections import Counter

# ==========================================
# CONFIGURATION
# ==========================================
CONFIG = {
    "INPUT_FILE": "logs.txt",
    "ALIAS_FILE": "alias.txt",
    "BLACKLIST_FILE": "blacklist.txt",
    "OUTPUT_BREACH_FILE": "breach_report.csv",
    "OUTPUT_STATS_FILE": "admin_stats.csv",
    "SIMILARITY_THRESHOLD": 0.75,
    "MIN_NAME_LENGTH": 3
}

# ==========================================
# TERMINAL COLORS
# ==========================================
class Colors:
    BLUE = '\033[94m'
    RED = '\033[91m'
    ORANGE = '\033[93m'
    GREEN = '\033[92m'
    RESET = '\033[0m'

    @staticmethod
    def print_tag(tag, message):
        color = Colors.RESET
        if tag == "[INFO]": color = Colors.BLUE
        elif tag == "[WARNING]": color = Colors.RED
        elif tag == "[ALERT]": color = Colors.ORANGE
        elif tag == "[STATS]": color = Colors.GREEN
        
        print(f"{color}{tag}{Colors.RESET} {message}")

# ==========================================
# CUSTOM EXCEPTIONS
# ==========================================
class AdminToolError(Exception): pass
class FileAccessError(AdminToolError): pass
class LogParseError(AdminToolError): pass

# ==========================================
# DATA CLASSES
# ==========================================
@dataclass
class LogEntry:
    admin_canonical: str
    admin_original: str
    server: str
    timestamp: datetime

@dataclass
class Breach:
    admin: str
    alias_used: str
    timestamp: datetime
    gap_minutes: float
    server_from: str
    server_to: str

# ==========================================
# CLASS: IDENTITY MANAGER
# ==========================================
class IdentityManager:
    def __init__(self, alias_file: str, blacklist_file: str):
        self.alias_file = alias_file
        self.blacklist_file = blacklist_file
        self.name_map = {}
        self.canonical_names = set()
        self.blacklist_pairs = set()
        self._load_data()

    def _load_data(self):
        self._ensure_file_exists(self.alias_file)
        self._ensure_file_exists(self.blacklist_file)

        try:
            with open(self.alias_file, 'r', encoding='utf-8', errors='replace') as f:
                for row in csv.reader(f):
                    if len(row) >= 2:
                        self.name_map[row[0]] = row[1]
                        self.canonical_names.add(row[1])
        except IOError as e:
            Colors.print_tag("[WARNING]", f"Could not read alias file: {e}")

        try:
            with open(self.blacklist_file, 'r', encoding='utf-8', errors='replace') as f:
                for row in csv.reader(f):
                    if len(row) >= 2:
                        self.blacklist_pairs.add((row[0].strip().lower(), row[1].strip().lower()))
        except IOError as e:
            Colors.print_tag("[WARNING]", f"Could not read blacklist file: {e}")

    def _ensure_file_exists(self, filepath):
        if not os.path.exists(filepath):
            try:
                open(filepath, 'w').close()
            except IOError:
                raise FileAccessError(f"Could not create missing file: {filepath}")

    def _save_new_alias(self, alias: str, canonical: str):
        try:
            with open(self.alias_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([alias, canonical])
            Colors.print_tag("[INFO]", f"Auto-learned alias: '{alias}' -> '{canonical}'")
        except IOError:
            Colors.print_tag("[WARNING]", "Failed to write alias to disk.")

    def _is_blacklisted(self, name: str, existing: str) -> bool:
        return (name.lower(), existing.lower()) in self.blacklist_pairs

    def get_canonical_name(self, name: str) -> str:
        name = name.strip()
        if len(name) < CONFIG["MIN_NAME_LENGTH"]: return name
        
        if name in self.name_map: return self.name_map[name]
        
        for existing in self.canonical_names:
            if self._is_blacklisted(name, existing): continue

            is_substring = (name.lower() in existing.lower()) or (existing.lower() in name.lower())
            
            parts_name = name.lower().split()
            parts_existing = existing.lower().split()
            first_word_match = False
            if parts_name and parts_existing:
                if parts_name[0] == parts_existing[0] and len(parts_name[0]) > 3:
                    first_word_match = True

            similarity = SequenceMatcher(None, name.lower(), existing.lower()).ratio()
            
            if is_substring or first_word_match or similarity >= CONFIG["SIMILARITY_THRESHOLD"]:
                self._save_new_alias(name, existing)
                self.name_map[name] = existing
                return existing

        self.canonical_names.add(name)
        self.name_map[name] = name
        return name

# ==========================================
# CLASS: LOG PARSER
# ==========================================
class LogParser:
    def __init__(self, filepath: str, identity_manager: IdentityManager):
        self.filepath = filepath
        self.identity_manager = identity_manager

    def parse(self) -> List[LogEntry]:
        if not os.path.exists(self.filepath):
            raise FileAccessError(f"Log file '{self.filepath}' not found.")

        Colors.print_tag("[INFO]", f"Reading logs from {self.filepath}...")
        try:
            with open(self.filepath, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except IOError as e:
            raise FileAccessError(f"Failed to read file: {e}")

        raw_blocks = content.split('[')
        parsed_entries = []
        skipped_count = 0

        for block in raw_blocks:
            if not block.strip(): continue
            try:
                entry = self._parse_single_block(block)
                if entry:
                    parsed_entries.append(entry)
            except LogParseError:
                skipped_count += 1
                continue

        if skipped_count > 0:
            Colors.print_tag("[WARNING]", f"Skipped {skipped_count} invalid or non-admin blocks.")
        
        return parsed_entries

    def _parse_single_block(self, block: str) -> Optional[LogEntry]:
        if "**Admin:**" not in block: return None
        if "]" not in block: raise LogParseError("Missing timestamp bracket")
            
        time_str = block.split(']')[0].strip()
        timestamp = self._parse_timestamp(time_str)

        admin_match = re.search(r"\*\*Admin:\*\*\s*(.+)", block)
        if not admin_match: raise LogParseError("Missing admin name")
        
        raw_name = admin_match.group(1).strip()
        canonical_name = self.identity_manager.get_canonical_name(raw_name)

        server = "Unknown Server"
        if "{Embed}" in block:
            parts = block.split("{Embed}")
            if len(parts) > 1:
                lines = parts[1].strip().split('\n')
                for line in lines:
                    if line.strip():
                        server = line.strip()
                        break
        
        return LogEntry(canonical_name, raw_name, server, timestamp)

    def _parse_timestamp(self, time_str: str) -> datetime:
        formats = ["%d/%m/%Y %H:%M", "%m/%d/%Y %H:%M", "%d-%m-%Y %H:%M"]
        for fmt in formats:
            try:
                return datetime.strptime(time_str, fmt)
            except ValueError:
                continue
        raise LogParseError("Invalid timestamp")

# ==========================================
# CLASS: ANALYZER (Breaches & Stats)
# ==========================================
class Analyzer:
    @staticmethod
    def find_breaches(logs: List[LogEntry]) -> List[Breach]:
        logs.sort(key=lambda x: (x.admin_canonical, x.timestamp))
        breaches = []
        from itertools import groupby
        
        for admin, user_logs in groupby(logs, key=lambda x: x.admin_canonical):
            user_logs_list = list(user_logs)
            for i in range(1, len(user_logs_list)):
                current = user_logs_list[i]
                prev = user_logs_list[i-1]
                
                delta = current.timestamp - prev.timestamp
                minutes_diff = delta.total_seconds() / 60
                
                if 0.1 < minutes_diff < 5 and current.server != prev.server:
                    breaches.append(Breach(
                        admin=admin,
                        alias_used=current.admin_original,
                        timestamp=current.timestamp,
                        gap_minutes=round(minutes_diff, 2),
                        server_from=prev.server,
                        server_to=current.server
                    ))
        return breaches

    @staticmethod
    def generate_stats(logs: List[LogEntry]):
        stats = {}
        # Group data: Admin -> {count: 0, servers: []}
        for entry in logs:
            name = entry.admin_canonical
            if name not in stats:
                stats[name] = {'servers': []}
            stats[name]['servers'].append(entry.server)

        results = []
        for name, data in stats.items():
            total_claims = len(data['servers'])
            # Find most common server
            if total_claims > 0:
                most_common_server = Counter(data['servers']).most_common(1)[0][0]
            else:
                most_common_server = "N/A"
            
            results.append({
                "admin": name,
                "count": total_claims,
                "fav_server": most_common_server
            })
        
        # Sort by Count (Descending)
        results.sort(key=lambda x: x['count'], reverse=True)
        return results[:20] # Return Top 20

# ==========================================
# CLASS: REPORTER
# ==========================================
class Reporter:
    def print_breaches(self, breaches: List[Breach], output_file: str):
        print("")
        if not breaches:
            Colors.print_tag("[INFO]", "No breaches found.")
            return

        Colors.print_tag("[ALERT]", f"FOUND {len(breaches)} RULE BREACHES")
        print("-" * 110)
        print(f"{'ADMIN':<30} | {'TIME':<15} | {'GAP':<8} | {'SWITCH'}")
        print("-" * 110)
        
        for b in breaches:
            time_str = b.timestamp.strftime("%d/%m %H:%M")
            switch_str = f"{b.server_from} -> {b.server_to}"
            print(f"{b.admin:<30} | {time_str:<15} | {b.gap_minutes}m   | {switch_str}")

        self._save_breaches_csv(breaches, output_file)

    def _save_breaches_csv(self, breaches, filepath):
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Admin", "Alias", "Time", "Gap (Min)", "Server From", "Server To"])
                for b in breaches:
                    writer.writerow([
                        b.admin, b.alias_used, b.timestamp.strftime("%Y-%m-%d %H:%M"),
                        b.gap_minutes, b.server_from, b.server_to
                    ])
            Colors.print_tag("[INFO]", f"Breach report saved to {filepath}")
        except IOError as e:
            Colors.print_tag("[WARNING]", f"Error saving CSV: {e}")

    def print_stats(self, stats, output_file: str):
        print("")
        if not stats:
            Colors.print_tag("[INFO]", "No stats available.")
            return

        Colors.print_tag("[STATS]", "TOP 20 MOST ACTIVE ADMINS")
        print("-" * 80)
        print(f"{'RANK':<6} | {'ADMIN NAME':<30} | {'CLAIMS':<8} | {'FAVORITE SERVER'}")
        print("-" * 80)

        for idx, s in enumerate(stats, 1):
            print(f"#{idx:<5} | {s['admin']:<30} | {s['count']:<8} | {s['fav_server']}")

        self._save_stats_csv(stats, output_file)

    def _save_stats_csv(self, stats, filepath):
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Rank", "Admin", "Total Claims", "Favorite Server"])
                for idx, s in enumerate(stats, 1):
                    writer.writerow([idx, s['admin'], s['count'], s['fav_server']])
            Colors.print_tag("[INFO]", f"Stats report saved to {filepath}")
        except IOError as e:
            Colors.print_tag("[WARNING]", f"Error saving Stats CSV: {e}")

# ==========================================
# MAIN EXECUTION
# ==========================================
def main():
    # 1. Parse Arguments
    parser = argparse.ArgumentParser(description="Discord Admin Log Analyzer")
    parser.add_argument("-b", "--breach", action="store_true", help="Check for 5-minute rule breaches")
    parser.add_argument("-s", "--stats", action="store_true", help="Show Admin Statistics (Top 20)")
    args = parser.parse_args()

    # If no args provided, show help
    if not args.breach and not args.stats:
        parser.print_help()
        sys.exit(0)

    try:
        identity_mgr = IdentityManager(CONFIG["ALIAS_FILE"], CONFIG["BLACKLIST_FILE"])
        parser_logic = LogParser(CONFIG["INPUT_FILE"], identity_mgr)
        reporter = Reporter()

        # Parse Data Once
        logs = parser_logic.parse()
        Colors.print_tag("[INFO]", f"Analyzed {len(logs)} valid claims.")

        # FEATURE: BREACH DETECTION
        if args.breach:
            breaches = Analyzer.find_breaches(logs)
            reporter.print_breaches(breaches, CONFIG["OUTPUT_BREACH_FILE"])

        # FEATURE: STATS GENERATION
        if args.stats:
            stats = Analyzer.generate_stats(logs)
            reporter.print_stats(stats, CONFIG["OUTPUT_STATS_FILE"])

    except FileAccessError as e:
        Colors.print_tag("[WARNING]", str(e))
        sys.exit(1)
    except Exception as e:
        Colors.print_tag("[WARNING]", f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()