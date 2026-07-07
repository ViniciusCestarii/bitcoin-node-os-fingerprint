import argparse
import csv
from collections import Counter, defaultdict


def load_rows(path: str):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def print_bar(label: str, count: int, total: int, width: int = 30) -> None:
    pct = (count / total * 100) if total else 0
    filled = int(width * pct / 100)
    bar = "#" * filled + "-" * (width - filled)
    print(f"  {label:<20} {count:>6}  {pct:5.1f}%  [{bar}]")


OS_CLASS_LEGEND = {
    "Unknown": "nmap had no OS guess, or the guess scored below 70% accuracy.",
    "Other/Device": "guess matched a router/firewall/printer/appliance or similar, "
                     "likely a middlebox in front of the node rather than the node itself.",
    "Other": "guess matched an OS outside the tracked classes (Linux, BSD, Windows, "
             "macOS, Android, Solaris).",
}


def print_legend() -> None:
    print("\nLegend")
    print("-" * 60)
    for label, meaning in OS_CLASS_LEGEND.items():
        print(f"  {label}: {meaning}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_path", help="filtered scan CSV to analyse")
    args = parser.parse_args()

    rows = load_rows(args.csv_path)
    total = len(rows)

    host_states = Counter(row["host_state"] for row in rows)
    reachable_total = host_states.get("reachable", 0)

    reachable_rows = [row for row in rows if row["host_state"] == "reachable"]
    os_classes = Counter(row["os_class"] for row in reachable_rows)

    accuracies = defaultdict(list)
    for row in reachable_rows:
        if row["accuracy"]:
            accuracies[row["os_class"]].append(int(row["accuracy"]))

    print("=" * 60)
    print(f"Scan file: {args.csv_path}")
    print(f"Total records: {total}")
    print("=" * 60)

    print("\nHost state (reachable vs unreachable)")
    print("-" * 60)
    for state in sorted(host_states, key=host_states.get, reverse=True):
        print_bar(state, host_states[state], total)

    print(f"\nOS class among reachable nodes (n={reachable_total})")
    print("-" * 60)
    for label, count in sorted(os_classes.items(), key=lambda kv: kv[1], reverse=True):
        print_bar(label, count, reachable_total)

    print("\nAccuracy by OS class (reachable nodes with a guess)")
    print("-" * 60)
    for label in sorted(accuracies, key=lambda l: len(accuracies[l]), reverse=True):
        values = accuracies[label]
        avg = sum(values) / len(values)
        print(f"  {label:<20} n={len(values):<5} min={min(values):<4} avg={avg:5.1f}  max={max(values)}")

    print_legend()
    print()


if __name__ == "__main__":
    main()
