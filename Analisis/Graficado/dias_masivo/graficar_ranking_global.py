"""Plot rank against number of victims from the global ranking file."""

import argparse
import os
import re

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402


DEFAULT_INPUT = r"C:\Users\TESTER\Desktop\imagenes\ranking_conversaciones_global.txt"
SECTION_PATTERN = re.compile(r"^Ranking of attackers - (\S+)\s*$")
ROW_PATTERN = re.compile(
    r"^\s*(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+([0-9]+(?:\.[0-9]+)?)\s*$"
)


def read_ranking(path):
    """Return ranking rows grouped by protocol."""
    rankings = {}
    current_protocol = None

    with open(path, "r", encoding="utf-8", errors="replace") as ranking_file:
        for line in ranking_file:
            section_match = SECTION_PATTERN.match(line)
            if section_match:
                current_protocol = section_match.group(1)
                rankings.setdefault(current_protocol, [])
                continue

            row_match = ROW_PATTERN.match(line)
            if not row_match or current_protocol is None:
                continue

            rank, protocol, attacker_ip, victims, mean_unique_ports = row_match.groups()
            rankings.setdefault(protocol, []).append(
                {
                    "rank": int(rank),
                    "attacker_ip": attacker_ip,
                    "victims": int(victims),
                    "mean_unique_ports": float(mean_unique_ports),
                }
            )

    return {protocol: rows for protocol, rows in rankings.items() if rows}


def plot_ranking(rankings, output_path):
    """Plot columns 4 and 5 against the rank on separate vertical axes."""
    figure, victims_axes = plt.subplots(figsize=(12, 6.5))
    ports_axes = victims_axes.twinx()
    victims_color = "#365C6D"
    ports_color = "#9B5C5C"
    victims_lines = []
    ports_lines = []

    for protocol, rows in rankings.items():
        ranks = [row["rank"] for row in rows]
        victims = [row["victims"] for row in rows]
        mean_unique_ports = [row["mean_unique_ports"] for row in rows]
        victims_lines.extend(
            victims_axes.plot(
                ranks,
                victims,
                color=victims_color,
                linewidth=1.5,
                label=f"{protocol} - Number of victims",
            )
        )
        ports_lines.extend(
            ports_axes.plot(
                ranks,
                mean_unique_ports,
                color=ports_color,
                linewidth=1.1,
                alpha=0.85,
                label=f"{protocol} - Mean unique ports per victim",
            )
        )

    victims_axes.set_title("Global Attacker Ranking")
    victims_axes.set_xlabel("Rank")
    victims_axes.set_ylabel("Number of victims", color=victims_color)
    ports_axes.set_ylabel("Mean unique ports per victim", color=ports_color)
    victims_axes.set_xlim(left=1, right=max(ranks))
    victims_axes.set_ylim(bottom=0)
    ports_axes.set_ylim(bottom=0)
    victims_axes.tick_params(axis="y", colors=victims_color)
    ports_axes.tick_params(axis="y", colors=ports_color)
    victims_axes.grid(True, alpha=0.3)
    lines = victims_lines + ports_lines
    victims_axes.legend(lines, [line.get_label() for line in lines], loc="upper right")
    figure.tight_layout()
    figure.savefig(output_path, dpi=150)
    plt.close(figure)


def main():
    parser = argparse.ArgumentParser(
        description="Plot rank (column 1) against number of victims (column 4)."
    )
    parser.add_argument("input", nargs="?", default=DEFAULT_INPUT, help="Global ranking text file")
    parser.add_argument("--output", help="Output PNG path")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        parser.error(f"Input file does not exist: {args.input}")

    output_path = args.output or os.path.splitext(args.input)[0] + ".png"
    rankings = read_ranking(args.input)
    if not rankings:
        parser.error("No ranking rows were found in the input file")

    plot_ranking(rankings, output_path)
    row_count = sum(len(rows) for rows in rankings.values())
    print(f"Chart saved to {output_path} ({row_count} rows)")


if __name__ == "__main__":
    main()