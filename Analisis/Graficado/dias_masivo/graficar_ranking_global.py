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


def _bounds(values, logarithmic=False):
    """Return readable axis bounds with a small margin around the data."""
    minimum = min(values)
    maximum = max(values)
    if logarithmic:
        return minimum / 1.15, maximum * 1.15
    return max(0, minimum - (maximum - minimum) * 0.05), maximum * 1.05


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


def plot_ranking(rankings, output_path, logarithmic_y=False):
    """Plot columns 4 and 5 against rank in aligned charts."""
    figure, (victims_axes, ports_axes) = plt.subplots(
        2, 1, figsize=(12, 8), sharex=True, layout="constrained"
    )
    victims_color = "#365C6D"
    ports_color = "#9B5C5C"
    all_ranks = []
    all_victims = []
    all_mean_unique_ports = []

    for protocol, rows in rankings.items():
        ranks = [row["rank"] for row in rows]
        victims = [row["victims"] for row in rows]
        mean_unique_ports = [row["mean_unique_ports"] for row in rows]
        all_ranks.extend(ranks)
        all_victims.extend(victims)
        all_mean_unique_ports.extend(mean_unique_ports)
        victims_axes.plot(
            ranks,
            victims,
            color=victims_color,
            linewidth=1.5,
            label=protocol,
        )
        ports_axes.plot(
            ranks,
            mean_unique_ports,
            color=ports_color,
            linewidth=1.1,
            label=protocol,
        )

    figure.suptitle("Global Attacker Ranking")
    victims_ylabel = "Number of victims"
    ports_ylabel = "Mean unique ports per victim"
    if logarithmic_y:
        victims_axes.set_yscale("log")
        ports_axes.set_yscale("log")
        victims_ylabel += " (log scale)"
        ports_ylabel += " (log scale)"

    victims_axes.set_ylabel(victims_ylabel, color=victims_color)
    ports_axes.set_ylabel(ports_ylabel, color=ports_color)
    ports_axes.set_xlabel("Rank")
    victims_axes.set_xlim(left=1, right=max(all_ranks))
    if logarithmic_y:
        victims_axes.set_ylim(min(all_victims), max(all_victims) * 1.15)
        ports_axes.set_ylim(min(all_mean_unique_ports), max(all_mean_unique_ports) * 1.15)
    else:
        victims_axes.set_ylim(*_bounds(all_victims))
        ports_axes.set_ylim(*_bounds(all_mean_unique_ports))
    victims_axes.tick_params(axis="y", colors=victims_color)
    ports_axes.tick_params(axis="y", colors=ports_color)
    victims_axes.grid(True, alpha=0.3)
    ports_axes.grid(True, alpha=0.3)
    if len(rankings) > 1:
        victims_axes.legend(title="Protocol")
        ports_axes.legend(title="Protocol")
    figure.savefig(output_path, dpi=150)
    plt.close(figure)


def main():
    parser = argparse.ArgumentParser(
        description="Plot rank (column 1) against number of victims (column 4)."
    )
    parser.add_argument("input", nargs="?", default=DEFAULT_INPUT, help="Global ranking text file")
    parser.add_argument("--output", help="Output PNG path")
    parser.add_argument(
        "--log-y",
        action="store_true",
        help="Use logarithmic scales for both vertical axes",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        parser.error(f"Input file does not exist: {args.input}")

    default_suffix = "_log" if args.log_y else ""
    output_path = args.output or os.path.splitext(args.input)[0] + default_suffix + ".png"
    rankings = read_ranking(args.input)
    if not rankings:
        parser.error("No ranking rows were found in the input file")

    plot_ranking(rankings, output_path, logarithmic_y=args.log_y)
    row_count = sum(len(rows) for rows in rankings.values())
    print(f"Chart saved to {output_path} ({row_count} rows)")


if __name__ == "__main__":
    main()