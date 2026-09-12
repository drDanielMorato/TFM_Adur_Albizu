"""Create chronological mosaics from the daily plot images."""

import argparse
import math
import os
from datetime import date

import matplotlib.image as image
import matplotlib.pyplot as plt


DEFAULT_INPUT = r"C:\Users\TESTER\Desktop\imagenes"
DEFAULT_OUTPUT = DEFAULT_INPUT
EXCLUDED_DATES = {
    "2017-12-19",
    "2018-01-18",
    "2018-02-07",
    "2018-02-26",
    "2018-03-15",
}
PLOT_TYPES = {
    "actividad_temporal_ataques": "Temporal Attack Activity",
    "cdf_puertos_unicos": "Unique Ports CDF",
    "densidad_duracion_ataques": "Attack Duration Density",
    "histograma_puertos_unicos": "Unique Ports Histogram",
}


def find_daily_plots(input_directory):
    """Return complete, non-excluded daily directories in chronological order."""
    daily_plots = []
    for directory_name in os.listdir(input_directory):
        directory_path = os.path.join(input_directory, directory_name)
        if not os.path.isdir(directory_path) or directory_name in EXCLUDED_DATES:
            continue

        try:
            date.fromisoformat(directory_name)
        except ValueError:
            continue

        plots = {}
        for plot_type in PLOT_TYPES:
            expected_name = f"{directory_name}_{plot_type}.png"
            plot_path = os.path.join(directory_path, expected_name)
            if os.path.isfile(plot_path):
                plots[plot_type] = plot_path

        if len(plots) == len(PLOT_TYPES):
            daily_plots.append((directory_name, plots))

    return sorted(daily_plots, key=lambda item: item[0])


def create_mosaic(
    daily_plots,
    plot_type,
    title,
    output_path,
    columns=4,
    dpi=300,
    part_number=None,
    total_parts=None,
):
    """Create one image containing one labelled panel per day."""
    rows = math.ceil(len(daily_plots) / columns)
    figure, axes = plt.subplots(
        rows,
        columns,
        figsize=(columns * 4.5, rows * 3.0),
        squeeze=False,
    )
    axes = axes.ravel()

    for axis, (day, plots) in zip(axes, daily_plots):
        axis.imshow(image.imread(plots[plot_type]), interpolation="none")
        axis.set_title(day, fontsize=8)
        axis.axis("off")

    for axis in axes[len(daily_plots):]:
        axis.axis("off")

    part_label = f" - Part {part_number} of {total_parts}" if total_parts else ""
    figure.suptitle(
        f"{title}{part_label} - Daily Mosaic ({len(daily_plots)} days)",
        fontsize=16,
    )
    figure.tight_layout(rect=(0, 0, 1, 0.98))
    figure.savefig(output_path, dpi=dpi)
    plt.close(figure)


def main():
    parser = argparse.ArgumentParser(
        description="Create four chronological mosaics from daily plot images."
    )
    parser.add_argument("--input", default=DEFAULT_INPUT, help="Directory containing daily folders")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="Directory for the four mosaics")
    parser.add_argument(
        "--parts",
        type=int,
        choices=(1, 2, 3),
        default=3,
        help="Split each plot into this many chronological images (default: 3)",
    )
    parser.add_argument(
        "--columns",
        type=int,
        default=4,
        help="Number of panels per row (default: 4)",
    )
    parser.add_argument("--dpi", type=int, default=300, help="Output resolution (default: 300)")
    args = parser.parse_args()

    if args.columns < 1:
        parser.error("--columns must be at least 1")
    if args.dpi < 1:
        parser.error("--dpi must be at least 1")
    if not os.path.isdir(args.input):
        parser.error(f"Input directory does not exist: {args.input}")

    daily_plots = find_daily_plots(args.input)
    if not daily_plots:
        parser.error("No complete daily plot directories were found")

    os.makedirs(args.output, exist_ok=True)
    for plot_type, title in PLOT_TYPES.items():
        part_size = math.ceil(len(daily_plots) / args.parts)
        for part_index in range(args.parts):
            start = part_index * part_size
            end = min(start + part_size, len(daily_plots))
            daily_plots_part = daily_plots[start:end]
            if not daily_plots_part:
                continue

            if args.parts == 1:
                filename = f"mosaic_{plot_type}.png"
                part_number = None
                total_parts = None
            else:
                filename = f"mosaic_{plot_type}_part_{part_index + 1}_of_{args.parts}.png"
                part_number = part_index + 1
                total_parts = args.parts

            output_path = os.path.join(args.output, filename)
            create_mosaic(
                daily_plots_part,
                plot_type,
                title,
                output_path,
                args.columns,
                args.dpi,
                part_number,
                total_parts,
            )
            print(f"Created {output_path}")

    print(f"Processed {len(daily_plots)} complete days")
    print(f"Excluded dates: {', '.join(sorted(EXCLUDED_DATES))}")


if __name__ == "__main__":
    main()