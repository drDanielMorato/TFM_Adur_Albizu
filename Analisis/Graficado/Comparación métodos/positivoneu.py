import matplotlib.pyplot as plt
import numpy as np

# Data definitions
categories = ['Neu']
threshold_1 = [0]
threshold_2 = [0]
threshold_3 = [0]
threshold_4 = [0]

# Setup dimensions
n_groups = len(categories)
n_bars = 4
bar_width = 0.2

# Get colors matching the viridis color map
colors = plt.cm.viridis(np.linspace(0, 0.8, n_bars))

fig, ax = plt.subplots(figsize=(10, 4))

# Compute x positions for each group's bars
x = np.arange(n_groups)

# Plot each threshold bar group
rects1 = ax.bar(x - 1.5 * bar_width, threshold_1, bar_width, label='Threshold 1', color=colors[0])
rects2 = ax.bar(x - 0.5 * bar_width, threshold_2, bar_width, label='Threshold 2', color=colors[1])
rects3 = ax.bar(x + 0.5 * bar_width, threshold_3, bar_width, label='Threshold 3', color=colors[2])
rects4 = ax.bar(x + 1.5 * bar_width, threshold_4, bar_width, label='Threshold 4', color=colors[3])

# Logarithmic scaling & axes parameters
ax.set_yscale('log')
ax.set_ylabel('False Positive IPs Detected', fontsize=14)
ax.set_xlabel('Method', fontsize=14)

# Extra headroom so the value annotations aren't clipped at the top
max_height = max(threshold_1 + threshold_2 + threshold_3 + threshold_4)
ax.set_ylim(top=max_height * 1.2)

ax.set_xticks(x)  # Center ticks on the bar clusters
ax.set_xticklabels(categories, fontweight='bold', fontsize=10)

# Value annotations above non-zero bars
all_rects = [rects1, rects2, rects3, rects4]
for rect_group in all_rects:
    for rect in rect_group:
        height = rect.get_height()
        if height > 0:
            ax.annotate(f'{int(height)}',
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),  # 3 points vertical offset
                        textcoords="offset points",
                        ha='center', va='bottom',
                        fontweight='bold', fontsize=9)

# Aesthetics and layout
ax.legend(frameon=False, fontsize=10)
plt.tight_layout()
plt.show()