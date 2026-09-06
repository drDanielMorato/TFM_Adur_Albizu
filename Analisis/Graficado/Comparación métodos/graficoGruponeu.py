import matplotlib.pyplot as plt
import numpy as np

# Data
categories = ['Threshold 1', 'Threshold 2', 'Threshold 3', 'Threshold 4']
detected = [98, 98, 94, 90]
not_detected = [8, 8, 12, 16]

# Label locations and bar width
x = np.arange(len(categories))
width = 0.35

fig, ax = plt.subplots(figsize=(8, 4))

# Plot bars with matching hex colors
rects1 = ax.bar(x - width/2, detected, width, label='Detected Scans', color='#FF496C')
rects2 = ax.bar(x + width/2, not_detected, width, label='Not Detected Scans', color='#72A0ED')

# Labels and formatting
ax.set_ylabel('Number of Scans', fontsize=12)
ax.set_xlabel('Neu Method', fontsize=12)
ax.set_xticks(x)
ax.set_xticklabels(categories)
ax.set_ylim(0, 145)
ax.legend(loc='upper left', fontsize=12)

# Add value labels on top of each bar
ax.bar_label(rects1, padding=1, fontsize=10)
ax.bar_label(rects2, padding=1, fontsize=10)

plt.tight_layout()
plt.show()