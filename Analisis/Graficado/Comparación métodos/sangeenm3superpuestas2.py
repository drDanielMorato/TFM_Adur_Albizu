import matplotlib.pyplot as plt

# Datos
unique_ports = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70]
fp_sangeen = [6266, 2477, 1639, 1250, 1059, 954, 865, 802, 751, 704, 664, 630, 605, 568]
fp_metodo3 = [0] * len(unique_ports)  # 0 para todos los umbrales

fig, ax = plt.subplots(figsize=(8, 5))

# Traza azul: Sangeen
ax.plot(unique_ports, fp_sangeen, color='blue', linestyle='-', linewidth=2, marker='s', markersize=6, label='Sangeen')

# Traza roja: Método 3 (plana en 0)
ax.plot(unique_ports, fp_metodo3, color='red', linestyle='-', linewidth=2.5, marker='o', markersize=6, label='Method 3')

# Etiquetas y formato
ax.set_xlabel('Number of unique ports', fontsize=12)
ax.set_ylabel('Number of false positives (FP)', fontsize=12)
ax.set_title('False positive count across thresholds', fontsize=14, fontweight='bold')
ax.grid(True, linestyle=':', alpha=0.6)
ax.legend(fontsize=11)

plt.tight_layout()
plt.show()