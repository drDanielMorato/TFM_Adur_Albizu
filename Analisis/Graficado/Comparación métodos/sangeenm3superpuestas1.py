import matplotlib.pyplot as plt

# Datos
puertos = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70]
fn = [0, 2, 4, 6, 7, 9, 9, 10, 10, 10, 10, 10, 10, 10]

fig, ax = plt.subplots(figsize=(8, 5))

# Método 3: Línea roja continua más gruesa con marcadores circulares
ax.plot(puertos, fn, color='red', linestyle='-', linewidth=2.5, marker='o', markersize=8, label='Method 3')

# Sangeen: Línea azul punteada encima con marcadores cuadrados más pequeños
ax.plot(puertos, fn, color='blue', linestyle='--', linewidth=2, marker='s', markersize=5, label='Sangeen')

ax.set_xlabel('Number of unique ports')
ax.set_ylabel('Number of false negatives (FN)')
ax.set_title('False negative count across thresholds')
ax.grid(True, linestyle=':', alpha=0.6)
ax.legend()

plt.tight_layout()
plt.show()