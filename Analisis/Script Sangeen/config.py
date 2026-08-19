TIME_THRESHOLD = 30 # umbral de tiempo en segundos para considerar que un flujo ha terminado y se debe crear una nueva flow entry
UNIQUE_PORTS_THRESHOLD = 20 # umbral de puertos únicos para considerar que un flujo es sospechoso
PACKET_REORDER_WINDOW = 0.001 # ventana de 1 ms para reordenar timestamps de captura ligeramente desordenados