# TFM_Adur_Albizu

TFM de Adur Albizu sobre el análisis de trazas de red para detectar escaneos de puertos.

## 0. Versionado

| Versión (README) | Fecha de modificación | Autor |
|---|---|---|
| 0.2 | 30.08.2026 | Adur Albizu |

## 1. Flujo de trabajo

El repositorio cubre tres etapas:

1. **Extracción:** convierte capturas de red en registros de flujo mediante `procesaConexiones`.
2. **Detección:** aplica los métodos 3, Neu et al. y Sangeen et al. para localizar escaneos de puertos.
3. **Evaluación:** compara las detecciones con el ground truth y calcula métricas sobre los datasets Sangeen y CICIDS2017.

## 2. Métodos de detección

| Directorio | Descripción |
|---|---|
| `Extraccion/` | Extracción de flujos y series temporales a partir de capturas. Véase [Extraccion/README.md](Extraccion/README.md). |
| `Analisis/Metodo 3/` | Método desarrollado en el TFM; analiza conversaciones TCP y UDP. |
| `Analisis/Script Neu et al/` | Implementación de Neu et al. sobre registros de flujo TCP. |
| `Analisis/Script Sangeen/` | Implementación de Sangeen et al. mediante lectura directa de paquetes. |
| `Analisis/Calculo Metricas/` | Scripts para generar el ground truth y calcular métricas. |

En los tres métodos, `main.py` utiliza la entrada propia del algoritmo y `main_desde_pcap.py` procesa un directorio de capturas independientes. 

Los umbrales y ventanas temporales de cada método se encuentran en su archivo `config.py`.

