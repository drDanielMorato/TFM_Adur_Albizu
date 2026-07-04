# procesar.py

Script para la extracción y preprocesado de archivos `.pcap` capturados en la red de la universidad. A partir de un conjunto de archivos pcap comprimidos, genera registros de flujo y series temporales.

## 0. Versionado
| Versión (Readme)| Fecha de modificación | Autor
|---|---|---|
| 0.1 | 04.07.2026 | Adur Albizu

## 1. Localización del script

| Entorno | Ruta |
|---|---|
| Local (@TLM83) | `/opt3/proyectistas/adur.albizu/VirtualBoxVM/Scripts/TFM_Adur_Albizu/Extraccion/procesar.py` |
| @trazas | `/home/adur.albizu/scripts/` |
| Repositorio GitHub | [TFM_Adur_Albizu](https://github.com/drDanielMorato/TFM_Adur_Albizu) |

## 2. Control de cambios

- Todos los cambios se suben directamente a Git.
- Se utiliza versionado semántico: **el número de versión debe incrementarse en cada commit y crear un tag en git**.

## 3. ¿Qué hace el script?

1. **Lanza `procesaConexiones`** sobre el directorio de montaje indicado (p. ej. `/trazas1`, `/trazas2`), incluyendo los siguientes módulos:
    `moduleTCPfirstData.so`
   - `moduleUDPfirstData.so`
   - `moduleTCPhistFlags.so`
   - `moduleTLSAppLevel.so`
   - `moduleDNSparserAppLevel.so`
   - `moduloSerieTemporal.so`: prepara un conjunto de series temporales para la subred de la universidad, marcándola como destino u origen según el filtro BPF. Los filtros exploran el tráfico según el protocolo de comunicación (TCP, ICMP, UDP...), desglosado según si es de entrada o salida.

2. **Extrae las MACs** de los registros de flujo, utilizando la salida `salida_udp_` generada en el paso anterior.

3. **Lanza `tseries`**, contra los mismos filtros definidos en el paso 1, pero basándose en las MACs encontradas en el paso 2 en lugar de en los rangos de IPs de la subred de la UPNA.

4. **Convierte el directorio resultante en read-only.**

> ⚠️ **Nota:** se mencionan "el módulo tseries de `procesaConexiones`" y "la herramienta `tseries`". Aunque ambos generan archivos con series temporales, son herramientas distintas.

## 4. Argumentos de entrada

| Argumento | Alias | Descripción |
|---|---|---|
| `--rutaOrigen` | `-o` | Directorio de montaje a analizar (`/trazas1`, `/trazas2`...), contiene los archivos .gz. |
| `--rutaDestino` | `-d` | Directorio de salida donde se almacenará el resultado (usualmente `/opt2/adur/`) |
| `--rutaConfig` | `-c` | Ruta completa del archivo de configuraciones `config.ini` necesario para la ejecución de procesar.py |
| `--version` | `-v` | Muestra la versión del script |

## 5. Archivos indispensables para la ejecución

- **`procesar.py`**: el script en sí.
- **`ConfiguracionesProcesaConexiones.txt`**: configuraciones concretas utilizadas para lanzar `procesaConexiones`. Se establece en el config.ini.
- **`config.ini`**: archivo de configuraciones de `procesar.py`. Debe definir los siguientes valores:
  - `plantillaConfiguracionesProcesaConexiones`: ruta del fichero `ConfiguracionesProcesaConexiones.txt`, que contiene todas las configuraciones de `procesaConexiones`. Es una plantilla que se rellena con los parámetros de entrada provistos al lanzar el script de extracción.
  - `rutaBinarioProcesaConexiones`: ruta concreta del binario de `procesaConexiones`. Útil para probar distintas versiones.
  - `rutaBinarioTseries`: ruta concreta del binario de `tseries`. Útil para probar distintas versiones.
  - `rutaModulosProcesaConexiones`: directorio en el que se hallan los módulos de `procesaConexiones`.
> ⚠️ **Nota:** Hay dos config.ini en este repositorio:
>- **`config.ini`**: Configuraciones locales, @TLM83.
>- **`trazas/config.ini`**: Configuraciones para @trazas.
## 6. Resultado de la ejecución

```
SerialId_FirstTimestamp/
├── index.json
├── script_20260524_173717.log
└── 20171215-113439/
    ├── globals.txt
    ├── ConfiguracionesProcesaConexiones.txt
    ├── filtrosBpfModuloTseriesProcesaConexiones.txt
    ├── procesaConexiones.log
    ├── salida_tcp, salida_udp, ...
    ├── salidaModuloTseries_serie_.txt
    ├── filtrosBpfTseries.txt
    ├── listaFicherosGzTseries.txt
    ├── tseries.log
    └── salidaTseries.txt
```

### `SerialId_FirstTimestamp/`

Directorio raíz de salida. Contiene subdirectorios que siguen la misma estructura que el directorio de origen, más los siguientes archivos:

- **`index.json`**: índice o resumen del disco. Contiene información relevante como el número de serie, carpetas, espacio ocupado, timestamps...
- **`script_20260524_173717.log`** (nombre de ejemplo): logs del script extractor. Contienen información relevante como los comandos exactos de `procesaConexiones` y `tseries` que se han ejecutado.

### `SerialId_FirstTimestamp/20171215-113439/` (ejemplo)

Directorio espejo del subdirectorio original. Será único por cada subdirectorio de origen; podrían encontrarse dos espejos para aquellos discos en los que la captura de paquetes paró y reinició.

- **`globals.txt`**: estadísticas globales de `procesaConexiones`.
- **`ConfiguracionesProcesaConexiones.txt`**: configuraciones concretas utilizadas para lanzar `procesaConexiones`.
- **`filtrosBpfModuloTseriesProcesaConexiones.txt`**: filtros BPF aplicados al módulo tseries de `procesaConexiones`, con el identificador de cada serie temporal resultante.
- **`procesaConexiones.log`**: logs de la herramienta `procesaConexiones`.
- **`salida_tcp`, `salida_udp`, ...**: archivos de registros de flujo de `procesaConexiones`.
- **`salidaModuloTseries_serie_.txt`**: series resultantes de ejecutar el módulo tseries de `procesaConexiones`.
- **`filtrosBpfTseries.txt`**: filtros BPF referenciados al lanzar el comando de la herramienta `tseries`. No están asociados a los identificadores de las series resultantes; esa referencia está en `tseries.log`.
- **`listaFicherosGzTseries.txt`**: lista de ficheros `.pcap` a analizar por la herramienta `tseries`, referenciada directamente en el comando `tseries` lanzado.
- **`tseries.log`**: filtros BPF implementados en la herramienta `tseries`, junto al identificador de serie al que se relacionan.
- **`salidaTseries.txt`**: series resultantes de ejecutar la herramienta `tseries`.

## 7. Ejemplos de ejecución

### @TLM83

```bash
python3 procesar.py \
  --rutaOrigen /opt3/proyectistas/adur.albizu/VirtualBoxVM/raw/20171215-113439/ \
  --rutaDestino /opt3/proyectistas/adur.albizu/VirtualBoxVM/processed/20171215-113439 \
  --rutaConfig /opt3/proyectistas/adur.albizu/VirtualBoxVM/Scripts/TFM_Adur_Albizu/Extraccion/config.ini
```

### @trazas

```bash
python3 procesar.py \
  --rutaOrigen /trazas1 \
  --rutaDestino /opt2/adur \
  --rutaConfig /opt3/proyectistas/adur.albizu/Desktop/tarea_03_03/ScriptProcesado/config.ini
```