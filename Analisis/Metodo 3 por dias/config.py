import ipaddress

COL_SRC_IP_TCP = 0   # Direccion IP del cliente de la conexion
COL_SRC_PORT_TCP = 1 # Puerto empleado por el cliente 
COL_DST_IP_TCP = 2   # Direccion IP del servidor de la conexion
COL_DST_PORT_TCP = 3 # Puerto empleado por el servidor 

COL_FIRSTPACKETTIME_TCP = 4 # timestamp del primer paquete de la conexion
COL_LASTPACKETTIME_TCP = 5 # timestamp del ultimo paquetes de la conexion
COL_LASTSRC2DST_TCP = 14 # timestamp del ultimo paquete de cliente a servidor  
COL_LASTDST2SRC_TCP = 15 # timestamp del ultimo paquete de servidor a cliente

COL_NUMPACKETS_SRC2DST_TCP = 16 # numero de paquetes de cliente a servidor (*1)
COL_NUMPACKETS_DST2SRC_TCP = 17 # numero de paquetes de servidor a cliente (*1)
COL_NUMSYNS_SRC2DST_TCP =  18 # numero de SYNs de cliente a servidor (*1)
COL_NUMSYNS_DST2SRC_TCP =  19 # numero de SYNs de servidor a cliente (*1)
COL_NUMFINS_SRC2DST_TCP =  20 # numero de FINs de cliente a servidor
COL_NUMFINS_DST2SRC_TCP =  21 # numero de FINs de servidor a cliente
COL_NUMRST_SRC2DST_TCP =  22 #  numero de RSTs de cliente a servidor 
COL_NUMRST_DST2SRC_TCP =  23 #  numero de RSTs de servidor a cliente
COL_NUMPACKETSDATA_SRC2DST_TCP = 24 # numero de paquetes con datos de cliente a servidor (*1)
COL_NUMPACKETSDATA_DST2SRC_TCP = 25 # numero de paquetes con datos de servidor a cliente (*1)

COL_FIRSTACK_SRC2DST_TIME_TCP = 8 #timestamp del primer ACK de cliente a servidor (-1 si no hay tal paquete)
COL_FIRSTACK_DST2SRC_TIME_TCP = 9#timestamp del primer ACK del servidor al cliente (-1 si no hay tal paquete)  
COL_FIRSTSYN_SRC2DST_TIME = 6 #timestamp del primer SYN de cliente a servidor 

COL_TCPBYTES_SD_TCP = 36  #bytesIPSrcToDst numero de paquetes de cliente a servidor 
COL_TCPBYTES_DS_TCP = 37  #bytesIPDstToSrc

COL_FIRSTPACKETFLAGS_TCP = 48 # Flags del primer paquete que se ve (en hexadecimal), que si hay desorden puede no ser el primero de la conexion. 

COL_SRC_IP_UDP = 0
COL_SRC_PORT_UDP = 1
COL_DST_IP_UDP = 2
COL_DST_PORT_UDP = 3
COL_FIRSTPACKETTIME_UDP = 4 # timestamp del primer paquete de la conexion
COL_LASTPACKETTIME_UDP = 5 # timestamp del ultimo paquete de la conexion
COL_UDPBYTES_SD_UDP = 44
COL_UDPBYTES_DS_UDP = 45

# Cadenas que identifican a los archivos de entrada, y nombre del archivo de salida
PATRON_TCP = "_tcp_"
PATRON_UDP = "_udp_"
ARCHIVO_RESULTADO = "resultado_alt.txt"
ARCHIVO_RESULTADO_JSON = "resultado_metodo3.json"
ARCHIVO_ESTADISTICAS_POR_DIA = "estadisticas_por_dia.txt"

# Zona horaria con la que se decide a qué día pertenece cada registro de flujo
ZONA_HORARIA_DIAS = "Europe/Madrid"

THRESHOLD_PUERTOS_UNICOS = 10 # Limite por encima del cual considero que una conversación podría ser un escaneo
THRESHOLD_ENTROPIA = -0.10 # Limite de h por encima del cual considero que una conversación podría ser un escaneo
THRESHOLD_PROPORCION_SONDEOS_TCP = 0.9 # La proporción de flujos TCP compatibles con un sondeo debe superar este valor
THRESHOLD_PROPORCION_SONDEOS_UDP = 0.9 # Proporción mínima de flujos UDP sin respuesta

# Ventana temporal 
INTERVALO_ESCANEOS_DIFERENTES = 30 #Intervalo a partir del cual separo dos escaneos a una misma IP

# Ventana del buffer de reordenado: cuanto mayor, más desorden tolera a costa de más memoria
VENTANA_REORDENADO = 7200

#Rangos internos IP de la uni: 130.206.158.0 - 130.206.175.255
RANGOS_INTERNOS =["130.206.158.0/23", #130.206.158.0 - 130.206.159.255 
                  "130.206.160.0/20"] #130.206.160.0 - 130.206.175.255

REDES_INTERNAS = [ipaddress.ip_network(r, strict=False) for r in RANGOS_INTERNOS]
