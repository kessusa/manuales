# Agente de IA para el análisis automático de incidencias de red

**Estado:** prototipo funcional (PoC) · **Ámbito actual:** incidencias de conectividad EMEA

---

## 1. El problema

Una parte significativa de las incidencias que llegan a NetSec por ServiceNow son
del mismo tipo: *"no tengo conectividad de A hacia B"*. El diagnóstico es casi
siempre el mismo procedimiento manual:

1. Leer el ticket y extraer IP origen, IP destino, protocolo y puerto.
2. Localizar en la topología qué firewall/zona cubre esas IPs.
3. Comprobar en Playflows si existe una regla que permita ese flujo.
4. Concluir: o el firewall bloquea (hay que pedir regla) o el firewall permite
   y el problema está en el endpoint o la aplicación.

Es un trabajo repetitivo, de bajo valor añadido y que consume tiempo de perfiles
Tier 3. Además, una parte de esos tickets acaba concluyendo que **el firewall no
era el problema**: tiempo invertido en descartar.

## 2. La propuesta

Un agente de IA que ejecuta ese mismo procedimiento de forma autónoma y deja en
el ticket un análisis técnico con causa raíz y siguientes pasos.

La clave del diseño es **dónde ponemos la inteligencia**. El modelo de lenguaje
no decide si una regla permite o no el tráfico: eso lo decide Playflows, que es
la fuente de verdad. El modelo se encarga de lo que sí sabe hacer bien:
interpretar el texto libre del ticket, decidir qué herramienta usar y redactar
la conclusión en lenguaje profesional.

```
Ticket ServiceNow
      │
      ▼
[Extracción]  IPs, protocolo y puerto desde el texto libre del ticket
      │
      ▼
[Agente]  decide qué herramienta llamar ──► Playflows (check_flow)
      │                                     devuelve la regla exacta,
      │  ◄──────────────────────────────    su posición y su acción
      ▼
[Conclusión]  Causa raíz + detalle técnico + siguientes pasos
```

## 3. Qué está ya funcionando

- **Conexión con el LLM corporativo** vía *function calling* nativo: el modelo
  invoca herramientas de forma estructurada, sin interpretación de texto libre.
  Verificado contra nuestro gateway interno.
- **Lectura del ticket en ServiceNow** y extracción automática del flujo de red
  a partir de la descripción y las work notes.
- **Herramienta `check_flow`** sobre Playflows: dadas origen, destino y servicio,
  devuelve la regla que hace match, su posición, su tag y si permite o bloquea.
  Resuelve el caso en una sola consulta, sin listar ni interpretar reglas.
- **Bucle de investigación con salvaguardas**: control de iteraciones, caché de
  consultas repetidas y reintento ante errores.

Probado extremo a extremo con un ticket real de RDP (tcp-3389): el agente extrae
el flujo, consulta Playflows, identifica la regla que lo permite y redacta el
análisis.

## 4. Arquitectura pensada para crecer

El agente está construido sobre un **registro de herramientas**. Añadir una
capacidad nueva consiste en registrar una función; el agente aprende a usarla
automáticamente, sin tocar su lógica interna.

| Fase | Herramienta | Qué permite responder |
|------|-------------|------------------------|
| Hecho | Playflows | ¿Hay regla de firewall para este flujo? |
| Siguiente | Elasticsearch | ¿Qué dicen los logs? ¿Se ve el tráfico? ¿Se está denegando? |
| Después | WAF / AVI | ¿El bloqueo viene del WAF y no de la red? |
| Después | AbuseIPDB | ¿La IP origen tiene reputación maliciosa? |

Cada herramienta nueva multiplica los tipos de incidencia que el agente puede
cerrar por sí solo, reutilizando todo lo ya construido.

## 5. Qué podemos conseguir

- **Triaje automático**: el agente analiza la incidencia en cuanto entra y deja
  el diagnóstico en el ticket, de modo que el ingeniero abre un caso ya
  documentado en lugar de uno en blanco.
- **Descarte rápido de falsos positivos de red**: cerrar o redirigir sin
  intervención los casos donde el firewall ya permite el tráfico.
- **Homogeneidad**: mismo procedimiento y mismo nivel de detalle en todos los
  análisis, con independencia de quién esté de guardia.
- **Trazabilidad**: cada conclusión queda respaldada por las consultas concretas
  que la sustentan (regla, posición, tag), no por una opinión del modelo.
- **Base reutilizable**: la arquitectura sirve para cualquier flujo de trabajo
  de NetSec que hoy sea "consultar varias herramientas y concluir".

## 6. Garantías de control

- **El agente no modifica nada**: solo consulta. No abre, cambia ni cierra
  reglas; las peticiones de cambio siguen el circuito habitual de aprobación.
- **La decisión técnica no la toma el modelo**, la toma Playflows. El modelo
  transporta e interpreta, no infiere el estado del firewall.
- **Validación humana**: en la primera fase el análisis se propone como
  sugerencia, y el ingeniero valida antes de que se publique en el ticket.
- **Solo herramientas y datos internos**: se apoya en las APIs corporativas ya
  existentes y en el LLM interno.

## 7. Siguientes pasos propuestos

1. **Validación en volumen**: ejecutar el agente contra un lote de incidencias ya
   cerradas y comparar su conclusión con la resolución real. Nos da una medida
   objetiva de fiabilidad antes de ponerlo delante de nadie.
2. **Integrar Elasticsearch** para cubrir los casos donde la red permite el
   tráfico pero el problema se ve en los logs.
3. **Piloto acotado**: activar el triaje automático sobre una categoría concreta
   de tickets, con validación humana previa a la publicación.
4. **Medición**: tiempo de diagnóstico y porcentaje de incidencias resueltas o
   correctamente redirigidas sin intervención manual.

---

*Documento de trabajo. El prototipo es funcional pero está en fase de
validación; las cifras de impacto se obtendrán en el paso 1.*
