# Mantenimiento automatizado de reglas de firewall con IA agéntica

## Problema

Las políticas de firewall crecen pero casi nunca se limpian. Con el tiempo se acumulan reglas sin ningún hit desde hace meses, reglas demasiado amplias (any/any, redes /8 o /16, servicio "ALL"), objetos que apuntan a redes ya retiradas y permisos de protocolos prohibidos por la normativa interna que nadie ha vuelto a revisar. Auditar esto a mano en varios ADOMs de FortiManager y dominios de Check Point es lento, requiere cruzar datos de tres o cuatro herramientas y el criterio varía según el analista.

## Solución

Un agente integrado en el netsec-dashboard que, de forma periódica, revisa las políticas de FortiManager y Check Point y genera propuestas de cambio justificadas. Para cada regla devuelve:

- Tipo de hallazgo: sin uso / demasiado amplia / red obsoleta / protocolo prohibido / regla en sombra
- Evidencia concreta: hits y último uso, tráfico real observado en logs, estado del objeto en IPAM y CMDB
- Nivel de confianza y nivel de riesgo del cambio
- **Cambio propuesto con alcance mínimo**: deshabilitar la regla, sustituir la red amplia por las subredes realmente usadas, eliminar el objeto obsoleto, o retirar el protocolo prohibido
- Acción recomendada: aplicar, revisar con el owner, mantener con excepción documentada

Además genera un resumen ejecutivo por ADOM/dominio: número de reglas afectadas, porcentaje de any/any, redes retiradas detectadas y protocolos prohibidos aún permitidos.

## Cómo funciona

La clave es que el LLM no decide qué borrar: orquesta herramientas deterministas y redacta la justificación. El sistema:

1. **Recoge los datos con código, no con el modelo**: reglas y contadores de hits (conectores fortimanager.py y checkpoint ya existentes), logs de tráfico de 90–180 días desde Elasticsearch agregados por regla, redes activas en IPAM, hosts vivos en la CMDB y la lista corporativa de protocolos prohibidos.
2. **Ejecuta los análisis como tools registradas** en el bucle de function calling del agente: `unused_rules`, `overly_broad_rules`, `stale_networks`, `shadowed_rules`, `forbidden_protocols`. Cada una devuelve hallazgos con su evidencia.
3. **El LLM corporativo (LLM@CIB, sin que los datos salgan del banco)** agrupa los hallazgos, prioriza, redacta la justificación en lenguaje claro y construye el diff exacto del cambio.
4. **Valida el cambio antes de proponerlo** lanzando el preview de policy package (FortiManager) o el verify (Check Point) para confirmar que el paquete compila.

Los conteos, hits y cifras del informe los calcula el propio código, no el modelo, para que sean exactos y auditables.

## Salvaguardas

El diseño es conservador por defecto:

- **Nunca se aplica un cambio sin aprobación humana**: cada propuesta abre un ticket en ServiceNow con el diff y la evidencia, y lo ejecuta el agente solo tras la aprobación del owner de la regla.
- Las reglas se **deshabilitan antes de borrarse**; el borrado definitivo se propone a los 30 días si no ha habido incidencias.
- Lista de reglas intocables (DR, backup, monitorización) marcadas por etiqueta en la propia regla, que el agente nunca toca.
- El análisis de "sin uso" considera tráfico estacional: para ciertas VLANs se amplía la ventana a 6–12 meses antes de marcar la regla.
- Cada cambio instalado genera una revisión con comentario que referencia el ticket, y el agente **vigila los denies nuevos durante 48 h**; si aparecen drops sobre lo retirado, propone el rollback a la revisión anterior.
- Si la evidencia es débil (pocos logs, objeto sin correspondencia clara en IPAM), el hallazgo se marca como **"requiere revisión manual"**, nunca como "seguro de eliminar".
- Todas las decisiones del agente quedan registradas (tools llamadas, datos usados, propuesta) para auditoría y para evaluar la calidad del modelo.

## Despliegue

Fase 1 en solo lectura sobre el ADOM AD-TEST y el dominio ukcmaint generando informes, midiendo precisión de los hallazgos durante unas semanas. Fase 2 con creación de tickets. Fase 3 con ejecución tras aprobación.

## Beneficio

- Reduce la auditoría de políticas de semanas a horas y la hace continua en lugar de puntual.
- Reduce la superficie de ataque de forma medible: reglas retiradas, any/any eliminados, protocolos prohibidos cerrados.
- Hace la limpieza **homogénea y trazable** entre analistas y ejecuciones, con evidencia verificable en cada cambio.
- Facilita el cumplimiento normativo y las auditorías, al tener justificación documentada de cada regla que se mantiene o se retira.
