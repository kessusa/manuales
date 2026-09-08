# Automatización del análisis de logs WAF con IA

## Problema

Antes de poner una política WAF en producción hay que revisar manualmente miles de eventos (25.000 líneas en un export típico) para separar ataques reales de falsos positivos y decidir qué excepciones aplicar. Es un trabajo lento, repetitivo y difícil de mantener consistente entre analistas.

## Solución

Un módulo integrado en el netsec-dashboard que toma el Excel del search visual de AVI y devuelve el mismo fichero enriquecido, con 16 campos de análisis por línea:

- Clasificación: ataque / falso positivo / benigno / desconocido
- Nivel de confianza (ataque y falso positivo) y nivel de riesgo
- Tipo de ataque (SQLi, XSS, RCE, path traversal, scanner…)
- Evidencia concreta extraída del log y análisis del experto
- Impacto en producción y acción recomendada (permitir, bloquear, monitorizar, investigar, parchear)
- **Excepción AVI WAF sugerida** con su alcance mínimo: URL, parámetro, cookie o regla concreta
- Recomendación de corrección en la aplicación cuando el log apunta a una vulnerabilidad real

Además genera una hoja de resumen ejecutivo con patrones detectados, principales orígenes de ataque, reglas que más falsos positivos causan y cambios de política recomendados.

## Cómo funciona

La clave para que sea viable a esta escala es que los logs WAF son muy repetitivos. El sistema:

1. **Agrupa los eventos en "firmas" únicas** (regla + path + elemento que disparó el match), normalizando los valores variables como identificadores, timestamps y query strings.
2. **Analiza cada firma una sola vez** con el LLM corporativo (LLM@CIB, sin que los datos salgan del banco), en lotes y con reintentos automáticos.
3. **Propaga el veredicto** a todas las líneas de esa firma.

Así, 25.000 eventos se reducen a unas decenas de análisis reales. Los conteos y agregados del informe los calcula el propio código, no el modelo, para que las cifras sean exactas.

## Salvaguardas

El diseño es conservador por defecto:

- Si la evidencia es débil, la línea se marca como **"requiere revisión manual"**, nunca como "seguro de excluir".
- No se proponen exclusiones globales de reglas salvo justificación clara: se prioriza siempre la excepción más estrecha posible.
- El resultado es **una propuesta para revisión humana**, no un cambio automático en el WAF.
- Cada veredicto cita la evidencia concreta del log (regla, URI, parámetro, IP origen), de modo que es verificable.

## Beneficio

- Reduce de días a minutos la primera pasada de análisis.
- Hace la revisión **homogénea y trazable** entre analistas y entre ejecuciones.
- Acelera el paso de las políticas WAF de modo detección a modo bloqueo, que es el objetivo del proyecto.
