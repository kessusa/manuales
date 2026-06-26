<style>
/* ===== Posición de las columnas fijas ===== */
.avi-waf-scroll th.sticky-col:nth-child(1),
.avi-waf-scroll td.sticky-col:nth-child(1) {
  position: sticky; left: 0;
  width: 60px; min-width: 60px; max-width: 60px;
  box-sizing: border-box;
}
.avi-waf-scroll th.sticky-col:nth-child(2),
.avi-waf-scroll td.sticky-col:nth-child(2) {
  position: sticky; left: 60px;      /* = ancho de la columna 1 */
  min-width: 150px;
  box-sizing: border-box;
}

/* ===== Cabecera fija ===== */
.avi-waf-scroll thead th { position: sticky; top: 0; z-index: 2; }

/* ===== Capas ===== */
.avi-waf-scroll tbody td.sticky-col  { z-index: 1; }
.avi-waf-scroll thead th.sticky-col  { z-index: 3; }

/* ===== Color de cada fila (la variable que heredan las columnas fijas) ===== */
.avi-waf-scroll thead th { --row-bg: #fff; }
.avi-waf-scroll tbody tr { --row-bg: #fff; }
.avi-waf-scroll tbody tr:nth-child(even) { --row-bg: #f2f2f2; }                  /* rayado */
.avi-waf-scroll tbody tr:has(.form-check-input:checked) { --row-bg: #c8e6c9; }  /* TU verde */

/* Pinta todas las celdas con el color de su fila */
.avi-waf-scroll thead th,
.avi-waf-scroll tbody td { background: var(--row-bg); }

/* Columnas fijas: mismo color + tapa la rendija de 1px a los lados */
.avi-waf-scroll th.sticky-col,
.avi-waf-scroll td.sticky-col {
  box-shadow: -1px 0 0 0 var(--row-bg), 1px 0 0 0 var(--row-bg);
}
</style>
