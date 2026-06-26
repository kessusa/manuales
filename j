<style>
/* Posición de las dos columnas fijas */
.avi-waf-scroll th.sticky-col:nth-child(1),
.avi-waf-scroll td.sticky-col:nth-child(1) {
  position: sticky; left: 0;
  width: 60px; min-width: 60px; max-width: 60px;
  box-sizing: border-box;
}
.avi-waf-scroll th.sticky-col:nth-child(2),
.avi-waf-scroll td.sticky-col:nth-child(2) {
  position: sticky; left: 60px;
  min-width: 150px;
  box-sizing: border-box;
}

/* Cabecera fija + capas */
.avi-waf-scroll thead th { position: sticky; top: 0; z-index: 2; }
.avi-waf-scroll tbody td.sticky-col { z-index: 1; }
.avi-waf-scroll thead th.sticky-col { z-index: 3; }

/* Las celdas fijas toman el MISMO color que Bootstrap aplica a la fila.
   --bs-table-bg lo define Bootstrap (blanco normal, gris en striped,
   verde en table-success). Con el fallback #fff cubrimos filas sin variable. */
.avi-waf-scroll th.sticky-col,
.avi-waf-scroll td.sticky-col {
  background-color: var(--bs-table-bg, #fff);
  box-shadow: -1px 0 0 0 var(--bs-table-bg, #fff),
               1px 0 0 0 var(--bs-table-bg, #fff);
}
</style>
