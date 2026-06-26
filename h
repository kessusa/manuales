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

/* Columnas fijas = MISMO color que el resto de la fila, en todos los estados */
.avi-waf-scroll th.sticky-col,
.avi-waf-scroll td.sticky-col {
  /* base blanca opaca: tapa lo que pasa por debajo al hacer scroll */
  background-color: #fff;
  /* encima, repinto el color que Bootstrap da a la fila:
     capa de abajo = variante (verde de table-success)
     capa de arriba = rayado/selección (cubro los nombres de variable de cada versión de BS) */
  background-image:
    linear-gradient(
      var(--bs-table-accent-bg, var(--bs-table-bg-state, var(--bs-table-bg-type, transparent))),
      var(--bs-table-accent-bg, var(--bs-table-bg-state, var(--bs-table-bg-type, transparent)))
    ),
    linear-gradient(var(--bs-table-bg, transparent), var(--bs-table-bg, transparent));
}
</style>
