<style>
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

.avi-waf-scroll thead th { position: sticky; top: 0; z-index: 2; }
.avi-waf-scroll tbody td.sticky-col { z-index: 1; }
.avi-waf-scroll thead th.sticky-col { z-index: 3; }

/* Base opaca (blanco) + color que Bootstrap da a la fila por encima.
   Así el rayado gris de table-striped se copia igual, sin inventar tono. */
.avi-waf-scroll thead th.sticky-col,
.avi-waf-scroll tbody td.sticky-col {
  background-color: #fff;
  background-image: linear-gradient(var(--bs-table-bg, transparent),
                                    var(--bs-table-bg, transparent));
}

/* Fila seleccionada: verde en TODA la fila, fijas incluidas */
.avi-waf-scroll tbody tr.selected > td {
  background-color: #d1e7dd !important;
  background-image: none !important;   /* anula el gradiente para que mande el verde */
}
</style>
