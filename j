/* base */
.table-scroll td.sticky-col,
.table-scroll th.sticky-col {
  position: sticky;
  background: var(--bs-body-bg, #fff);
  box-sizing: border-box;
  z-index: 2;
}
.table-scroll th.sticky-col:nth-child(1),
.table-scroll td.sticky-col:nth-child(1) { left: 0; min-width: 60px; }
.table-scroll th.sticky-col:nth-child(2),
.table-scroll td.sticky-col:nth-child(2) { left: 60px; min-width: 150px; }

/* franja gris del striped */
.table-scroll tbody tr:nth-of-type(odd) td.sticky-col {
  background: var(--bs-table-striped-bg, #f2f2f2);
}

/* fila seleccionada (verde) */
.table-scroll tbody tr.table-success td.sticky-col {
  background: var(--bs-success-bg-subtle, #d1e7dd);
}

/* tapa la ranura con el color correcto de cada celda */
.table-scroll td.sticky-col::before,
.table-scroll th.sticky-col::before {
  content: "";
  position: absolute;
  top: 0;
  bottom: 0;
  left: -8px;
  width: 8px;
  background: inherit;
  z-index: -1;
}

/* cabecera por encima */
.table-scroll thead th.sticky-col { z-index: 3; }
