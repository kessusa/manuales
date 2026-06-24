.table-scroll {
  scrollbar-width: none;
  -ms-overflow-style: none;
  position: relative;
  max-height: 500px;
  overflow-y: auto;
  overflow-x: auto;
}

/* 1ª columna: checkbox */
.table-scroll th.sticky-col:nth-child(1),
.table-scroll td.sticky-col:nth-child(1) {
  position: sticky;
  left: 0;
  min-width: 60px;
  background: #fff;
  box-sizing: border-box;
  z-index: 2;
}

/* tapa la ranura fina del borde izquierdo */
.table-scroll th.sticky-col:nth-child(1)::before,
.table-scroll td.sticky-col:nth-child(1)::before {
  content: "";
  position: absolute;
  top: 0;
  bottom: 0;
  left: -8px;
  width: 8px;
  background: #fff;
}

/* 2ª columna: URL */
.table-scroll th.sticky-col:nth-child(2),
.table-scroll td.sticky-col:nth-child(2) {
  position: sticky;
  left: 60px;
  min-width: 150px;
  background: #fff;
  box-sizing: border-box;
  z-index: 2;
}

/* cabecera fija por encima del cuerpo donde se cruzan */
.table-scroll thead th.sticky-col {
  z-index: 3;
}
