/* ===== WAF Sticky Columns ===== */

#avi_waf_table thead th {
    position: sticky;
    top: 0;
    background: #fff !important;
    background-image: none !important;
    z-index: 20;
    box-sizing: border-box;
}

#avi_waf_table tbody td.sticky-col {
    position: sticky;
    background: #fff !important;
    background-image: none !important;
    box-sizing: border-box;
    z-index: 10;
}

/* Primera columna (checkbox) */

#avi_waf_table thead th.sticky-col:nth-child(1),
#avi_waf_table tbody td.sticky-col:nth-child(1) {
    left: 0;
    width: 60px;
    min-width: 60px;
    max-width: 60px;
    z-index: 50;
}

/* Segunda columna (URL) */

#avi_waf_table thead th.sticky-col:nth-child(2),
#avi_waf_table tbody td.sticky-col:nth-child(2) {
    left: 60px;
    width: 510px;
    min-width: 510px;
    max-width: 510px;
    z-index: 49;
}

/* Mantener el color de las filas seleccionadas */

#avi_waf_table tbody tr.selected td.sticky-col,
#avi_waf_table tbody tr.table-success td.sticky-col {
    background: #d1e7dd !important;
    background-image: none !important;
}
