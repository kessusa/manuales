.table-scroll {
    height: 400px !important;
    max-height: 400px !important;
    overflow: auto !important;
    position: relative !important;
}

#avi_waf_table thead th {
    position: sticky !important;
    top: 0 !important;
    background: #fff !important;
    z-index: 1000 !important;
}

/* columnas fijas izquierda */
#avi_waf_table th.sticky-col:nth-child(1),
#avi_waf_table td.sticky-col:nth-child(1) {
    position: sticky !important;
    left: 0 !important;
    width: 60px !important;
    min-width: 60px !important;
    max-width: 60px !important;
    background: #fff !important;
    z-index: 1100 !important;
}

#avi_waf_table th.sticky-col:nth-child(2),
#avi_waf_table td.sticky-col:nth-child(2) {
    position: sticky !important;
    left: 60px !important;
    width: 510px !important;
    min-width: 510px !important;
    max-width: 510px !important;
    background: #fff !important;
    z-index: 1099 !important;
}

/* las cabeceras sticky izquierda necesitan top + left */
#avi_waf_table thead th.sticky-col:nth-child(1) {
    top: 0 !important;
    left: 0 !important;
    z-index: 2000 !important;
}

#avi_waf_table thead th.sticky-col:nth-child(2) {
    top: 0 !important;
    left: 60px !important;
    z-index: 1999 !important;
}
