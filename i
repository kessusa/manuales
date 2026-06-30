.table-scroll {
    position: relative;
    height: 400px;
    max-height: 400px;
    overflow-y: auto;
    overflow-x: auto;
}

#avi_waf_table thead th {
    position: sticky !important;
    top: 0 !important;
    background: #fff !important;
    background-image: none !important;
    z-index: 1000 !important;
}

/* body sticky columns */
#avi_waf_table tbody td.sticky-col {
    position: sticky !important;
    background: #fff !important;
    background-image: none !important;
    box-sizing: border-box;
}

/* checkbox BODY */
#avi_waf_table tbody td.sticky-col:nth-child(1) {
    left: 0 !important;
    width: 60px !important;
    min-width: 60px !important;
    max-width: 60px !important;
    z-index: 100 !important;
}

/* URL BODY */
#avi_waf_table tbody td.sticky-col:nth-child(2) {
    left: 60px !important;
    width: 510px !important;
    min-width: 510px !important;
    max-width: 510px !important;
    z-index: 99 !important;
}

/* checkbox HEADER: top + left + z-index MUY ALTO */
#avi_waf_table thead th.sticky-col:nth-child(1) {
    position: sticky !important;
    top: 0 !important;
    left: 0 !important;
    width: 60px !important;
    min-width: 60px !important;
    max-width: 60px !important;
    background: #fff !important;
    background-image: none !important;
    z-index: 3000 !important;
}

/* URL HEADER: top + left + z-index MUY ALTO */
#avi_waf_table thead th.sticky-col:nth-child(2) {
    position: sticky !important;
    top: 0 !important;
    left: 60px !important;
    width: 510px !important;
    min-width: 510px !important;
    max-width: 510px !important;
    background: #fff !important;
    background-image: none !important;
    z-index: 2999 !important;
}

/* selected rows */
#avi_waf_table tbody tr.selected > td,
#avi_waf_table tbody tr.table-success > td {
    background-color: #d1e7dd !important;
    background-image: none !important;
}

#avi_waf_table tbody tr.selected > td.sticky-col,
#avi_waf_table tbody tr.table-success > td.sticky-col {
    background-color: #d1e7dd !important;
    background-image: none !important;
}
