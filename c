#avi_waf_table th.sticky-col,
#avi_waf_table td.sticky-col {
    position: sticky;
    background-color: #fff !important;
    background-image: none !important;
    box-sizing: border-box;
    z-index: 10;
}

#avi_waf_table th.sticky-col:nth-child(1),
#avi_waf_table td.sticky-col:nth-child(1) {
    left: 0;
    width: 60px;
    min-width: 60px;
    max-width: 60px;
    z-index: 12;
}

#avi_waf_table th.sticky-col:nth-child(2),
#avi_waf_table td.sticky-col:nth-child(2) {
    left: 60px;
    width: 510px;
    min-width: 510px;
    max-width: 510px;
    z-index: 11;
}

#avi_waf_table thead th.sticky-col {
    z-index: 30;
}

#avi_waf_table tr.selected td.sticky-col,
#avi_waf_table tr.table-success td.sticky-col {
    background-color: #d1e7dd !important;
    background-image: none !important;
}

.table-scroll {
    position: relative;
    max-height: 500px;
    overflow-y: auto;
    overflow-x: auto;
}

#avi_waf_table thead th {
    position: sticky;
    top: 0;
    background-color: #fff;
    z-index: 20;
}

#avi_waf_table thead th.sticky-col {
    z-index: 40;
}
