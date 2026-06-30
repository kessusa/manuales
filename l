.table-scroll {
    position: relative;
    max-height: 400px;
    overflow-y: auto;
    overflow-x: auto;
}

#avi_waf_table thead th {
    position: sticky;
    top: 0;
    background: #fff !important;
    background-image: none !important;
    z-index: 100;
}

#avi_waf_table tbody td.sticky-col {
    position: sticky;
    background: #fff !important;
    background-image: none !important;
    z-index: 10;
}

#avi_waf_table thead th.sticky-col:nth-child(1),
#avi_waf_table tbody td.sticky-col:nth-child(1) {
    left: 0;
    width: 60px;
    min-width: 60px;
    max-width: 60px;
    z-index: 120;
}

#avi_waf_table thead th.sticky-col:nth-child(2),
#avi_waf_table tbody td.sticky-col:nth-child(2) {
    left: 60px;
    width: 510px;
    min-width: 510px;
    max-width: 510px;
    z-index: 119;
}
