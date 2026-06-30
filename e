.table-scroll {
    position: relative;
    max-height: 400px;
    overflow-y: auto;
    overflow-x: auto;
}

#avi_waf_table {
    border-collapse: separate !important;
    border-spacing: 0;
}

#avi_waf_table thead {
    position: sticky;
    top: 0;
    z-index: 100;
}

#avi_waf_table thead th {
    background: #fff !important;
    background-image: none !important;
}

#avi_waf_table th.sticky-col:nth-child(1),
#avi_waf_table td.sticky-col:nth-child(1) {
    position: sticky;
    left: 0;
    width: 60px;
    min-width: 60px;
    max-width: 60px;
    background: #fff !important;
    z-index: 120;
}

#avi_waf_table th.sticky-col:nth-child(2),
#avi_waf_table td.sticky-col:nth-child(2) {
    position: sticky;
    left: 60px;
    width: 510px;
    min-width: 510px;
    max-width: 510px;
    background: #fff !important;
    z-index: 119;
}
