} else if ($_selected_option === "group_lookup") {

    // Hide all other sections
    $('#main-single-search, #main-multiple-search, #main-secure-change-search, #main-whoswho-search, #main-sref-search, #main-frida-ar-section, #main-frida-port-section, #main-iv2-search').addClass('d-none');

    // Show Group lookup section
    $('#main-group-lookup-search').removeClass('d-none');
    $('#group_lookup_search_value').text($_q_search);

    // Loader (replaced by the server response)
    $('#id_group_lookup_content').html(
        '<div id="id_group_lookup_loader" class="text-center">' +
        '    <div class="spinner-border spinner-border-sm text-secondary" role="status">' +
        '        <span class="sr-only">Loading...</span></div>' +
        '    <span class="text-secondary ps-2">Loading Group Data...</span>' +
        '</div>'
    );

    $.ajax({
        url: "{% url 'group_lookup_search' %}",
        data: {q_search: $_q_search},
        success: function (data) {
            $('#id_group_lookup_content').empty().html(data);
        },
        error: function () {
            $('#id_group_lookup_content').empty().append(
                '<div class="col-12 text-center">' +
                '    <small class="font-italic mb-2 text-xxs">' +
                '        <i class="fas fa-exclamation-triangle me-1"></i>' +
                'Internal Server Error !</small> </div>'
            );
        }
    });

} else {
