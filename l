<div class="d-flex mb-3 fw-bold">
    <span class="me-auto"><i class="fas fa-arrow-right me-1"></i> Show result(s)</span>
    <button type="button" class="btn-close pf-close" aria-label="Close"></button>
</div>
{% if firewalls %}
    <p class="mb-2">
        <span class="fw-bold">{{ group_name }}</span> found on {{ firewalls|length }} firewall{{ firewalls|length|pluralize }} &middot;
        {% if differing_count %}
            <span class="text-danger">{{ differing_count }} differ{{ differing_count|pluralize:"s," }} from {{ reference_tag }}</span>
        {% else %}
            <span class="text-success">all identical to {{ reference_tag }}</span>
        {% endif %}
    </p>
    <div class="table-responsive">
        <table class="table table-sm table-bordered mb-0 align-middle">
            <thead>
                <tr class="text-nowrap">
                    <th scope="col">FW Tag</th>
                    <th scope="col">Status</th>
                    <th scope="col" class="text-end">Added</th>
                    <th scope="col" class="text-end">Missing</th>
                </tr>
            </thead>
            <tbody>
                {% for firewall in firewalls %}
                    {% if firewall.differences %}
                        <tr class="text-nowrap" role="button" data-bs-toggle="collapse" data-bs-target="#group-comparator-fw-{{ forloop.counter }}" aria-expanded="false">
                            <td>
                                <i class="fas fa-chevron-down me-1"></i>{{ firewall.fw_tag }}
                                <button type="button" class="btn btn-sm btn-outline-secondary ms-2 py-0 group-comparator-copy" data-copy-target="#group-comparator-commands-{{ forloop.counter }}" title="Copy alignment commands">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </td>
                            <td><span class="badge bg-danger">{{ firewall.differences|length }} group{{ firewall.differences|length|pluralize }} differ{{ firewall.differences|length|pluralize:"s," }}</span></td>
                            <td class="text-end text-success">{{ firewall.added_count }}</td>
                            <td class="text-end text-danger">{{ firewall.missing_count }}</td>
                        </tr>
                        <tr class="collapse" id="group-comparator-fw-{{ forloop.counter }}">
                            <td colspan="4" class="bg-light">
                                <label for="group-comparator-commands-{{ forloop.counter }}" class="small fw-bold">Alignment commands</label>
                                <textarea id="group-comparator-commands-{{ forloop.counter }}" class="form-control form-control-sm font-monospace mb-2" rows="3" readonly>{{ firewall.alignment_commands }}</textarea>
                                <table class="table table-sm mb-0">
                                    <thead>
                                        <tr class="text-nowrap">
                                            <th scope="col">Subgroup</th>
                                            <th scope="col">Added value</th>
                                            <th scope="col">Missing value</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for row in firewall.differences %}
                                            <tr>
                                                <td class="text-nowrap">{{ row.subgroup_path|join:" › "|default:"N/A" }}</td>
                                                <td class="text-success">
                                                    {% include 'tools/firewall_components/group_comparator_values.html' with values=row.added_values subgroups=row.added_subgroups %}
                                                </td>
                                                <td class="text-danger">
                                                    {% include 'tools/firewall_components/group_comparator_values.html' with values=row.missing_values subgroups=row.missing_subgroups %}
                                                </td>
                                            </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </td>
                        </tr>
                    {% else %}
                        <tr class="text-nowrap">
                            <td>{{ firewall.fw_tag }}</td>
                            <td>
                                {% if firewall.is_reference %}
                                    <span class="badge bg-secondary">Reference</span>
                                {% else %}
                                    <span class="badge bg-success">Identical</span>
                                {% endif %}
                            </td>
                            <td class="text-end text-muted">-</td>
                            <td class="text-end text-muted">-</td>
                        </tr>
                    {% endif %}
                {% endfor %}
            </tbody>
        </table>
    </div>
    <script>
        // Rebound on every load of this component; the namespace avoids duplicated handlers.
        $(document).off('click.groupComparatorCopy').on('click.groupComparatorCopy', '.group-comparator-copy', function (event) {
            event.stopPropagation();
            const button = $(this);
            const commands = $(button.data('copy-target')).val();
            const show_copied = function () {
                button.find('i').removeClass('fa-copy').addClass('fa-check');
                setTimeout(function () {
                    button.find('i').removeClass('fa-check').addClass('fa-copy');
                }, 1500);
            };

            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(commands).then(show_copied);
                return;
            }
            // Fallback for plain HTTP: the source textarea may be collapsed, so copy from a temporary one
            const temporary_textarea = $('<textarea>').val(commands).css({position: 'fixed', opacity: 0}).appendTo('body');
            temporary_textarea[0].select();
            document.execCommand('copy');
            temporary_textarea.remove();
            show_copied();
        });
    </script>
{% else %}
    <div class="row text-center">
        <span class="text-secondary fst-italic">
            {% if group_name and reference_tag %}
                Group {{ group_name }} was not found on {{ reference_tag }}.
            {% else %}
                No data is currently available.
            {% endif %}
        </span>
    </div>
{% endif %}
