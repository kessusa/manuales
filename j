    <div class="d-flex align-items-center mb-2">
        <p class="mb-0 me-auto">
            <span class="fw-bold">{{ group_name }}</span> found on {{ firewalls|length }} firewall{{ firewalls|length|pluralize }} ·
            {% if differing_count %}
                <span class="text-danger">{{ differing_count }} differ{{ differing_count|pluralize:"s," }} from {{ reference_tag }}</span>
            {% else %}
                <span class="text-success">all identical to {{ reference_tag }}</span>
            {% endif %}
        </p>
        <a class="btn btn-sm btn-outline-primary"
           href="{% url 'download_csv_stream_report' 'EXPORT_GROUP_COMPARATOR' %}?{% url_replace request 'ajax' False %}">
            <i class="fas fa-file-csv me-1"></i>Export CSV
        </a>
    </div>
