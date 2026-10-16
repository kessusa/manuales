{% if mode == 'row' %}
    {# Table row of one group; includes itself for every subgroup #}
    <tr class="group-lookup-row" data-depth="{{ depth }}" data-name="{{ node.group_name }}">
        <td class="text-nowrap" style="padding-left: calc(0.75rem + {% widthratio depth 1 24 %}px);">
            {% if depth %}<span class="text-muted mr-1 me-1">&#9492;</span>{% endif %}
            <span class="font-weight-bold fw-bold{% if depth == 0 %} text-primary{% endif %}">{{ node.group_name }}</span>
        </td>
        <td class="text-nowrap text-muted">{{ parent_name|default:'-' }}</td>
        <td class="text-center">{{ depth }}</td>
        <td>
            {% for ip in node.ips %}
                <span class="badge badge-light bg-light text-dark border font-weight-normal fw-normal mr-1 me-1 mb-1">{{ ip }}</span>
            {% empty %}
                <span class="text-muted small font-italic fst-italic">Subgroups only</span>
            {% endfor %}
        </td>
        <td class="text-center">{{ node.ips|length }}</td>
    </tr>
    {% for child in node.subgroups %}
        {% with child_depth=depth|add:1 %}
            {% include 'search_components/group_lookup_component.html' with node=child depth=child_depth parent_name=node.group_name mode='row' %}
        {% endwith %}
    {% endfor %}

{% elif mode == 'text' %}
    {# Plain-text tree for the copy button: one .tree-line per group or IP #}
    <div class="tree-line">{{ line_prefix }}{{ node.group_name }}</div>
    {% for ip in node.ips %}
        <div class="tree-line">{{ child_prefix }}{% if forloop.last and not node.subgroups %}└── {% else %}├── {% endif %}{{ ip }}</div>
    {% endfor %}
    {% for child in node.subgroups %}
        {% if forloop.last %}
            {% with next_line_prefix=child_prefix|add:'└── ' next_child_prefix=child_prefix|add:'    ' %}
                {% include 'search_components/group_lookup_component.html' with node=child line_prefix=next_line_prefix child_prefix=next_child_prefix mode='text' %}
            {% endwith %}
        {% else %}
            {% with next_line_prefix=child_prefix|add:'├── ' next_child_prefix=child_prefix|add:'│   ' %}
                {% include 'search_components/group_lookup_component.html' with node=child line_prefix=next_line_prefix child_prefix=next_child_prefix mode='text' %}
            {% endwith %}
        {% endif %}
    {% endfor %}

{% elif error %}
    <div class="alert alert-warning mb-0">{{ error }}</div>

{% else %}
    <div class="d-flex justify-content-end mb-2">
        <button type="button" id="group-lookup-copy-btn" class="btn btn-sm btn-outline-secondary"
                title="Copy the group tree as plain text">
            <i class="fas fa-copy mr-1 me-1"></i>Copy tree
        </button>
    </div>

    <div class="table-responsive">
        <table class="table table-sm table-hover align-middle mb-0">
            <thead class="thead-light table-light">
            <tr>
                <th class="text-nowrap">Group</th>
                <th class="text-nowrap">Parent group</th>
                <th class="text-center">Level</th>
                <th>IPs</th>
                <th class="text-center text-nowrap"># IPs</th>
            </tr>
            </thead>
            <tbody>
            {% include 'search_components/group_lookup_component.html' with node=hierarchy depth=0 parent_name='' mode='row' %}
            </tbody>
        </table>
    </div>

    <div id="group-lookup-copy-content" class="d-none">
        {% include 'search_components/group_lookup_component.html' with node=hierarchy line_prefix='' child_prefix='' mode='text' %}
    </div>

    <script type="text/javascript">
        $('#group-lookup-copy-btn').click(function () {
            const lines = $('#group-lookup-copy-content .tree-line').map(function () {
                return this.textContent;
            }).get();

            const temp_element = document.createElement('textarea');
            temp_element.value = lines.join('\n');
            document.body.appendChild(temp_element);
            temp_element.select();
            document.execCommand('copy');
            document.body.removeChild(temp_element);

            iziToast.success({
                position: 'topRight',
                message: 'Text Copied',
            });
        });
    </script>
{% endif %}
