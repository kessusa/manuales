{% if error %}
    <div class="alert alert-warning mb-0">{{ error }}</div>
{% else %}
    <div class="card w-100 border-0 shadow-sm">
        <div class="card-header bg-white d-flex flex-wrap align-items-center justify-content-between py-3">
            <div>
                <div class="text-muted small">Showing results for</div>
                <h5 class="mb-0 text-primary font-weight-bold fw-bold">{{ hierarchy.group_name }}</h5>
            </div>
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
                {% include 'search_components/group_lookup_node.html' with node=hierarchy depth=0 parent_name='' mode='row' %}
                </tbody>
            </table>
        </div>
    </div>

    <div id="group-lookup-copy-content" class="d-none">
        {% include 'search_components/group_lookup_node.html' with node=hierarchy line_prefix='' child_prefix='' mode='text' %}
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
