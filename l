{% if error %}
    <div class="alert alert-warning mb-0">{{ error }}</div>
{% else %}
    <div class="card w-100 border-0 shadow-sm">
        <div class="card-header bg-white py-3">
            <div class="text-muted small">Showing results for</div>
            <h5 class="mb-0 text-primary font-weight-bold fw-bold">{{ hierarchy.group_name }}</h5>
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
                {% include 'search_components/group_lookup_node.html' with node=hierarchy depth=0 parent_name='' %}
                </tbody>
            </table>
        </div>
    </div>
{% endif %}
