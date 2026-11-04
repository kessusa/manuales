<div class="col-md-5">
    <label class="form-label">Tag Name</label>
    <div class="dropdown group-comparator-tag">
        <button class="form-select form-select-sm text-start" type="button"
                data-bs-toggle="dropdown" data-bs-auto-close="outside" aria-expanded="false">
            <span class="group-comparator-tag-label">Select tag</span>
        </button>
        <div class="dropdown-menu w-100 p-2">
            <input type="search" class="form-control form-control-sm mb-2 filter-input"
                   placeholder="Search tag..." autocomplete="off">
            <div class="dropdown-list" style="max-height: 300px; overflow-y: auto;">
                {% for tag_name in group_comparator_form.fields.tag_name.queryset %}
                    <div class="dropdown-item">
                        <input class="form-check-input" type="radio" name="tag_name" value="{{ tag_name }}"
                               id="group-comparator-tag-{{ forloop.counter }}">
                        <label class="form-check-label" for="group-comparator-tag-{{ forloop.counter }}">{{ tag_name }}</label>
                    </div>
                {% endfor %}
            </div>
            <div class="no-results d-none text-muted small px-2">No results</div>
        </div>
    </div>
</div>
