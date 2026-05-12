<div class="dropdown">
    <button class="btn btn-outline-secondary dropdown-toggle w-100 d-flex align-items-center"
            type="button" id="wafPoliciesDropdown"
            data-bs-toggle="dropdown" data-bs-auto-close="outside"
            aria-expanded="false">
        <span id="wafPoliciesLabel" class="flex-grow-1 text-start">Select WAF Policies</span>
    </button>

    <ul class="dropdown-menu w-100 p-3" aria-labelledby="wafPoliciesDropdown"
        style="max-height:340px; overflow-y:auto;">

        <li style="list-style:none;">
            <div class="input-group mb-2">
                <span class="input-group-text bg-body">
                    <i class="fa fa-search text-secondary" style="font-size: 0.8rem !important;"></i>
                </span>
                <input type="text" class="form-control" id="wafPolicySearch"
                       placeholder="Search policies..." aria-label="Search policies">
            </div>
        </li>

        <li class="waf-policy-item" style="list-style:none; padding:3px 3px;">
            <div class="form-check">
                <input class="form-check-input" type="checkbox" id="selectAllPolicies">
                <label class="form-check-label" for="selectAllPolicies">
                    All
                </label>
            </div>
        </li>

        <li id="noPoliciesFound" class="text-muted small px-1"
            style="list-style:none; display:none;">
            No policies found
        </li>

        {% for policy in form.waf_policies %}
        <li class="waf-policy-item" style="list-style:none; padding:3px 3px;">
            <div class="form-check">
                {{ policy.tag }}
                <label class="form-check-label" for="{{ policy.id_for_label }}">
                    {{ policy.choice_label }}
                </label>
            </div>
        </li>
        {% endfor %}

    </ul>

    <small class="text-muted fst-italic d-block mt-2">
        <i class="fa fa-info-circle me-1"></i>
        Select one or more WAF policies to apply changes to
    </small>
</div>
