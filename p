{# ============================================================ #}
{#  avi_waf_rules_modal.html                                    #}
{#  Estilos inline, radios simples, Bootstrap + iziToast        #}
{#  El script del final fuerza modal-xl en el .modal-dialog     #}
{# ============================================================ #}

{# iziToast CDN (elimínalas si ya las cargas en base.html) #}
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/izitoast@1.4.0/dist/css/iziToast.min.css">
<script src="https://cdn.jsdelivr.net/npm/izitoast@1.4.0/dist/js/iziToast.min.js"></script>

<div class="modal-header"
     style="background: linear-gradient(135deg, var(--bs-primary) 0%, color-mix(in srgb, var(--bs-primary) 75%, #000) 100%);
            color:#fff; border-bottom:none; padding:1rem 1.5rem;">
    <h5 class="modal-title" style="color:#fff; margin:0; font-weight:600;">
        <i class="fa fa-shield-alt me-2"></i>Modify WAF Rules
    </h5>
    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"
            style="filter:brightness(0) invert(1); opacity:.9;"></button>
</div>

<form method="post" action="{% url 'avi_rule_modify' %}" id="waf-rules-form" novalidate>
    {% csrf_token %}
    <div class="modal-body"
         style="background: var(--bs-tertiary-bg); padding:1.25rem;">

        {# ---------- Rule identification ---------- #}
        <div style="border:1px solid var(--bs-border-color); border-radius:.5rem;
                    padding:1rem 1.25rem; background:var(--bs-body-bg); margin-bottom:1rem;">
            <div style="font-size:.75rem; font-weight:700; text-transform:uppercase;
                        letter-spacing:.04em; color:var(--bs-secondary-color); margin-bottom:.75rem;">
                <i class="fa fa-fingerprint text-primary me-1"></i> Rule identification
            </div>
            <div class="row g-3">
                <div class="col-md-6">
                    <div class="form-floating">
                        {{ form.rule_id }}
                        <label for="{{ form.rule_id.id_for_label }}">
                            {{ form.rule_id.label }}
                            <span class="text-muted small ms-1">Ex: 9002140</span>
                        </label>
                    </div>
                    {% if form.rule_id.help_text %}
                        <small class="text-muted fst-italic">{{ form.rule_id.help_text }}</small>
                    {% endif %}
                    {% if form.rule_id.errors %}
                        <div class="invalid-feedback d-block">{{ form.rule_id.errors|join:", " }}</div>
                    {% endif %}
                </div>
                <div class="col-md-6">
                    <div class="form-floating">
                        {{ form.group_name }}
                        <label for="{{ form.group_name.id_for_label }}">
                            {{ form.group_name.label }}
                            <span class="text-muted small ms-1">Ex: CRS_901_Initialization</span>
                        </label>
                    </div>
                    {% if form.group_name.help_text %}
                        <small class="text-muted fst-italic">{{ form.group_name.help_text }}</small>
                    {% endif %}
                    {% if form.group_name.errors %}
                        <div class="invalid-feedback d-block">{{ form.group_name.errors|join:", " }}</div>
                    {% endif %}
                </div>
            </div>
        </div>

        {# ---------- Group type ---------- #}
        <div style="border:1px solid var(--bs-border-color); border-radius:.5rem;
                    padding:1rem 1.25rem; background:var(--bs-body-bg); margin-bottom:1rem;">
            <label style="font-size:.75rem; font-weight:700; text-transform:uppercase;
                          letter-spacing:.04em; color:var(--bs-secondary-color);
                          margin-bottom:.75rem; display:block;">
                <i class="fa fa-layer-group text-primary me-1"></i>
                {{ form.group_type.label }}
                <span class="text-secondary ms-1 d-inline-block" tabindex="0"
                      data-bs-toggle="popover" data-bs-trigger="hover focus"
                      data-bs-placement="top" data-bs-html="true"
                      data-bs-content="<p class='text-dark mb-0 pb-0 fw-normal'><span class='text-primary fw-bold'>PRE-CRS:</span> Custom rules</p><p class='text-dark mb-0 pb-0 fw-normal'><span class='text-primary fw-bold'>CRS:</span> Core Rule Set</p>"
                      style="cursor:help;">
                    <i class="far fa-question-circle"></i>
                </span>
            </label>
            <div class="d-flex flex-wrap gap-3">
                {% for choice in form.group_type %}
                    <div class="form-check">
                        {{ choice.tag }}
                        <label class="form-check-label" for="{{ choice.id_for_label }}">
                            {{ choice.choice_label }}
                        </label>
                    </div>
                {% endfor %}
            </div>
        </div>

        {# ---------- Action ---------- #}
        <div style="border:1px solid var(--bs-border-color); border-radius:.5rem;
                    padding:1rem 1.25rem; background:var(--bs-body-bg); margin-bottom:1rem;">
            <label style="font-size:.75rem; font-weight:700; text-transform:uppercase;
                          letter-spacing:.04em; color:var(--bs-secondary-color);
                          margin-bottom:.75rem; display:block;">
                <i class="fa fa-bolt text-primary me-1"></i>
                {{ form.action.label }}
                <span class="text-secondary ms-1 d-inline-block" tabindex="0"
                      data-bs-toggle="popover" data-bs-trigger="hover focus"
                      data-bs-placement="top" data-bs-html="true"
                      data-bs-content="<p class='text-dark mb-0 pb-0 fw-normal'><span class='text-primary fw-bold'>Add Rule:</span> New rule</p><p class='text-dark mb-0 pb-0 fw-normal'><span class='text-primary fw-bold'>Add Exclusion:</span> Exclusion</p><p class='text-dark mb-0 pb-0 fw-normal'><span class='text-primary fw-bold'>Enable/Disable:</span> Activate/deactivate</p>"
                      style="cursor:help;">
                    <i class="far fa-question-circle"></i>
                </span>
            </label>
            <div class="d-flex flex-wrap gap-3">
                {% for choice in form.action %}
                    <div class="form-check">
                        {{ choice.tag }}
                        <label class="form-check-label" for="{{ choice.id_for_label }}">
                            {{ choice.choice_label }}
                        </label>
                    </div>
                {% endfor %}
            </div>
        </div>

        {# ---------- Mode ---------- #}
        <div style="border:1px solid var(--bs-border-color); border-radius:.5rem;
                    padding:1rem 1.25rem; background:var(--bs-body-bg); margin-bottom:1rem;">
            <label style="font-size:.75rem; font-weight:700; text-transform:uppercase;
                          letter-spacing:.04em; color:var(--bs-secondary-color);
                          margin-bottom:.75rem; display:block;">
                <i class="fa fa-sliders-h text-primary me-1"></i>
                {{ form.mode.label }}
                <span class="text-secondary ms-1 d-inline-block" tabindex="0"
                      data-bs-toggle="popover" data-bs-trigger="hover focus"
                      data-bs-placement="top" data-bs-html="true"
                      data-bs-content="<p class='text-dark mb-0 pb-0 fw-normal'><span class='text-primary fw-bold'>Enforcement:</span> Block attacks</p><p class='text-dark mb-0 pb-0 fw-normal'><span class='text-primary fw-bold'>Detection:</span> Only log</p>"
                      style="cursor:help;">
                    <i class="far fa-question-circle"></i>
                </span>
            </label>
            <div class="d-flex flex-wrap gap-3">
                {% for choice in form.mode %}
                    <div class="form-check">
                        {{ choice.tag }}
                        <label class="form-check-label" for="{{ choice.id_for_label }}">
                            {{ choice.choice_label }}
                        </label>
                    </div>
                {% endfor %}
            </div>
        </div>

        {# ---------- Exclusion data / JSON ---------- #}
        <div style="border:1px solid var(--bs-border-color); border-radius:.5rem;
                    padding:1rem 1.25rem; background:var(--bs-body-bg); margin-bottom:1rem;">
            <label style="font-size:.75rem; font-weight:700; text-transform:uppercase;
                          letter-spacing:.04em; color:var(--bs-secondary-color);
                          margin-bottom:.75rem; display:block;">
                <i class="fa fa-code text-primary me-1"></i>
                {{ form.exclusion_data.label }}
                <span class="text-secondary ms-1 d-inline-block" tabindex="0"
                      data-bs-toggle="popover" data-bs-trigger="hover focus"
                      data-bs-placement="top" data-bs-html="true"
                      data-bs-content="<p class='text-dark mb-0 pb-0 fw-normal'><span class='text-primary fw-bold'>Format:</span> JSON</p><p class='text-dark mb-0 pb-0 fw-normal'><span class='text-primary fw-bold'>Use for:</span> exclusions or rule definitions</p>"
                      style="cursor:help;">
                    <i class="far fa-question-circle"></i>
                </span>
            </label>

            <ul class="nav nav-tabs mb-3" id="exclusionExamplesTab" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" id="exclusion-uri-tab"
                            data-bs-toggle="tab" data-bs-target="#exclusion-uri"
                            type="button" role="tab"
                            aria-controls="exclusion-uri" aria-selected="true">
                        <i class="fa fa-ban me-1"></i> Exception Example
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="add-rule-tab"
                            data-bs-toggle="tab" data-bs-target="#add-rule"
                            type="button" role="tab"
                            aria-controls="add-rule" aria-selected="false">
                        <i class="fa fa-plus-circle me-1"></i> Rule Example
                    </button>
                </li>
            </ul>

            <div class="tab-content mb-3" id="exclusionExamplesContent">
                <div class="tab-pane fade show active" id="exclusion-uri"
                     role="tabpanel" aria-labelledby="exclusion-uri-tab">
<pre style="background:var(--bs-dark); color:var(--bs-light); border-radius:.375rem;
            padding:.85rem 1rem; font-size:.8rem; line-height:1.5; margin:0;
            max-height:220px; overflow:auto;"><code>{
  "uri_path": "/admin",
  "match_element": "REQUEST_HEADERS:User-Agent",
  "match_element_criteria": {
    "match_case": "INSENSITIVE",
    "match_op": "REGEX_MATCH"
  }
}</code></pre>
                </div>
                <div class="tab-pane fade" id="add-rule"
                     role="tabpanel" aria-labelledby="add-rule-tab">
<pre style="background:var(--bs-dark); color:var(--bs-light); border-radius:.375rem;
            padding:.85rem 1rem; font-size:.8rem; line-height:1.5; margin:0;
            max-height:220px; overflow:auto;"><code>{
  "enable": true,
  "is_sensitive": true,
  "mode": "WAF_MODE_ENFORCEMENT",
  "name": "React_CVE_Block_Rule_2",
  "rule": "SecRule TX:is_react_action \"@unconditionalMatch\" \"id:500001, phase:2, block, t:none, msg:'React CVE Exploit Attempt', log, severity:1\""
}</code></pre>
                </div>
            </div>

            <div class="form-floating">
                {{ form.exclusion_data }}
                <label for="{{ form.exclusion_data.id_for_label }}">Enter your JSON here</label>
            </div>
            {% if form.exclusion_data.help_text %}
                <small class="text-muted fst-italic">{{ form.exclusion_data.help_text }}</small>
            {% endif %}
            {% if form.exclusion_data.errors %}
                <div class="invalid-feedback d-block">{{ form.exclusion_data.errors|join:", " }}</div>
            {% endif %}
        </div>

        {# ---------- WAF Policies ---------- #}
        <div style="border:1px solid var(--bs-border-color); border-radius:.5rem;
                    padding:1rem 1.25rem; background:var(--bs-body-bg); margin-bottom:0;">
            <label style="font-size:.75rem; font-weight:700; text-transform:uppercase;
                          letter-spacing:.04em; color:var(--bs-secondary-color);
                          margin-bottom:.75rem; display:block;">
                <i class="fa fa-shield-virus text-primary me-1"></i>
                {{ form.waf_policies.label }}
                <span class="text-secondary ms-1 d-inline-block" tabindex="0"
                      data-bs-toggle="popover" data-bs-trigger="hover focus"
                      data-bs-placement="top" data-bs-html="true"
                      data-bs-content="<p class='text-dark mb-0 pb-0 fw-normal'><span class='text-primary fw-bold'>Selection:</span> one or more</p><p class='text-dark mb-0 pb-0 fw-normal'><span class='text-primary fw-bold'>Applies to:</span> chosen WAF policies</p>"
                      style="cursor:help;">
                    <i class="far fa-question-circle"></i>
                </span>
            </label>

            <div class="dropdown">
                <button class="btn btn-outline-secondary dropdown-toggle w-100 text-start"
                        type="button" id="wafPoliciesDropdown"
                        data-bs-toggle="dropdown" data-bs-auto-close="outside"
                        aria-expanded="false">
                    <i class="fa fa-shield me-2 text-primary"></i>
                    <span id="wafPoliciesLabel">Select WAF Policies</span>
                </button>
                <ul class="dropdown-menu w-100 p-3" aria-labelledby="wafPoliciesDropdown"
                    style="max-height:340px; overflow-y:auto;">
                    <div class="input-group mb-2">
                        <span class="input-group-text bg-body">
                            <i class="fa fa-search text-secondary"></i>
                        </span>
                        <input type="text" class="form-control" id="wafPolicySearch"
                               placeholder="Search policies..." aria-label="Search policies">
                    </div>
                    <div class="d-flex justify-content-between align-items-center mb-2 px-1">
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="selectAllPolicies">
                            <label class="form-check-label fw-semibold" for="selectAllPolicies">
                                Select all
                            </label>
                        </div>
                        <span class="text-muted small" id="noPoliciesFound" style="display:none;">
                            No policies found
                        </span>
                    </div>
                    <hr class="my-2">
                    {% for policy in form.waf_policies %}
                        <li class="waf-policy-item" style="list-style:none; padding:.25rem .25rem;">
                            <div class="form-check">
                                {{ policy.tag }}
                                <label class="form-check-label" for="{{ policy.id_for_label }}">
                                    {{ policy.choice_label }}
                                </label>
                            </div>
                        </li>
                    {% endfor %}
                </ul>
            </div>
            <small class="text-muted fst-italic d-block mt-2">
                <i class="fa fa-info-circle me-1"></i>
                Select one or more WAF policies to apply changes to
            </small>
        </div>

    </div>

    <div class="modal-footer"
         style="background:var(--bs-body-bg); border-top:1px solid var(--bs-border-color);
                padding:.85rem 1.5rem; gap:.5rem;">
        <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
            <i class="fa fa-times me-1"></i> Cancel
        </button>
        <button type="submit" class="btn btn-primary" id="waf-submit-btn">
            <i class="fa fa-check me-1"></i> Apply Changes
        </button>
    </div>
</form>

<script>
(function () {
    // ---------- Forzar modal-xl en el .modal-dialog padre ----------
    const dialog = document.getElementById('waf-rules-form')?.closest('.modal-dialog');
    if (dialog) {
        dialog.classList.remove('modal-sm', 'modal-lg');
        dialog.classList.add('modal-xl');
    }

    // ---------- Popovers & Tooltips ----------
    function initPopoversAndTooltips(root) {
        if (typeof bootstrap === 'undefined') {
            console.warn('[WAF modal] bootstrap not loaded yet');
            return;
        }
        root.querySelectorAll('[data-bs-toggle="popover"]').forEach(function (el) {
            if (!bootstrap.Popover.getInstance(el)) {
                new bootstrap.Popover(el, { container: 'body', html: true, trigger: 'hover focus' });
            }
        });
        root.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(function (el) {
            if (!bootstrap.Tooltip.getInstance(el)) {
                new bootstrap.Tooltip(el, { container: 'body' });
            }
        });
    }

    // Init inmediato: el script se ejecuta cuando el contenido ya está en el DOM
    initPopoversAndTooltips(document);

    // Re-init al abrir el modal (por si el contenido es dinámico o se cierra y reabre)
    const modalEl = document.getElementById('waf-rules-form')?.closest('.modal');
    if (modalEl) {
        modalEl.addEventListener('shown.bs.modal', function () {
            initPopoversAndTooltips(modalEl);
        });
    }

    // ---------- Policies dropdown ----------
    const wafPoliciesDropdown = document.getElementById('wafPoliciesDropdown');
    const wafPoliciesLabel    = document.getElementById('wafPoliciesLabel');
    const wafPoliciesMenu     = document.querySelector('[aria-labelledby="wafPoliciesDropdown"]');
    const wafPolicySearch     = document.getElementById('wafPolicySearch');
    const selectAllPolicies   = document.getElementById('selectAllPolicies');
    const noPoliciesFound     = document.getElementById('noPoliciesFound');

    let isProcessingAll = false;

    if (wafPoliciesDropdown && wafPoliciesMenu) {

        function updatePolicySelection() {
            const checkedItems = wafPoliciesMenu.querySelectorAll(
                '.waf-policy-item input[type="checkbox"]:checked'
            );
            const allItems = wafPoliciesMenu.querySelectorAll(
                '.waf-policy-item input[type="checkbox"]'
            );

            wafPoliciesLabel.textContent = checkedItems.length > 0
                ? checkedItems.length + ' WAF Polic' + (checkedItems.length === 1 ? 'y' : 'ies') + ' selected'
                : 'Select WAF Policies';

            if (!isProcessingAll) {
                selectAllPolicies.checked = allItems.length > 0 &&
                                            checkedItems.length === allItems.length;
            }
        }

        wafPolicySearch.addEventListener('input', function () {
            const term  = this.value.toLowerCase();
            const items = document.querySelectorAll('.waf-policy-item');
            let found = 0;

            items.forEach(item => {
                const label = item.querySelector('label').textContent.toLowerCase();
                if (label.includes(term)) { item.style.display = ''; found++; }
                else                       { item.style.display = 'none'; }
            });

            noPoliciesFound.style.display = found === 0 ? '' : 'none';
        });

        selectAllPolicies.addEventListener('change', function () {
            isProcessingAll = true;
            const visibleItems = document.querySelectorAll(
                '.waf-policy-item:not([style*="display: none"]) input[type="checkbox"]'
            );
            visibleItems.forEach(cb => {
                cb.checked = this.checked;
                cb.dispatchEvent(new Event('change'));
            });
            updatePolicySelection();
            isProcessingAll = false;
        });

        wafPoliciesMenu.addEventListener('change', function (e) {
            if (e.target.type === 'checkbox' &&
                e.target.id   !== 'selectAllPolicies' &&
                e.target.closest('.waf-policy-item')) {
                updatePolicySelection();
            }
        });

        wafPoliciesMenu.addEventListener('click', function (e) { e.stopPropagation(); });

        wafPoliciesDropdown.addEventListener('hide.bs.dropdown', function () {
            wafPolicySearch.value = '';
            document.querySelectorAll('.waf-policy-item').forEach(it => it.style.display = '');
            noPoliciesFound.style.display = 'none';
            updatePolicySelection();
        });

        updatePolicySelection();
    }

    // ---------- iziToast defaults ----------
    if (typeof iziToast !== 'undefined') {
        iziToast.settings({
            timeout: 5000, resetOnHover: true, position: 'topRight',
            transitionIn: 'fadeInDown', transitionOut: 'fadeOutUp',
            closeOnEscape: true, progressBar: true, layout: 2
        });
    }

    function showToast(type, title, message) {
        if (typeof iziToast === 'undefined') {
            console[type === 'error' ? 'error' : 'log'](title + ': ' + message);
            return;
        }
        const fn = { success: iziToast.success, error: iziToast.error,
                     warning: iziToast.warning, info: iziToast.info }[type] || iziToast.info;
        fn.call(iziToast, { title: title || '', message: message || '' });
    }
    window.showWafToast = showToast;

    // ---------- Form submit via AJAX ----------
    const form = document.getElementById('waf-rules-form');
    const submitBtn = document.getElementById('waf-submit-btn');

    form.addEventListener('submit', function (e) {
        e.preventDefault();

        const selectedPolicies = wafPoliciesMenu
            ? wafPoliciesMenu.querySelectorAll('.waf-policy-item input[type="checkbox"]:checked')
            : [];
        if (wafPoliciesMenu && selectedPolicies.length === 0) {
            showToast('warning', 'No policies selected',
                      'Please select at least one WAF policy before applying changes.');
            return;
        }

        const jsonField = document.getElementById('{{ form.exclusion_data.id_for_label }}');
        if (jsonField && jsonField.value.trim().length > 0) {
            try { JSON.parse(jsonField.value); }
            catch (err) {
                showToast('error', 'Invalid JSON', 'The exclusion / rule data is not valid JSON.');
                return;
            }
        }

        const originalHtml = submitBtn.innerHTML;
        submitBtn.disabled  = true;
        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Applying...';

        const formData = new FormData(form);

        fetch(form.action, {
            method: 'POST',
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRFToken': formData.get('csrfmiddlewaretoken')
            }
        })
        .then(r => r.json().then(data => ({ ok: r.ok, data })))
        .then(({ ok, data }) => {
            if (ok && data.success) {
                showToast('success',
                          data.title   || 'Changes applied',
                          data.message || 'WAF rules updated successfully.');

                const modalEl = form.closest('.modal');
                if (modalEl) {
                    const modal = bootstrap.Modal.getInstance(modalEl);
                    if (modal) setTimeout(() => modal.hide(), 800);
                }
                form.reset();

                if (typeof window.onWafRulesUpdated === 'function') {
                    window.onWafRulesUpdated(data);
                }
            } else {
                showToast('error',
                          data.title   || 'Error',
                          data.message || 'Something went wrong while applying changes.');
            }
        })
        .catch(err => {
            console.error(err);
            showToast('error', 'Network error',
                      'The request could not be completed. Please try again.');
        })
        .finally(() => {
            submitBtn.disabled  = false;
            submitBtn.innerHTML = originalHtml;
        });
    });

    // ---------- Django messages ----------
    {% if messages %}
        {% for message in messages %}
            showToast(
                '{{ message.tags|default:"info" }}',
                '{{ message.tags|title|default:"Notice" }}',
                '{{ message|escapejs }}'
            );
        {% endfor %}
    {% endif %}
})();
</script>
