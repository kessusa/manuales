{# ============================================================ #}
{#  avi_waf_rules_modal.html                                    #}
{#  Modal rediseñado para modificar reglas WAF                  #}
{#  Usa Bootstrap 5 + iziToast para notificaciones              #}
{# ============================================================ #}

{# --- iziToast assets: si ya los cargas en base.html, elimina estas 2 líneas --- #}
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/izitoast@1.4.0/dist/css/iziToast.min.css">
<script src="https://cdn.jsdelivr.net/npm/izitoast@1.4.0/dist/js/iziToast.min.js"></script>

<style>
    /* ---------- Estilos locales del modal WAF ---------- */
    #waf-rules-form .waf-section {
        border: 1px solid #e3e6ec;
        border-radius: .75rem;
        padding: 1.25rem 1.25rem 1rem;
        background: #fff;
        transition: box-shadow .2s ease, border-color .2s ease;
    }
    #waf-rules-form .waf-section + .waf-section { margin-top: 1rem; }
    #waf-rules-form .waf-section:hover {
        border-color: #c9d4e3;
        box-shadow: 0 2px 8px rgba(40, 60, 100, .06);
    }
    #waf-rules-form .waf-section-title {
        font-size: .78rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: .04em;
        color: #5a6477;
        margin-bottom: .85rem;
        display: flex;
        align-items: center;
        gap: .5rem;
    }
    #waf-rules-form .waf-section-title i { color: #0d6efd; }

    #waf-rules-form .form-floating > label { color: #6c757d; }
    #waf-rules-form .tooltip-trigger {
        color: #6c757d;
        cursor: help;
        transition: color .15s ease;
    }
    #waf-rules-form .tooltip-trigger:hover { color: #0d6efd; }

    #waf-rules-form .form-check-modern {
        border: 1px solid #e3e6ec;
        border-radius: .5rem;
        padding: .6rem .9rem;
        transition: all .15s ease;
        cursor: pointer;
        flex: 1;
        min-width: 0;
    }
    #waf-rules-form .form-check-modern:hover {
        border-color: #9ec5fe;
        background: #f5f9ff;
    }
    #waf-rules-form .form-check-modern input:checked ~ label {
        color: #0d6efd;
        font-weight: 600;
    }
    #waf-rules-form .form-check-modern:has(input:checked) {
        border-color: #0d6efd;
        background: #eaf2ff;
    }

    #waf-rules-form .json-example {
        background: #0f172a;
        color: #e2e8f0;
        border-radius: .5rem;
        padding: 1rem;
        font-size: .8rem;
        line-height: 1.5;
        margin-bottom: 0;
        max-height: 260px;
        overflow: auto;
    }
    #waf-rules-form .nav-tabs-modern {
        border-bottom: 2px solid #e3e6ec;
        margin-bottom: .75rem;
    }
    #waf-rules-form .nav-tabs-modern .nav-link {
        border: none;
        color: #6c757d;
        font-weight: 500;
        padding: .5rem 1rem;
        border-bottom: 2px solid transparent;
        margin-bottom: -2px;
    }
    #waf-rules-form .nav-tabs-modern .nav-link.active {
        color: #0d6efd;
        background: transparent;
        border-bottom-color: #0d6efd;
    }

    #waf-rules-form #wafPoliciesDropdown {
        min-height: 46px;
        border-color: #dee2e6;
        background: #fff;
    }
    #waf-rules-form #wafPoliciesDropdown:hover { border-color: #9ec5fe; }
    #waf-rules-form .dropdown-menu { box-shadow: 0 10px 30px rgba(0,0,0,.1); }
    #waf-rules-form .waf-policy-item {
        padding: .35rem .5rem;
        border-radius: .35rem;
        transition: background .1s ease;
    }
    #waf-rules-form .waf-policy-item:hover { background: #f1f3f5; }

    .waf-modal .modal-header {
        background: linear-gradient(135deg, #0d6efd 0%, #0a58ca 100%);
        color: #fff;
        border-bottom: none;
        border-radius: .5rem .5rem 0 0;
        padding: 1.1rem 1.5rem;
    }
    .waf-modal .modal-header h5 { color: #fff; margin: 0; font-weight: 600; }
    .waf-modal .modal-header .btn-close { filter: brightness(0) invert(1); opacity: .85; }
    .waf-modal .modal-body { background: #f8f9fb; padding: 1.5rem; }
    .waf-modal .modal-footer {
        background: #fff;
        border-top: 1px solid #e3e6ec;
        padding: 1rem 1.5rem;
    }
</style>

<div class="modal-header">
    <h5 class="modal-title"><i class="fa fa-shield-alt me-2"></i>Modify WAF Rules</h5>
    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
</div>

<form method="post" action="{% url 'avi_rule_modify' %}" id="waf-rules-form" novalidate>
    {% csrf_token %}
    <div class="modal-body p-0">
        <div class="p-4">

            {# ---------- Rule / Group identification ---------- #}
            <div class="waf-section">
                <div class="waf-section-title">
                    <i class="fa fa-fingerprint"></i> Rule identification
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
            <div class="waf-section">
                <label class="waf-section-title mb-2">
                    <i class="fa fa-layer-group"></i>
                    {{ form.group_type.label }}
                    <span class="tooltip-trigger d-inline-block ms-auto" tabindex="0"
                          data-bs-toggle="tooltip" data-bs-placement="top"
                          title="PRE-CRS: Custom rules | CRS: Core Rule Set">
                        <i class="far fa-question-circle"></i>
                    </span>
                </label>
                <div class="d-flex gap-2 flex-wrap">
                    {% for choice in form.group_type %}
                        <div class="form-check form-check-modern">
                            {{ choice.tag }}
                            <label class="form-check-label w-100" for="{{ choice.id_for_label }}">
                                {{ choice.choice_label }}
                            </label>
                        </div>
                    {% endfor %}
                </div>
            </div>

            {# ---------- Action ---------- #}
            <div class="waf-section">
                <label class="waf-section-title mb-2">
                    <i class="fa fa-bolt"></i>
                    {{ form.action.label }}
                    <span class="tooltip-trigger d-inline-block ms-auto" tabindex="0"
                          data-bs-toggle="tooltip" data-bs-placement="top"
                          title="Add Rule: New rule | Add Exclusion: Exclusion | Enable/Disable: Activate/deactivate">
                        <i class="far fa-question-circle"></i>
                    </span>
                </label>
                <div class="row g-2">
                    {% for choice in form.action %}
                        <div class="col-md-3 col-sm-6">
                            <div class="form-check form-check-modern">
                                {{ choice.tag }}
                                <label class="form-check-label w-100" for="{{ choice.id_for_label }}">
                                    {{ choice.choice_label }}
                                </label>
                            </div>
                        </div>
                    {% endfor %}
                </div>
            </div>

            {# ---------- Mode ---------- #}
            <div class="waf-section">
                <label class="waf-section-title mb-2">
                    <i class="fa fa-sliders-h"></i>
                    {{ form.mode.label }}
                    <span class="tooltip-trigger d-inline-block ms-auto" tabindex="0"
                          data-bs-toggle="tooltip" data-bs-placement="top"
                          title="Enforcement: Block attacks | Detection: Only log">
                        <i class="far fa-question-circle"></i>
                    </span>
                </label>
                <div class="d-flex gap-2 flex-wrap">
                    {% for choice in form.mode %}
                        <div class="form-check form-check-modern">
                            {{ choice.tag }}
                            <label class="form-check-label w-100" for="{{ choice.id_for_label }}">
                                {{ choice.choice_label }}
                            </label>
                        </div>
                    {% endfor %}
                </div>
            </div>

            {# ---------- Exclusion data / JSON ---------- #}
            <div class="waf-section">
                <label class="waf-section-title mb-2">
                    <i class="fa fa-code"></i>
                    {{ form.exclusion_data.label }}
                    <span class="tooltip-trigger d-inline-block ms-auto" tabindex="0"
                          data-bs-toggle="tooltip" data-bs-placement="top"
                          title="JSON format for exclusions or rule definitions">
                        <i class="far fa-question-circle"></i>
                    </span>
                </label>

                <ul class="nav nav-tabs-modern" id="exclusionExamplesTab" role="tablist">
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
<pre class="json-example"><code>{
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
<pre class="json-example"><code>{
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
            <div class="waf-section">
                <label class="waf-section-title mb-2">
                    <i class="fa fa-shield-virus"></i>
                    {{ form.waf_policies.label }}
                    <span class="tooltip-trigger d-inline-block ms-auto" tabindex="0"
                          data-bs-toggle="tooltip" data-bs-placement="top"
                          title="Select one or more WAF policies">
                        <i class="far fa-question-circle"></i>
                    </span>
                </label>

                <div class="dropdown">
                    <button class="btn btn-outline-secondary dropdown-toggle w-100 text-start"
                            type="button" id="wafPoliciesDropdown"
                            data-bs-toggle="dropdown" data-bs-auto-close="outside"
                            aria-expanded="false">
                        <i class="fa fa-shield me-1 text-primary"></i> Select WAF Policies
                    </button>
                    <ul class="dropdown-menu w-100 p-3" aria-labelledby="wafPoliciesDropdown"
                        style="max-height: 340px; overflow-y: auto;">
                        <div class="input-group mb-3">
                            <span class="input-group-text bg-white"><i class="fa fa-search text-muted"></i></span>
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
                            <li class="waf-policy-item">
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
    </div>

    <div class="modal-footer">
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
    // ---------- Tooltips ----------
    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(function (el) {
        new bootstrap.Tooltip(el);
    });

    // ---------- Policies dropdown ----------
    const wafPoliciesDropdown = document.getElementById('wafPoliciesDropdown');
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

            wafPoliciesDropdown.innerHTML = checkedItems.length > 0
                ? '<i class="fa fa-shield me-1 text-primary"></i>' +
                  checkedItems.length + ' WAF Polic' + (checkedItems.length === 1 ? 'y' : 'ies') + ' selected'
                : '<i class="fa fa-shield me-1 text-primary"></i> Select WAF Policies';

            if (!isProcessingAll) {
                selectAllPolicies.checked = allItems.length > 0 &&
                                            checkedItems.length === allItems.length;
            }
        }

        wafPolicySearch.addEventListener('input', function () {
            const term = this.value.toLowerCase();
            const items = document.querySelectorAll('.waf-policy-item');
            let found = 0;

            items.forEach(item => {
                const label = item.querySelector('label').textContent.toLowerCase();
                if (label.includes(term)) {
                    item.style.display = '';
                    found++;
                } else {
                    item.style.display = 'none';
                }
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

    // ---------- iziToast: defaults ----------
    if (typeof iziToast !== 'undefined') {
        iziToast.settings({
            timeout:        5000,
            resetOnHover:   true,
            position:       'topRight',
            transitionIn:   'fadeInDown',
            transitionOut:  'fadeOutUp',
            closeOnEscape:  true,
            progressBar:    true,
            layout:         2
        });
    }

    function showToast(type, title, message) {
        if (typeof iziToast === 'undefined') {
            console[type === 'error' ? 'error' : 'log'](title + ': ' + message);
            return;
        }
        const fn = {
            success: iziToast.success,
            error:   iziToast.error,
            warning: iziToast.warning,
            info:    iziToast.info
        }[type] || iziToast.info;

        fn.call(iziToast, { title: title || '', message: message || '' });
    }
    window.showWafToast = showToast;   // exposed for views / AJAX callbacks

    // ---------- Form submit via AJAX ----------
    const form = document.getElementById('waf-rules-form');
    const submitBtn = document.getElementById('waf-submit-btn');

    form.addEventListener('submit', function (e) {
        e.preventDefault();

        // Client-side check: at least one policy selected
        const selectedPolicies = wafPoliciesMenu
            ? wafPoliciesMenu.querySelectorAll('.waf-policy-item input[type="checkbox"]:checked')
            : [];
        if (wafPoliciesMenu && selectedPolicies.length === 0) {
            showToast('warning', 'No policies selected',
                      'Please select at least one WAF policy before applying changes.');
            return;
        }

        // Validate JSON if provided
        const jsonField = document.getElementById('{{ form.exclusion_data.id_for_label }}');
        if (jsonField && jsonField.value.trim().length > 0) {
            try { JSON.parse(jsonField.value); }
            catch (err) {
                showToast('error', 'Invalid JSON', 'The exclusion / rule data is not valid JSON.');
                return;
            }
        }

        const originalHtml = submitBtn.innerHTML;
        submitBtn.disabled = true;
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
        .then(r => r.json().then(data => ({ ok: r.ok, status: r.status, data })))
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
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalHtml;
        });
    });

    // ---------- Django messages (if present) ----------
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
