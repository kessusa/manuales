{# 
============================================================================
  File manager template - FINAL with layout fixes + working batch actions.
  Location: templates/tools/file_manager.html

  Changes vs previous version:
    - Table uses <colgroup> with fixed widths so columns align correctly
    - "Select all" checkbox is fully visible (proper width column)
    - Size and Actions columns aligned to the right (text-end)
    - Delete buttons (single + batch) now use btn-outline-danger (red)
    - Batch buttons (Download / Move / Delete selected) now fully functional
      following the same pattern as the existing deleteFile() function:
        * iziToast.question for confirmation
        * fetch with X-CSRFToken header
        * iziToast.success / iziToast.error for feedback
        * Full page reload after success
============================================================================
#}
{% extends "base.html" %}
{% load custom_filters %}

{% block currentTitle %}File Manager{% endblock %}

{% block content %}
<div class="row">
  <div class="col-12 mb-2">

    {# ---------------------------------------------------------- Breadcrumbs #}
    {% if breadcrumbs or current_folder %}
      <nav aria-label="breadcrumb" class="mb-3">
        <ol class="breadcrumb">
          <li class="breadcrumb-item">
            <a href="{% url 'file_manager' %}" class="text-primary">
              <i class="fas fa-home"></i> Home
            </a>
          </li>
          {% for crumb in breadcrumbs %}
            {% if forloop.last %}
              <li class="breadcrumb-item active" aria-current="page">{{ crumb.name }}</li>
            {% else %}
              <li class="breadcrumb-item">
                <a href="{% url 'file_manager_folder' folder_id=crumb.id %}" class="text-primary">
                  {{ crumb.name }}
                </a>
              </li>
            {% endif %}
          {% endfor %}
        </ol>
      </nav>
    {% endif %}

    <div class="card card-small mb-3">

      {# -------------------------------------------------------- Card header #}
      <div class="card-header border-bottom d-flex justify-content-between align-items-center flex-wrap">
        <h6 class="mb-0">File Manager Overview</h6>
        <div class="btn-group">
          {% if current_folder %}
            <a href="{% url 'download_folder_zip' folder_id=current_folder.id %}"
               class="btn btn-sm btn-outline-primary active-light"
               title="Download this folder as a ZIP archive">
              <i class="fas fa-file-archive"></i> Download ZIP
            </a>
            <a href="{% url 'folder_permissions' folder_id=current_folder.id %}"
               class="btn btn-sm btn-outline-primary active-light">
              <i class="fas fa-shield-alt"></i> Permissions
            </a>
          {% endif %}
          {% if can_add_in_current %}
            <button type="button"
                    class="btn btn-sm btn-outline-primary active-light"
                    data-bs-toggle="modal"
                    data-bs-target="#newFolderModal">
              <i class="fas fa-folder-plus"></i> New folder
            </button>
            <button type="button"
                    class="btn btn-sm btn-outline-primary active-light"
                    data-bs-toggle="modal"
                    data-bs-target="#uploadModal">
              <i class="fas fa-upload"></i> Upload
            </button>
          {% endif %}
        </div>
      </div>

      {# ---------------------------------------------- Batch action toolbar #}
      <div class="card-body border-bottom py-2">
        <div class="d-flex justify-content-between align-items-center flex-wrap">
          <div class="btn-group">
            <button type="button"
                    id="downloadSelectedBtn"
                    class="btn btn-sm btn-outline-primary active-light"
                    disabled>
              <i class="fas fa-download"></i> Download selected (<span class="selected-count">0</span>)
            </button>
            <button type="button"
                    id="moveSelectedBtn"
                    class="btn btn-sm btn-outline-primary active-light"
                    disabled>
              <i class="fas fa-arrows-alt"></i> Move selected (<span class="selected-count">0</span>)
            </button>
            <button type="button"
                    id="deleteSelectedBtn"
                    class="btn btn-sm btn-outline-danger active-light"
                    disabled>
              <i class="fas fa-trash"></i> Delete selected (<span class="selected-count">0</span>)
            </button>
          </div>
          <small class="fw-light">Tip: tick the checkboxes to act on multiple files at once.</small>
        </div>
      </div>

      {# ---------------------------------------------------------- Listing #}
      <div class="card-body p-0">
        <div class="table-responsive">
          <table class="table table-striped mb-0" style="width: 100%; table-layout: fixed;">

            {# Fixed column widths so the layout doesn't shift #}
            <colgroup>
              <col style="width: 50px;">       {# checkbox  #}
              <col style="width: 50px;">       {# icon      #}
              <col>                            {# name (flex) #}
              <col style="width: 110px;">      {# size      #}
              <col style="width: 280px;">      {# actions   #}
            </colgroup>

            <thead>
              <tr class="text-nowrap">
                <th class="text-center align-middle">
                  <input type="checkbox" id="selectAll" class="form-check-input">
                </th>
                <th></th>
                <th class="text-start">Name</th>
                <th class="text-end">Size</th>
                <th class="text-end pe-3">Actions</th>
              </tr>
            </thead>
            <tbody>

              {# 'Up' link to parent folder #}
              {% if current_folder %}
                <tr class="text-nowrap">
                  <td></td>
                  <td class="text-center align-middle">
                    <i class="fas fa-level-up-alt"></i>
                  </td>
                  <td class="text-start text-primary align-middle" colspan="3">
                    {% if current_folder.parent %}
                      <a href="{% url 'file_manager_folder' folder_id=current_folder.parent.id %}" class="text-primary">..</a>
                    {% else %}
                      <a href="{% url 'file_manager' %}" class="text-primary">..</a>
                    {% endif %}
                  </td>
                </tr>
              {% endif %}

              {# Subfolders (no checkbox: folders cannot be batch-selected) #}
              {% for folder in subfolders %}
                <tr class="text-nowrap">
                  <td></td>
                  <td class="text-center align-middle">
                    <i class="fas fa-folder"></i>
                  </td>
                  <td class="text-start text-primary align-middle text-truncate">
                    <a href="{% url 'file_manager_folder' folder_id=folder.id %}" class="text-primary">
                      {{ folder.name }}
                    </a>
                  </td>
                  <td class="fw-light align-middle text-end">{{ folder.files.count }} file(s)</td>
                  <td class="text-end pe-3 align-middle">
                    <a href="{% url 'download_folder_zip' folder_id=folder.id %}"
                       class="btn btn-sm btn-outline-primary active-light"
                       title="Download as ZIP">
                      <i class="fas fa-file-archive"></i>
                    </a>
                    <button type="button"
                            class="btn btn-sm btn-outline-primary active-light"
                            data-bs-toggle="modal"
                            data-bs-target="#renameFolderModal"
                            data-folder-id="{{ folder.id }}"
                            data-folder-name="{{ folder.name }}"
                            title="Rename">
                      <i class="fas fa-pencil-alt"></i>
                    </button>
                    <button type="button"
                            class="btn btn-sm btn-outline-primary active-light"
                            data-bs-toggle="modal"
                            data-bs-target="#moveFolderModal"
                            data-folder-id="{{ folder.id }}"
                            data-folder-name="{{ folder.name }}"
                            title="Move">
                      <i class="fas fa-arrows-alt"></i>
                    </button>
                    <a href="{% url 'folder_permissions' folder_id=folder.id %}"
                       class="btn btn-sm btn-outline-primary active-light"
                       title="Permissions">
                      <i class="fas fa-shield-alt"></i>
                    </a>
                    <button type="button"
                            class="btn btn-sm btn-outline-danger active-light"
                            onclick="deleteFolder({{ folder.id }}, '{{ folder.name|escapejs }}')"
                            title="Delete">
                      <i class="fas fa-trash"></i>
                    </button>
                  </td>
                </tr>
              {% endfor %}

              {# Files with selection checkbox #}
              {% for f in files %}
                <tr class="text-nowrap">
                  <td class="text-center align-middle">
                    <input type="checkbox"
                           class="form-check-input file-checkbox"
                           value="{{ f.id }}">
                  </td>
                  <td class="text-center align-middle">
                    <i class="fas fa-file"></i>
                  </td>
                  <td class="text-start text-primary align-middle text-truncate">
                    {{ f.name|default:f.original_filename }}
                  </td>
                  <td class="fw-light align-middle text-end">
                    {{ f.size|filesize }}
                  </td>
                  <td class="text-end pe-3 align-middle">
                    <a href="{% url 'download_file' file_id=f.id %}"
                       class="btn btn-sm btn-outline-primary active-light"
                       title="Download">
                      <i class="fas fa-download"></i>
                    </a>
                    <button type="button"
                            class="btn btn-sm btn-outline-primary active-light"
                            data-bs-toggle="modal"
                            data-bs-target="#renameFileModal"
                            data-file-id="{{ f.id }}"
                            data-file-name="{{ f.name|default:f.original_filename }}"
                            title="Rename">
                      <i class="fas fa-pencil-alt"></i>
                    </button>
                    <button type="button"
                            class="btn btn-sm btn-outline-primary active-light"
                            data-bs-toggle="modal"
                            data-bs-target="#moveFileModal"
                            data-file-id="{{ f.id }}"
                            data-file-name="{{ f.name|default:f.original_filename }}"
                            title="Move">
                      <i class="fas fa-arrows-alt"></i>
                    </button>
                    <button type="button"
                            class="btn btn-sm btn-outline-danger active-light"
                            onclick="deleteFile({{ f.id }}, '{{ f.name|default:f.original_filename|escapejs }}')"
                            title="Delete">
                      <i class="fas fa-trash"></i>
                    </button>
                  </td>
                </tr>
              {% endfor %}

              {% if not subfolders and not files %}
                <tr>
                  <td colspan="5" class="text-center fw-light py-4">
                    <i class="fas fa-folder-open"></i> This folder is empty.
                  </td>
                </tr>
              {% endif %}

            </tbody>
          </table>
        </div>
      </div>
    </div>

  </div>
</div>

{# =========================================================================
                                    MODALS
========================================================================= #}

{# Upload modal #}
<div class="modal fade" id="uploadModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <form id="uploadForm" enctype="multipart/form-data">
        {% csrf_token %}
        <input type="hidden" name="folder_id" value="{{ current_folder.id|default:'' }}">
        <div class="modal-header">
          <h6 class="modal-title">Upload files</h6>
          <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body">
          <label class="form-label">Select one or more files</label>
          <input type="file" name="files" class="form-control" multiple required>
          <small class="fw-light">You can select multiple files at once.</small>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-outline-primary active-light" data-bs-dismiss="modal">Cancel</button>
          <button type="submit" class="btn btn-outline-primary active-light">
            <i class="fas fa-upload"></i> Upload
          </button>
        </div>
      </form>
    </div>
  </div>
</div>

{# New folder modal #}
<div class="modal fade" id="newFolderModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <form id="newFolderForm">
        {% csrf_token %}
        <input type="hidden" name="parent_id" value="{{ current_folder.id|default:'' }}">
        <div class="modal-header">
          <h6 class="modal-title">New folder</h6>
          <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body">
          <label class="form-label">Folder name</label>
          <input type="text" name="name" class="form-control" placeholder="e.g. Firewall APAC Rules" required>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-outline-primary active-light" data-bs-dismiss="modal">Cancel</button>
          <button type="submit" class="btn btn-outline-primary active-light">
            <i class="fas fa-folder-plus"></i> Create
          </button>
        </div>
      </form>
    </div>
  </div>
</div>

{# Rename file modal #}
<div class="modal fade" id="renameFileModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <form id="renameFileForm" data-target-id="">
        {% csrf_token %}
        <div class="modal-header">
          <h6 class="modal-title">Rename file</h6>
          <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body">
          <label class="form-label">New name</label>
          <input type="text" name="new_name" id="renameFileInput" class="form-control" required>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-outline-primary active-light" data-bs-dismiss="modal">Cancel</button>
          <button type="submit" class="btn btn-outline-primary active-light">
            <i class="fas fa-pencil-alt"></i> Rename
          </button>
        </div>
      </form>
    </div>
  </div>
</div>

{# Rename folder modal #}
<div class="modal fade" id="renameFolderModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <form id="renameFolderForm" data-target-id="">
        {% csrf_token %}
        <div class="modal-header">
          <h6 class="modal-title">Rename folder</h6>
          <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body">
          <label class="form-label">New name</label>
          <input type="text" name="new_name" id="renameFolderInput" class="form-control" required>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-outline-primary active-light" data-bs-dismiss="modal">Cancel</button>
          <button type="submit" class="btn btn-outline-primary active-light">
            <i class="fas fa-pencil-alt"></i> Rename
          </button>
        </div>
      </form>
    </div>
  </div>
</div>

{# Move single file modal #}
<div class="modal fade" id="moveFileModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <form id="moveFileForm" data-target-id="">
        {% csrf_token %}
        <div class="modal-header">
          <h6 class="modal-title">Move file: <span id="moveFileLabel"></span></h6>
          <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body">
          <label class="form-label">Target folder</label>
          <select name="target_folder_id" class="form-select">
            <option value="">(root)</option>
            {% for fld in all_folders %}
              <option value="{{ fld.id }}">{{ fld.path }}</option>
            {% endfor %}
          </select>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-outline-primary active-light" data-bs-dismiss="modal">Cancel</button>
          <button type="submit" class="btn btn-outline-primary active-light">
            <i class="fas fa-arrows-alt"></i> Move
          </button>
        </div>
      </form>
    </div>
  </div>
</div>

{# Move single folder modal #}
<div class="modal fade" id="moveFolderModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <form id="moveFolderForm" data-target-id="">
        {% csrf_token %}
        <div class="modal-header">
          <h6 class="modal-title">Move folder: <span id="moveFolderLabel"></span></h6>
          <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body">
          <label class="form-label">New parent folder</label>
          <select name="target_folder_id" class="form-select">
            <option value="">(root)</option>
            {% for fld in all_folders %}
              <option value="{{ fld.id }}">{{ fld.path }}</option>
            {% endfor %}
          </select>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-outline-primary active-light" data-bs-dismiss="modal">Cancel</button>
          <button type="submit" class="btn btn-outline-primary active-light">
            <i class="fas fa-arrows-alt"></i> Move
          </button>
        </div>
      </form>
    </div>
  </div>
</div>

{# Move SELECTION modal (batch) #}
<div class="modal fade" id="moveSelectionModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog">
    <div class="modal-content">
      <form id="moveSelectionForm">
        {% csrf_token %}
        <div class="modal-header">
          <h6 class="modal-title">Move <span id="moveSelectionCount">0</span> file(s)</h6>
          <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body">
          <label class="form-label">Target folder</label>
          <select name="target_folder_id" class="form-select">
            <option value="">(root)</option>
            {% for fld in all_folders %}
              <option value="{{ fld.id }}">{{ fld.path }}</option>
            {% endfor %}
          </select>
          <small class="fw-light d-block mt-2">
            All selected files will be moved to this folder.
          </small>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-outline-primary active-light" data-bs-dismiss="modal">Cancel</button>
          <button type="submit" class="btn btn-outline-primary active-light">
            <i class="fas fa-arrows-alt"></i> Move
          </button>
        </div>
      </form>
    </div>
  </div>
</div>

{% endblock %}

{% block scripts %}
<script>
  // ================================================================
  //  Common helpers
  // ================================================================
  // Read CSRF from any form's hidden input on the page (the modals
  // always render at least one). We use this for every fetch call.
  function getCsrfToken() {
    const el = document.querySelector('[name=csrfmiddlewaretoken]');
    return el ? el.value : '';
  }

  function showSuccess(msg) {
    iziToast.success({ title: 'Success', message: msg });
  }
  function showError(msg) {
    iziToast.error({ title: 'Error', message: msg });
  }

  // Returns the array of file ids whose checkbox is currently ticked.
  function getSelectedFileIds() {
    return Array.from(document.querySelectorAll('.file-checkbox:checked'))
                .map(cb => cb.value);
  }

  // ================================================================
  //  Selection state: counter, button enable/disable, tri-state header
  // ================================================================
  function refreshSelectionState() {
    const ids = getSelectedFileIds();
    const count = ids.length;
    const totalBoxes = document.querySelectorAll('.file-checkbox').length;

    // Update every counter span (we have one per button)
    document.querySelectorAll('.selected-count').forEach(el => {
      el.textContent = count;
    });

    // Enable/disable batch buttons
    ['downloadSelectedBtn', 'moveSelectedBtn', 'deleteSelectedBtn'].forEach(id => {
      const btn = document.getElementById(id);
      if (btn) btn.disabled = (count === 0);
    });

    // Tri-state "select all" header checkbox
    const selectAll = document.getElementById('selectAll');
    if (!selectAll) return;
    if (totalBoxes === 0 || count === 0) {
      selectAll.checked = false;
      selectAll.indeterminate = false;
    } else if (count === totalBoxes) {
      selectAll.checked = true;
      selectAll.indeterminate = false;
    } else {
      selectAll.checked = false;
      selectAll.indeterminate = true;
    }
  }

  // ================================================================
  //  Single-file delete  (matches the existing pattern with iziToast.question)
  // ================================================================
  function deleteFile(fileId, fileName) {
    iziToast.question({
      timeout: 20000,
      close: false,
      overlay: true,
      toastOnce: true,
      id: 'question',
      zindex: 999,
      title: 'Confirm',
      message: `Are you sure you want to delete file "${fileName}"?`,
      position: 'center',
      buttons: [
        ['<button><b>YES</b></button>', function (instance, toast) {
          instance.hide({ transitionOut: 'fadeOut' }, toast, 'button');
          const url = '{% url "delete_file" file_id=0 %}'.replace('/0/', `/${fileId}/`);
          fetch(url, {
            method: 'POST',
            headers: {
              'X-CSRFToken': getCsrfToken(),
              'X-Requested-With': 'XMLHttpRequest'
            }
          })
          .then(r => r.json())
          .then(data => {
            if (data.status) {
              showSuccess(data.message);
              setTimeout(() => window.location.reload(), 1000);
            } else {
              showError(data.message);
            }
          })
          .catch(() => showError('An error occurred while deleting the file.'));
        }, true],
        ['<button>NO</button>', function (instance, toast) {
          instance.hide({ transitionOut: 'fadeOut' }, toast, 'button');
        }]
      ]
    });
  }

  // ================================================================
  //  Single-folder delete
  // ================================================================
  function deleteFolder(folderId, folderName) {
    iziToast.question({
      timeout: 20000,
      close: false,
      overlay: true,
      toastOnce: true,
      id: 'question',
      zindex: 999,
      title: 'Confirm',
      message: `Delete folder "${folderName}" and all its contents?`,
      position: 'center',
      buttons: [
        ['<button><b>YES</b></button>', function (instance, toast) {
          instance.hide({ transitionOut: 'fadeOut' }, toast, 'button');
          const url = '{% url "delete_folder" folder_id=0 %}'.replace('/0/', `/${folderId}/`);
          fetch(url, {
            method: 'POST',
            headers: {
              'X-CSRFToken': getCsrfToken(),
              'X-Requested-With': 'XMLHttpRequest'
            }
          })
          .then(r => r.json())
          .then(data => {
            if (data.status) {
              showSuccess(data.message);
              setTimeout(() => window.location.reload(), 1000);
            } else {
              showError(data.message);
            }
          })
          .catch(() => showError('An error occurred while deleting the folder.'));
        }, true],
        ['<button>NO</button>', function (instance, toast) {
          instance.hide({ transitionOut: 'fadeOut' }, toast, 'button');
        }]
      ]
    });
  }

  // ================================================================
  //  AJAX form submitter for single-file/folder modals
  // ================================================================
  function ajaxSubmitForm(form, url) {
    const formData = new FormData(form);
    return fetch(url, {
      method: 'POST',
      headers: {
        'X-CSRFToken': getCsrfToken(),
        'X-Requested-With': 'XMLHttpRequest'
      },
      body: formData
    })
    .then(r => r.json())
    .then(data => {
      if (data.status) {
        showSuccess(data.message);
        const modal = form.closest('.modal');
        if (modal) bootstrap.Modal.getInstance(modal).hide();
        setTimeout(() => window.location.reload(), 1000);
      } else {
        showError(data.message || 'Request failed.');
      }
    })
    .catch(() => showError('Request failed.'));
  }

  // ================================================================
  //  Modal pre-fill on open
  // ================================================================
  document.addEventListener('show.bs.modal', function (event) {
    const modal = event.target;
    const trigger = event.relatedTarget;
    if (!trigger) return;

    if (modal.id === 'renameFileModal') {
      document.getElementById('renameFileForm').dataset.targetId = trigger.getAttribute('data-file-id');
      document.getElementById('renameFileInput').value = trigger.getAttribute('data-file-name');
    }
    if (modal.id === 'renameFolderModal') {
      document.getElementById('renameFolderForm').dataset.targetId = trigger.getAttribute('data-folder-id');
      document.getElementById('renameFolderInput').value = trigger.getAttribute('data-folder-name');
    }
    if (modal.id === 'moveFileModal') {
      document.getElementById('moveFileForm').dataset.targetId = trigger.getAttribute('data-file-id');
      document.getElementById('moveFileLabel').textContent = trigger.getAttribute('data-file-name');
    }
    if (modal.id === 'moveFolderModal') {
      document.getElementById('moveFolderForm').dataset.targetId = trigger.getAttribute('data-folder-id');
      document.getElementById('moveFolderLabel').textContent = trigger.getAttribute('data-folder-name');
    }
  });

  // ================================================================
  //  Wire up everything once the DOM is ready
  // ================================================================
  document.addEventListener('DOMContentLoaded', function () {

    // ---- Single-action form submissions ------------------------------
    document.getElementById('uploadForm')?.addEventListener('submit', function (e) {
      e.preventDefault();
      ajaxSubmitForm(this, '{% url "upload_file" %}');
    });

    document.getElementById('newFolderForm')?.addEventListener('submit', function (e) {
      e.preventDefault();
      ajaxSubmitForm(this, '{% url "create_folder" %}');
    });

    document.getElementById('renameFileForm')?.addEventListener('submit', function (e) {
      e.preventDefault();
      const id = this.dataset.targetId;
      const url = '{% url "rename_file" file_id=0 %}'.replace('/0/', `/${id}/`);
      ajaxSubmitForm(this, url);
    });

    document.getElementById('renameFolderForm')?.addEventListener('submit', function (e) {
      e.preventDefault();
      const id = this.dataset.targetId;
      const url = '{% url "rename_folder" folder_id=0 %}'.replace('/0/', `/${id}/`);
      ajaxSubmitForm(this, url);
    });

    document.getElementById('moveFileForm')?.addEventListener('submit', function (e) {
      e.preventDefault();
      const id = this.dataset.targetId;
      const url = '{% url "move_file" file_id=0 %}'.replace('/0/', `/${id}/`);
      ajaxSubmitForm(this, url);
    });

    document.getElementById('moveFolderForm')?.addEventListener('submit', function (e) {
      e.preventDefault();
      const id = this.dataset.targetId;
      const url = '{% url "move_folder" folder_id=0 %}'.replace('/0/', `/${id}/`);
      ajaxSubmitForm(this, url);
    });

    // ---- Selection wiring --------------------------------------------
    document.querySelectorAll('.file-checkbox').forEach(cb => {
      cb.addEventListener('change', refreshSelectionState);
    });

    const selectAll = document.getElementById('selectAll');
    if (selectAll) {
      selectAll.addEventListener('change', function () {
        document.querySelectorAll('.file-checkbox').forEach(cb => {
          cb.checked = selectAll.checked;
        });
        refreshSelectionState();
      });
    }

    // ---- Batch DOWNLOAD: builds a hidden form and submits it so the
    //      browser handles the file-download dialog natively
    const downloadBtn = document.getElementById('downloadSelectedBtn');
    if (downloadBtn) {
      downloadBtn.addEventListener('click', function () {
        const ids = getSelectedFileIds();
        if (ids.length === 0) return;

        const form = document.createElement('form');
        form.method = 'POST';
        form.action = '{% url "download_files_zip" %}';
        form.style.display = 'none';

        const csrfInput = document.createElement('input');
        csrfInput.type = 'hidden';
        csrfInput.name = 'csrfmiddlewaretoken';
        csrfInput.value = getCsrfToken();
        form.appendChild(csrfInput);

        ids.forEach(id => {
          const input = document.createElement('input');
          input.type = 'hidden';
          input.name = 'file_ids';
          input.value = id;
          form.appendChild(input);
        });

        document.body.appendChild(form);
        form.submit();
        document.body.removeChild(form);
      });
    }

    // ---- Batch MOVE: open the selection modal and let its submit
    //      handler do the AJAX work
    const moveBtn = document.getElementById('moveSelectedBtn');
    if (moveBtn) {
      moveBtn.addEventListener('click', function () {
        const ids = getSelectedFileIds();
        if (ids.length === 0) return;

        document.getElementById('moveSelectionCount').textContent = ids.length;
        const modalEl = document.getElementById('moveSelectionModal');
        const modal = bootstrap.Modal.getOrCreateInstance(modalEl);
        modal.show();
      });
    }

    document.getElementById('moveSelectionForm')?.addEventListener('submit', function (e) {
      e.preventDefault();
      const ids = getSelectedFileIds();
      if (ids.length === 0) {
        showError('No files selected.');
        return;
      }

      const formData = new FormData(this);
      ids.forEach(id => formData.append('file_ids', id));

      fetch('{% url "move_files_batch" %}', {
        method: 'POST',
        headers: {
          'X-CSRFToken': getCsrfToken(),
          'X-Requested-With': 'XMLHttpRequest'
        },
        body: formData
      })
      .then(r => r.json())
      .then(data => {
        if (data.status) {
          showSuccess(data.message);
          bootstrap.Modal.getInstance(document.getElementById('moveSelectionModal')).hide();
          setTimeout(() => window.location.reload(), 1000);
        } else {
          showError(data.message || 'Move failed.');
        }
      })
      .catch(() => showError('An error occurred while moving the files.'));
    });

    // ---- Batch DELETE: confirm with iziToast.question, then AJAX
    const deleteBtn = document.getElementById('deleteSelectedBtn');
    if (deleteBtn) {
      deleteBtn.addEventListener('click', function () {
        const ids = getSelectedFileIds();
        if (ids.length === 0) return;

        iziToast.question({
          timeout: 20000,
          close: false,
          overlay: true,
          toastOnce: true,
          id: 'question',
          zindex: 999,
          title: 'Confirm',
          message: `Are you sure you want to delete ${ids.length} selected file(s)?`,
          position: 'center',
          buttons: [
            ['<button><b>YES</b></button>', function (instance, toast) {
              instance.hide({ transitionOut: 'fadeOut' }, toast, 'button');

              const formData = new FormData();
              ids.forEach(id => formData.append('file_ids', id));

              fetch('{% url "delete_files_batch" %}', {
                method: 'POST',
                headers: {
                  'X-CSRFToken': getCsrfToken(),
                  'X-Requested-With': 'XMLHttpRequest'
                },
                body: formData
              })
              .then(r => r.json())
              .then(data => {
                if (data.status) {
                  showSuccess(data.message);
                  setTimeout(() => window.location.reload(), 1000);
                } else {
                  showError(data.message || 'Delete failed.');
                }
              })
              .catch(() => showError('An error occurred while deleting the files.'));
            }, true],
            ['<button>NO</button>', function (instance, toast) {
              instance.hide({ transitionOut: 'fadeOut' }, toast, 'button');
            }]
          ]
        });
      });
    }

    // Initial render of selection state
    refreshSelectionState();
  });
</script>
{% endblock %}
