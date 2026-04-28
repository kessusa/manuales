{# 
  File manager template.

  Location in project: templates/rss/file_manager.html
  (Or wherever your project keeps templates for the 'rss' app.)

  Assumptions:
    - You extend a base template that loads Bootstrap 5 and Bootstrap Icons.
    - The base template has a {% block content %} placeholder.
#}
{% extends "base.html" %}
{% load humanize %}

{% block content %}
<div class="container-fluid py-3">

  {# Breadcrumb navigation #}
  <nav aria-label="breadcrumb" class="mb-3">
    <ol class="breadcrumb">
      <li class="breadcrumb-item">
        <a href="{% url 'rss:file_manager' %}" class="text-success">
          <i class="bi bi-house-door-fill"></i> Home
        </a>
      </li>
      {% for crumb in breadcrumbs %}
        {% if forloop.last %}
          <li class="breadcrumb-item active" aria-current="page">{{ crumb.name }}</li>
        {% else %}
          <li class="breadcrumb-item">
            <a href="{% url 'rss:file_manager_folder' folder_id=crumb.id %}" class="text-success">
              {{ crumb.name }}
            </a>
          </li>
        {% endif %}
      {% endfor %}
      {% if not current_folder %}
        <li class="breadcrumb-item active" aria-current="page">File Manager</li>
      {% endif %}
    </ol>
  </nav>

  {# Flash messages #}
  {% if messages %}
    {% for message in messages %}
      <div class="alert alert-{{ message.tags|default:'info' }} alert-dismissible fade show" role="alert">
        {{ message }}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
      </div>
    {% endfor %}
  {% endif %}

  {# Main card containing the file/folder listing #}
  <div class="card shadow-sm">
    <div class="card-header bg-white d-flex justify-content-between align-items-center">
      <h5 class="mb-0">File Manager Overview</h5>
      <div class="btn-group">
        <button class="btn btn-sm btn-outline-success" data-bs-toggle="modal" data-bs-target="#newFolderModal">
          <i class="bi bi-folder-plus"></i> New folder
        </button>
        <button class="btn btn-sm btn-success" data-bs-toggle="modal" data-bs-target="#uploadModal">
          <i class="bi bi-upload"></i> Upload
        </button>
      </div>
    </div>

    <div class="table-responsive">
      <table class="table table-hover mb-0 align-middle">
        <thead class="table-light">
          <tr>
            <th>Name</th>
            <th class="text-end" style="width: 220px;">Actions</th>
          </tr>
        </thead>
        <tbody>

          {# 'Up' link to parent folder #}
          {% if current_folder %}
            <tr>
              <td colspan="2">
                {% if current_folder.parent %}
                  <a href="{% url 'rss:file_manager_folder' folder_id=current_folder.parent.id %}" class="text-muted">
                    <i class="bi bi-arrow-90deg-up"></i> ..
                  </a>
                {% else %}
                  <a href="{% url 'rss:file_manager' %}" class="text-muted">
                    <i class="bi bi-arrow-90deg-up"></i> ..
                  </a>
                {% endif %}
              </td>
            </tr>
          {% endif %}

          {# Subfolders #}
          {% for folder in subfolders %}
            <tr>
              <td>
                <i class="bi bi-folder-fill text-secondary me-2"></i>
                <a href="{% url 'rss:file_manager_folder' folder_id=folder.id %}" class="text-success text-decoration-none">
                  {{ folder.name }}
                </a>
                <small class="text-muted ms-2">{{ folder.files.count }} file(s)</small>
              </td>
              <td class="text-end">
                <form method="post"
                      action="{% url 'rss:delete_folder' folder_id=folder.id %}"
                      class="d-inline"
                      onsubmit="return confirm('Delete folder &quot;{{ folder.name }}&quot; and all its contents?');">
                  {% csrf_token %}
                  <button type="submit" class="btn btn-sm btn-outline-danger" title="Delete folder">
                    <i class="bi bi-trash"></i>
                  </button>
                </form>
              </td>
            </tr>
          {% endfor %}

          {# Files #}
          {% for f in files %}
            <tr>
              <td>
                <i class="bi bi-file-earmark me-2"></i>
                <span>{{ f.original_filename }}</span>
                <small class="text-muted ms-2">{{ f.size|filesizeformat }}</small>
              </td>
              <td class="text-end">
                <a href="{% url 'rss:download_file' file_id=f.id %}"
                   class="btn btn-sm btn-outline-primary"
                   title="Download">
                  <i class="bi bi-download"></i>
                </a>
                <form method="post"
                      action="{% url 'rss:delete_file' file_id=f.id %}"
                      class="d-inline"
                      onsubmit="return confirm('Delete &quot;{{ f.original_filename }}&quot;?');">
                  {% csrf_token %}
                  <button type="submit" class="btn btn-sm btn-outline-danger" title="Delete">
                    <i class="bi bi-trash"></i>
                  </button>
                </form>
              </td>
            </tr>
          {% endfor %}

          {# Empty state #}
          {% if not subfolders and not files %}
            <tr>
              <td colspan="2" class="text-center text-muted py-4">
                <i class="bi bi-folder-x"></i> This folder is empty.
              </td>
            </tr>
          {% endif %}

        </tbody>
      </table>
    </div>
  </div>
</div>

{# Upload modal #}
<div class="modal fade" id="uploadModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog">
    <form method="post"
          action="{% url 'rss:upload_file' %}"
          enctype="multipart/form-data"
          class="modal-content">
      {% csrf_token %}
      <input type="hidden" name="folder_id" value="{{ current_folder.id|default:'' }}">
      <div class="modal-header">
        <h5 class="modal-title">Upload files</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <label class="form-label">Select one or more files</label>
        <input type="file" name="files" class="form-control" multiple required>
        <small class="text-muted">You can select multiple files at once.</small>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
        <button type="submit" class="btn btn-success">
          <i class="bi bi-upload"></i> Upload
        </button>
      </div>
    </form>
  </div>
</div>

{# New folder modal #}
<div class="modal fade" id="newFolderModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog">
    <form method="post" action="{% url 'rss:create_folder' %}" class="modal-content">
      {% csrf_token %}
      <input type="hidden" name="parent_id" value="{{ current_folder.id|default:'' }}">
      <div class="modal-header">
        <h5 class="modal-title">New folder</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <label class="form-label">Folder name</label>
        <input type="text" name="name" class="form-control" placeholder="e.g. Firewall APAC Rules" required>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
        <button type="submit" class="btn btn-success">
          <i class="bi bi-folder-plus"></i> Create
        </button>
      </div>
    </form>
  </div>
</div>

{% endblock %}
