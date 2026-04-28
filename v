"""
File manager views.

Location in project: rss/views.py
(Or append these views to your existing rss/views.py file.)

These views provide a custom UI on top of django-filer's data models:
    - filer.models.Folder  -> folder hierarchy stored in DB
    - filer.models.File    -> file objects with metadata + storage backend
"""
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import FileResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from filer.models import File, Folder


def _build_breadcrumbs(folder):
    """Return the chain of ancestor folders from root down to the given folder."""
    breadcrumbs = []
    node = folder
    while node is not None:
        breadcrumbs.insert(0, node)
        node = node.parent
    return breadcrumbs


def _redirect_to_folder(folder_id):
    """Helper to redirect back to the current folder view after an action."""
    if folder_id:
        return redirect('rss:file_manager_folder', folder_id=folder_id)
    return redirect('rss:file_manager')


@login_required
def file_manager(request, folder_id=None):
    """
    Render the file manager view.

    If folder_id is provided, list its subfolders and files.
    Otherwise, list root-level folders and files (those without a parent).
    """
    if folder_id:
        current_folder = get_object_or_404(Folder, id=folder_id)
        subfolders = current_folder.children.all().order_by('name')
        files = current_folder.files.all().order_by('original_filename')
    else:
        current_folder = None
        subfolders = Folder.objects.filter(parent__isnull=True).order_by('name')
        files = File.objects.filter(folder__isnull=True).order_by('original_filename')

    context = {
        'current_folder': current_folder,
        'subfolders': subfolders,
        'files': files,
        'breadcrumbs': _build_breadcrumbs(current_folder),
    }
    return render(request, 'rss/file_manager.html', context)


@login_required
def download_file(request, file_id):
    """Stream a file as an attachment so the browser triggers a download."""
    file_obj = get_object_or_404(File, id=file_id)
    return FileResponse(
        file_obj.file.open('rb'),
        as_attachment=True,
        filename=file_obj.original_filename,
    )


@login_required
@require_POST
def upload_file(request):
    """
    Handle file uploads. Supports multiple files in a single request.

    Expects:
        - POST field 'folder_id' (optional): target folder id
        - FILES field 'files': one or more files
    """
    folder_id = request.POST.get('folder_id') or None
    target_folder = Folder.objects.get(id=folder_id) if folder_id else None

    uploaded = request.FILES.getlist('files')
    if not uploaded:
        messages.warning(request, 'No files were selected.')
        return _redirect_to_folder(folder_id)

    for uploaded_file in uploaded:
        File.objects.create(
            file=uploaded_file,
            folder=target_folder,
            original_filename=uploaded_file.name,
            owner=request.user,
        )

    messages.success(request, f'{len(uploaded)} file(s) uploaded successfully.')
    return _redirect_to_folder(folder_id)


@login_required
@require_POST
def create_folder(request):
    """Create a new folder, optionally nested under a parent folder."""
    name = request.POST.get('name', '').strip()
    parent_id = request.POST.get('parent_id') or None

    if not name:
        messages.error(request, 'Folder name is required.')
        return _redirect_to_folder(parent_id)

    parent = Folder.objects.get(id=parent_id) if parent_id else None
    Folder.objects.create(name=name, parent=parent, owner=request.user)

    messages.success(request, f'Folder "{name}" created.')
    return _redirect_to_folder(parent_id)


@login_required
@require_POST
def delete_file(request, file_id):
    """Delete a single file. The actual file on disk is removed by filer."""
    file_obj = get_object_or_404(File, id=file_id)
    parent_folder_id = file_obj.folder_id
    file_obj.delete()
    messages.success(request, 'File deleted.')
    return _redirect_to_folder(parent_folder_id)


@login_required
@require_POST
def delete_folder(request, folder_id):
    """
    Delete a folder and all its contents (recursive cascade is handled by filer).
    Redirects back to the parent folder, or root if no parent exists.
    """
    folder = get_object_or_404(Folder, id=folder_id)
    parent_folder_id = folder.parent_id
    folder.delete()
    messages.success(request, 'Folder deleted.')
    return _redirect_to_folder(parent_folder_id)
