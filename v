"""
Additional views for batch operations on files.

Append these to your existing rss/views.py.

Endpoints added:
    - move_files_batch():   move a selection of files to another folder
    - delete_files_batch(): delete a selection of files in one go
"""
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_POST

from filer.models import File, Folder

# Reuses _has_permission already defined in views.py


@login_required
@require_POST
def move_files_batch(request):
    """
    Move multiple files to a target folder in a single request.

    Expected POST data:
        - file_ids: list of File ids (multiple values, e.g. from checkboxes)
        - target_folder_id: optional id of the destination folder (empty -> root)
    """
    file_ids = request.POST.getlist('file_ids')
    target_folder_id = request.POST.get('target_folder_id') or None

    if not file_ids:
        return JsonResponse({'status': False, 'message': 'No files selected.'})

    target_folder = (
        Folder.objects.get(id=target_folder_id) if target_folder_id else None
    )

    # Verify the user can place files in the target folder
    if target_folder and not _has_permission(request.user, target_folder, 'can_add_children'):
        return JsonResponse({
            'status': False,
            'message': 'You cannot place files in the target folder.',
        })

    moved = 0
    skipped = 0
    for f in File.objects.filter(id__in=file_ids):
        # Skip files whose source folder the user cannot edit
        if f.folder and not _has_permission(request.user, f.folder, 'can_edit'):
            skipped += 1
            continue
        f.folder = target_folder
        f.save()
        moved += 1

    target_label = target_folder.name if target_folder else 'root'

    if skipped:
        return JsonResponse({
            'status': True,
            'message': f'{moved} file(s) moved to "{target_label}". '
                       f'{skipped} skipped due to permissions.',
        })
    return JsonResponse({
        'status': True,
        'message': f'{moved} file(s) moved to "{target_label}".',
    })


@login_required
@require_POST
def delete_files_batch(request):
    """
    Delete multiple files in a single request.

    Expected POST data:
        - file_ids: list of File ids (multiple values, e.g. from checkboxes)
    """
    file_ids = request.POST.getlist('file_ids')
    if not file_ids:
        return JsonResponse({'status': False, 'message': 'No files selected.'})

    deleted = 0
    skipped = 0
    for f in File.objects.filter(id__in=file_ids):
        # Skip files whose folder the user cannot edit
        if f.folder and not _has_permission(request.user, f.folder, 'can_edit'):
            skipped += 1
            continue
        f.delete()
        deleted += 1

    if skipped:
        return JsonResponse({
            'status': True,
            'message': f'{deleted} file(s) deleted. {skipped} skipped due to permissions.',
        })
    return JsonResponse({
        'status': True,
        'message': f'{deleted} file(s) deleted successfully.',
    })
