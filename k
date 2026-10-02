import json
import traceback
from collections import defaultdict
from datetime import datetime, timedelta

import pytz
from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils import timezone

from API_cnx.checkpoint import CheckPoint
from rss.models import PushFirewall, PushFirewallLog, TaskUpdateDate

# Check Point show-task status -> PushFirewallLog.STATUS_CHOICES
TASK_STATUS_MAPPING = {
    'succeeded': 'success',
    'succeeded with warnings': 'warning',
    'partially succeeded': 'warning',
    'failed': 'failed',
}


def no_log(message, level=2):
    pass


def has_delete_action(changes):
    # Equivalent of FortiManager's 'action:DELETE' check, based on get_pending_changes output
    return any(change.get('action') == 'deleted' for change in changes or [])


def get_preview_status(message):
    # Returns (preview_status, internal_note)
    task = message.get('verify')
    if not task:
        return 'failed', None
    preview_status = TASK_STATUS_MAPPING.get(task.get('status'), 'pending')
    if preview_status != 'failed' and has_delete_action(message.get('changes')):
        return 'pending', 'ignored due a delete action'
    return preview_status, None


def preview_domain(obj_checkpoint, domain, policies, log=no_log):
    # policies: {tag_name: PushFirewall}. Returns the list of errors found in this domain.
    log(f'[{domain}] Login...')
    session_id = obj_checkpoint.login(domain)
    if not session_id:
        log(f'[{domain}] Login FAILED')
        return [f'{domain}: login failed']
    log(f'[{domain}] Login OK')

    errors = []
    try:
        for policy_name, tag_instance in policies.items():
            log(f'[{domain}] {policy_name}: verify-policy + show-task + show-changes...')
            message, transactions = obj_checkpoint.preview_policy_package(session_id, obj_checkpoint.base_url_v1, policy_name)

            if not message:
                log(f'[{domain}] {policy_name}: verify-policy FAILED (no task-id returned)')
                errors.append(f'{domain}/{policy_name}: verify-policy failed')
                continue

            task = message.get('verify') or {}
            changes = message.get('changes')
            changes_count = len(changes) if isinstance(changes, (list, dict)) else changes
            log(f'[{domain}] {policy_name}: task-id {transactions}, verify status: {task.get("status")}, '
                f'progress: {task.get("progress-percentage")}%')
            log(f'[{domain}] {policy_name}: pending changes: {changes_count}')
            log(json.dumps(message, indent=2, default=str), level=3)

            preview_status, internal_note = get_preview_status(message)
            log_entry = PushFirewallLog.objects.create(
                transaction_id=transactions,
                policy_log=tag_instance,
                preview_status=preview_status,
                preview_log=message,
                internal_note=internal_note,
            )
            log(f'[{domain}] {policy_name}: PushFirewallLog {log_entry.id} created, '
                f'preview_status={preview_status}, internal_note={internal_note}')

            if preview_status == 'failed':
                errors.append(f'{domain}/{policy_name}: preview failed')
    finally:
        obj_checkpoint.logout(session_id)
        log(f'[{domain}] Logout')

    return errors


# push_firewall_preview_checkpoint
class Command(BaseCommand):
    help = 'Push Firewall Preview Check Point'

    def add_arguments(self, parser):
        parser.add_argument('--hour', type=int, help='Override preview hour (0-23)')
        parser.add_argument('--tag', help='Preview this policy tag now, ignoring schedule filters (testing)')

    def log(self, message, level=2):
        # -v 2: step by step, -v 3: also the full preview_log JSON
        if self.verbosity >= level:
            self.stdout.write(message)

    def report(self, task_instance):
        errors = task_instance.message['errors']
        status = 'failed' if errors else 'success'
        self.stdout.write(f"Task {task_instance.id} finished with status: {status} "
                          f"({len(task_instance.message['policies'])} policies, {len(errors)} errors)")
        for error in errors:
            self.stderr.write(error)

    def handle(self, *args, **options):
        self.verbosity = options['verbosity']

        # 1. Task tracking
        task_instance = TaskUpdateDate.objects.create(name='push_firewall_preview_checkpoint', created_at=timezone.now())
        self.log(f'Task {task_instance.id} created')

        obj_checkpoint = CheckPoint()
        self.log(f'Check Point API: {obj_checkpoint.base_url_v1}')

        # 2. Select policies
        tag = options['tag']
        if tag:
            self.log(f'Manual run for tag {tag} (schedule filters ignored)')
            policies_query = PushFirewall.objects.filter(
                policy__tag_name=tag,
                policy__technology='CHECKPOINT',
            ).select_related('policy')
        else:
            hour_preview = options['hour']
            if hour_preview is None:
                hour_preview = (datetime.now(pytz.timezone('Europe/Paris')) + timedelta(hours=1)).hour
            current_day = datetime.today().strftime('%A').lower()
            hour_str = f'{hour_preview:02d}:00'
            self.log(f'Scheduled run for {hour_str} on {current_day}')

            policies_query = PushFirewall.objects.filter(
                Q(scheduled_time__contains=[hour_str])
                & Q(business_day__contains=current_day)
                & Q(auto=True)
                & Q(freeze=False)
                & Q(ticket__isnull=False)
                & Q(policy__technology='CHECKPOINT')
            ).select_related('policy')

        # 3. Group policies by domain: {domain: {tag_name: PushFirewall}}
        policies = defaultdict(dict)
        for push_firewall in policies_query:
            policies[push_firewall.policy.domain].setdefault(push_firewall.policy.tag_name, push_firewall)

        policy_list = [[policy_name, domain] for domain, tags in policies.items() for policy_name in tags]
        self.log(f'{len(policy_list)} policies found in {len(policies)} domains: {policy_list}')

        task_instance.message = {'policies': policy_list, 'errors': []}
        if not policies:
            task_instance.message['errors'].append('No policies found for the given criteria')
            task_instance.finish_at = timezone.now()
            task_instance.save()
            self.report(task_instance)
            return
        task_instance.save()

        # 4. Run the preview per domain
        for domain, domain_policies in policies.items():
            try:
                task_instance.message['errors'].extend(preview_domain(obj_checkpoint, domain, domain_policies, self.log))
            except Exception as error:
                task_instance.message['errors'].append(f'{domain}: {error}')
                self.log(traceback.format_exc())

        # 5. Finalize the task
        task_instance.finish_at = timezone.now()
        task_instance.save()
        self.report(task_instance)
