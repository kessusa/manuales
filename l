from collections import defaultdict
from datetime import datetime, timedelta

import pytz
from django.core.management.base import BaseCommand
from django.db.models import Max, Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from API_cnx.checkpoint import CheckPoint
from rss.models import PushFirewall, PushFirewallLog, TaskUpdateDate

DEFAULT_LOOKBACK_DAYS = 3

TASK_STATUS_MAPPING = {
    'succeeded': 'success',
    'succeeded with warnings': 'warning',
    'partially succeeded': 'warning',
    'failed': 'failed',
}


def has_delete_action(changes):
    return any(change.get('operation') == 'deleted' for change in changes or [])


def get_preview_status(verify_result, changes):
    status = (verify_result or {}).get('status')
    if not status:
        return 'failed', None
    preview_status = TASK_STATUS_MAPPING.get(status, 'pending')
    if preview_status != 'failed' and has_delete_action(changes):
        return 'pending', 'ignored due a delete action'
    return preview_status, None


def get_package_names(change):
    return {package if isinstance(package, str) else package.get('name') for package in change.get('policy_packages') or []}


def filter_changes_by_package(changes, policy_name):
    if changes is None:
        return None
    return [change for change in changes
            if not change.get('policy_packages') or policy_name in get_package_names(change)]


def published_after(session, last_install):
    publish_time = parse_datetime(session.get('publish_time') or '')
    if publish_time is None or timezone.is_naive(publish_time):
        return True
    return publish_time > last_install


def filter_changes_after_install(changes, last_install):
    if changes is None or last_install is None:
        return changes
    return [change for change in changes
            if not change.get('sessions') or any(published_after(session, last_install) for session in change['sessions'])]


def get_domain_from_date(policies, last_installs):
    install_dates = [last_installs.get(push_firewall.id) for push_firewall in policies.values()]
    if not install_dates or None in install_dates:
        return (timezone.now() - timedelta(days=DEFAULT_LOOKBACK_DAYS)).date().isoformat()
    return min(install_dates).date().isoformat()


def build_preview_log(verify_result, changes, format_changes):
    lines = ['=== Preview result ===', '']
    for detail in (verify_result or {}).get('details') or []:
        for key in ('errors', 'warnings'):
            lines += [f'{key[:-1]}: {item}' for item in detail.get(key) or []]

    if changes is None:
        lines.append('show-changes not available')
    else:
        lines += format_changes(changes).splitlines()
    return '\n'.join(lines)


def preview_domain(domain, policies, last_installs, connector=CheckPoint):
    errors = []

    try:
        obj_checkpoint = connector()
        changes = obj_checkpoint.get_pending_changes(
            obj_checkpoint.base_url_v1, domain, from_date=get_domain_from_date(policies, last_installs))
    except Exception as error:
        changes = None
        errors.append(f'{domain}: show-changes failed ({error})')

    for policy_name, tag_instance in policies.items():
        try:
            obj_checkpoint = connector()
            verify_result = obj_checkpoint.verify_policy_package(obj_checkpoint.base_url_v1, domain, policy_name)
        except Exception as error:
            errors.append(f'{domain}/{policy_name}: verify-policy failed ({error})')
            continue

        policy_changes = filter_changes_after_install(
            filter_changes_by_package(changes, policy_name), last_installs.get(tag_instance.id))
        preview_status, internal_note = get_preview_status(verify_result, policy_changes)

        PushFirewallLog.objects.create(
            transaction_id=verify_result.get('task_id'),
            policy_log=tag_instance,
            preview_status=preview_status,
            preview_log=build_preview_log(verify_result, policy_changes, obj_checkpoint.format_pending_changes),
            internal_note=internal_note,
        )

        if preview_status == 'failed':
            errors.append(f'{domain}/{policy_name}: preview failed')

    return errors


class Command(BaseCommand):
    help = 'Push Firewall Preview Check Point'

    def handle(self, *args, **options):
        task_instance = TaskUpdateDate.objects.create(name='push_firewall_preview_checkpoint', created_at=timezone.now())

        hour_preview = (datetime.now(pytz.timezone('Europe/Paris')) + timedelta(hours=1)).hour

        policies_query = PushFirewall.objects.filter(
            Q(scheduled_time__contains=[f'{hour_preview:02d}:00'])
            & Q(business_day__contains=datetime.today().strftime('%A').lower())
            & Q(auto=True)
            & Q(freeze=False)
            & Q(ticket__isnull=False)
            & Q(policy__technology='CHECKPOINT')
        ).select_related('policy')

        policies = defaultdict(dict)
        for push_firewall in policies_query:
            policies[push_firewall.policy.domain].setdefault(push_firewall.policy.tag_name, push_firewall)

        last_installs = dict(
            PushFirewallLog.objects.filter(policy_log_id__in=[push_firewall.id for push_firewall in policies_query], push_status='success')
            .values_list('policy_log')
            .annotate(last_install=Max('updated_at'))
        )

        task_instance.message = {
            'policies': [[policy_name, domain] for domain, tags in policies.items() for policy_name in tags],
            'errors': [],
        }
        task_instance.save()

        for domain, domain_policies in policies.items():
            try:
                task_instance.message['errors'].extend(preview_domain(domain, domain_policies, last_installs))
            except Exception as error:
                task_instance.message['errors'].append(f'{domain}: {error}')

        task_instance.finish_at = timezone.now()
        task_instance.save()
