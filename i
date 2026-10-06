from datetime import datetime

import pytz
from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils import timezone

from API_cnx.checkpoint import CheckPoint
from rss.models import PushFirewallLog, TaskUpdateDate

SUCCESS_STATUSES = ('succeeded', 'succeeded with warnings')


def get_push_status(install_result):
    return 'success' if (install_result or {}).get('status') in SUCCESS_STATUSES else 'failed'


def build_push_log(install_result):
    install_result = install_result or {}
    status = install_result.get('status')
    progress = install_result.get('progress')
    lines = ['=== Push result ===', '', f'status: {status}', f'progress: {progress}']

    for detail in install_result.get('details') or []:
        gateway = detail.get('gatewayName')
        if gateway:
            gateway_status = detail.get('statusDescription') or detail.get('statusCode')
            lines.append(f'{gateway}: {gateway_status}')
        for stage in detail.get('stagesInfo') or []:
            for item in stage.get('messages') or []:
                item_type = item.get('type')
                item_message = item.get('message')
                lines.append(f'{item_type}: {item_message}')
        for key in ('errors', 'warnings'):
            lines += [f'{key[:-1]}: {item}' for item in detail.get(key) or []]

    return '\n'.join(lines)


def get_push_policies(log_rows):
    # log_rows are ordered by id: only the latest preview of each policy decides the push
    latest_logs = {}
    for log_id, push_firewall_id, policy_name, domain, preview_status, push_status in log_rows:
        latest_logs[push_firewall_id] = (policy_name, domain, log_id, preview_status, push_status)

    return [
        [policy_name, domain, log_id]
        for policy_name, domain, log_id, preview_status, push_status in latest_logs.values()
        if preview_status == 'success' and push_status == 'not started yet'
    ]


def push_policy(policy_name, domain, log_id, connector=CheckPoint):
    # Returns the error found for this policy, None when the push succeeds
    try:
        # install_policy_package handles its own login / logout: one connector per call
        obj_checkpoint = connector()
        install_result = obj_checkpoint.install_policy_package(obj_checkpoint.base_url_v1, domain, policy_name)
        push_log = build_push_log(install_result)
    except Exception as error:
        install_result = None
        push_log = f'install-policy failed ({error})'

    push_status = get_push_status(install_result)
    PushFirewallLog.objects.filter(
        id=log_id
    ).update(
        transaction_push_id=(install_result or {}).get('task_id'),
        push_status=push_status,
        push_log=push_log,
        updated_at=timezone.now()
    )

    if push_status == 'failed':
        return f'{domain}/{policy_name}: push failed'
    return None


# push_firewall_checkpoint
class Command(BaseCommand):
    help = 'Push Firewall Check Point'

    def handle(self, *args, **options):

        task_instance = TaskUpdateDate.objects.create(name='push_firewall_checkpoint', created_at=timezone.now())

        # Time
        hour_push = datetime.now(pytz.timezone('Europe/Paris')).hour
        policies_query = PushFirewallLog.objects.filter(
            Q(policy_log__scheduled_time__contains=[f'{hour_push:02d}:00'])
            & Q(policy_log__ticket__isnull=False)
            & Q(policy_log__policy__technology='CHECKPOINT')
            & Q(policy_log__auto=True)
            & Q(policy_log__freeze=False)
            & Q(updated_at__date=datetime.today().date())
        )
        push_policies = get_push_policies(
            policies_query.values_list(
                'id', 'policy_log_id', 'policy_log__policy__tag_name', 'policy_log__policy__domain',
                'preview_status', 'push_status'
            ).order_by('id')
        )
        task_instance.message = {'policies': push_policies, 'errors': []}
        task_instance.save()

        for policy_name, domain, log_id in push_policies:
            error = push_policy(policy_name, domain, log_id)
            if error:
                task_instance.message['errors'].append(error)

        task_instance.finish_at = timezone.now()
        task_instance.save()
