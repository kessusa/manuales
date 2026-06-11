import operator
import time
from functools import reduce

from django.core.management.base import BaseCommand
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from API_cnx.illumio import IllumioAPI
from rss.models import Service, ServiceContent, TaskUpdateDate


def process_batch(data, batch_size=1000):
    records_to_create = []
    records_to_update = []

    existing_ip_list = (Service.objects.filter(reduce(
        operator.or_, (
            Q(
                service_identifier=obj.service_identifier,
                region=obj.region,
                infra_type=obj.infra_type
            ) for obj in data
        )
    )).values('id', 'service_identifier', 'region', 'infra_type'))

    lookup = {
        (item['service_identifier'], item['region'], item['infra_type']): item['id']
        for item in existing_ip_list
    }

    for obj in data:
        key = (obj.service_identifier, obj.region, obj.infra_type)
        if key in lookup:
            obj.id = lookup[key]
            records_to_update.append(obj)
        else:
            records_to_create.append(obj)

    with transaction.atomic():
        Service.objects.bulk_update(
            records_to_update,
            fields=['name', 'description', 'updated_at', 'deleted'],
            batch_size=batch_size
        )

    with transaction.atomic():
        Service.objects.bulk_create(records_to_create, ignore_conflicts=True, batch_size=batch_size)


def process_batch_child(data, batch_size=1000):
    records_to_create_child = []
    records_to_update_child = []

    existing_srv_content = (ServiceContent.objects.filter(reduce(
        operator.or_, (
            Q(
                port=obj.port,
                to_port=obj.to_port,          # <-- to_port
                proto=obj.proto,
                region=obj.region,
                infra_type=obj.infra_type
            ) for obj in data
        )
    )).values('id', 'port', 'to_port', 'proto', 'region', 'infra_type'))   # <-- to_port

    lookup = {
        (item['port'], item['to_port'], item['proto'], item['region'], item['infra_type']): item['id']   # <-- to_port
        for item in existing_srv_content
    }

    for obj in data:
        key = (obj.port, obj.to_port, obj.proto, obj.region, obj.infra_type)   # <-- to_port
        if key in lookup:
            obj.id = lookup[key]
            records_to_update_child.append(obj)
        else:
            records_to_create_child.append(obj)

    with transaction.atomic():
        ServiceContent.objects.bulk_update(
            records_to_update_child,
            fields=['proto_letter', 'updated_at', 'deleted'],
            batch_size=batch_size
        )

    with transaction.atomic():
        created = ServiceContent.objects.bulk_create(
            records_to_create_child, ignore_conflicts=True, batch_size=batch_size   # <-- FIX: era records_to_update_child
        )

    service_pks = set(obj.id for obj in records_to_update_child) | set(obj.id for obj in created)

    return service_pks


# illumio_service
class Command(BaseCommand):
    help = 'Update Illumio Services data'

    def add_arguments(self, parser):
        parser.add_argument('--region', type=str, default='emea')
        parser.add_argument('--infra', type=str, default='iv1')

    def handle(self, *args, **options):
        region = options['region']
        infra = options['infra']

        created_at = timezone.now()

        task_instance = TaskUpdateDate.objects.create(name=f'illumio_service', created_at=created_at)

        # Define Illumio object
        obj_illumio = IllumioAPI(env=region, infra_type=infra)

        # # Collection name
        collection_name = 'sec_policy/draft/services'

        # # Total count of collections
        total = int(obj_illumio.get_total(collection_name=collection_name))

        task_instance.message = {'region': region, 'infra': infra, 'total': total}
        task_instance.save()

        if total > 500:

            # # Create a Job Request
            retry_after_time, job_id = obj_illumio.pull_job(collection_name=collection_name, total=total)

            while True:
                status, result = obj_illumio.get_job(job_id)

                if status == 'done':
                    file_id = result['href'].replace('/orgs/1/datafiles/', '')
                    result = obj_illumio.get_datafiles(file_id)
                    break

                time.sleep(retry_after_time)
        else:
            result = obj_illumio.get_collections(collection_name=collection_name, total=total)

        BATCH_SIZE = 1000

        if result:
            if total < BATCH_SIZE:
                for service in result:
                    service_content = service.pop('service_ports', [])

                    service_obj, _ = Service.objects.update_or_create(
                        service_identifier=service['href'].replace(
                            '/orgs/1/sec_policy/draft/services/', '') if service.get('href') else None,
                        region=region,
                        infra_type=infra,
                        defaults={
                            'name': service.get('name').replace(' ', '_'),
                            'description': service.get('description'),
                            'updated_at': timezone.now(),
                            'deleted': False
                        }
                    )

                    # # Clear all links
                    service_obj.content.clear()

                    if service_content:
                        if len(service_content) < BATCH_SIZE:
                            for srv in service_content:
                                srv_content_instance, _ = ServiceContent.objects.update_or_create(
                                    region=region,
                                    infra_type=infra,
                                    port=srv.get('port'),
                                    to_port=srv.get('to_port'),          # <-- to_port
                                    proto=srv.get('proto'),
                                    proto_letter='TCP' if srv['proto'] == 6 else 'UDP' if srv['proto'] == 17 else srv['proto'],
                                    defaults={
                                        'updated_at': timezone.now(),
                                        'deleted': False
                                    }
                                )

                                service_obj.content.add(srv_content_instance)
                        else:
                            batch_child = []

                            for j, srv in enumerate(service_content, start=1):
                                batch_child.append(
                                    ServiceContent(
                                        region=region,
                                        infra_type=infra,
                                        port=srv.get('port'),
                                        to_port=srv.get('to_port'),      # <-- to_port
                                        proto=srv.get('proto'),
                                        proto_letter='TCP' if srv['proto'] == 6 else 'UDP' if srv['proto'] == 17 else srv['proto'],
                                        updated_at=timezone.now(),
                                        deleted=False
                                    )
                                )

                                if j % BATCH_SIZE == 0:
                                    service_pks = process_batch_child(batch_child)
                                    service_obj.content.add(*service_pks)

                                    batch_child = []

                            if batch_child:
                                service_pks = process_batch_child(batch_child)
                                service_obj.content.add(*service_pks)
            else:
                batch = []
                service_links = []
                for i, service in enumerate(result, start=1):

                    service_identifier = service['href'].replace(
                        '/orgs/1/sec_policy/draft/services/', '') if service.get('href') else None
                    service_ports = service.pop('service_ports', [])

                    if service_ports:
                        service_links.append({
                            'identifier': service_identifier,
                            'contents': service_ports
                        })

                    if len(service_ports) < BATCH_SIZE:
                        for srv in service_ports:
                            srv_content_instance, _ = ServiceContent.objects.update_or_create(
                                region=region,
                                infra_type=infra,
                                port=srv.get('port'),
                                to_port=srv.get('to_port'),              # <-- to_port
                                proto=srv.get('proto'),
                                proto_letter='TCP' if srv['proto'] == 6 else 'UDP' if srv['proto'] == 17 else srv['proto'],
                                defaults={
                                    'updated_at': timezone.now(),
                                    'deleted': False
                                }
                            )
                    else:
                        batch_child = []

                        for j, srv in enumerate(service_ports, start=1):
                            batch_child.append(
                                ServiceContent(
                                    region=region,
                                    infra_type=infra,
                                    port=srv.get('port'),
                                    to_port=srv.get('to_port'),          # <-- to_port
                                    proto=srv.get('proto'),
                                    proto_letter='TCP' if srv['proto'] == 6 else 'UDP' if srv['proto'] == 17 else srv['proto'],
                                    updated_at=timezone.now(),
                                    deleted=False
                                )
                            )

                            if j % BATCH_SIZE == 0:
                                process_batch_child(batch_child)

                                batch_child = []

                        if batch_child:
                            process_batch_child(batch_child)

                    batch.append(
                        Service(
                            service_identifier=service_identifier,
                            region=region,
                            infra_type=infra,
                            name=service.get('name').replace(' ', '_'),
                            description=service.get('description'),
                            updated_at=timezone.now(),
                            deleted=False
                        )
                    )

                    if i % BATCH_SIZE == 0:
                        process_batch(batch)
                        batch = []

                if batch:
                    process_batch(batch)

                if service_links:
                    for item in service_links:
                        service_instance = Service.objects.get(
                            service_identifier=item['identifier'],
                            region=region,
                            infra_type=infra
                        )
                        service_instance.content.clear()

                        for content in item['contents']:
                            service_content = ServiceContent.objects.filter(
                                region=region,
                                infra_type=infra,
                                port=content.get('port', None),
                                to_port=content.get('to_port', None),    # <-- to_port
                                proto=content.get('proto', None),
                            )
                            service_instance.content.add(*service_content)

        finish_at = timezone.now()

        Service.objects.filter(region=region, infra_type=infra).exclude(
            updated_at__date__range=[created_at.date(), finish_at.date()]
        ).update(deleted=True)

        ServiceContent.objects.filter(region=region, infra_type=infra).exclude(
            updated_at__date__range=[created_at.date(), finish_at.date()]
        ).update(deleted=True)

        task_instance.finish_at = finish_at
        task_instance.save()
