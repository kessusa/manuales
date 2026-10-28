def build_access_request_ports(sn_ticket_id):
    """Return every AR service with its matching matrix ports, if any."""
    access_requests = AccessRequest.objects.filter(
        task__sn_ticket_id=sn_ticket_id
    ).order_by('ar_number').values_list('ar_number', 'services')

    ar_services = [
        (ar_number, protocol, port_number)
        for ar_number, services in access_requests
        for protocol, port_number in parse_services(services)
    ]

    service_keys = {
        (protocol.upper(), port_number)
        for _ar_number, protocol, port_number in ar_services
        if port_number.isdigit()
    }

    ports_by_service = defaultdict(list)
    if service_keys:
        matrix_ports = Port.objects.annotate(
            port_start=Cast(Func(F('port_number'), Value('-'), Value(1),
                                 function='SPLIT_PART', output_field=CharField()), IntegerField()),
            port_end=Cast(Func(F('port_number'), Value('-'), Value(-1),
                               function='SPLIT_PART', output_field=CharField()), IntegerField()),
        ).annotate(
            ar_service=Case(
                *[
                    When(
                        Q(protocol__iexact=protocol)
                        & Q(port_start__lte=int(port_number))
                        & Q(port_end__gte=int(port_number)),
                        then=Value(f'{protocol}_{port_number}'),
                    )
                    for protocol, port_number in service_keys
                ],
                default=None,
                output_field=CharField(),
            )
        ).exclude(ar_service__isnull=True)

        for matrix_port in matrix_ports:
            ports_by_service[matrix_port.ar_service].append(matrix_port)

    rows = []
    for ar_number, protocol, port_number in ar_services:
        matching_ports = ports_by_service.get(f'{protocol.upper()}_{port_number}') or [None]
        rows.extend({
            'ar_number': ar_number,
            'ar_protocol': protocol,
            'ar_port_number': port_number,
            'matrix_port': matrix_port,
        } for matrix_port in matching_ports)
    return rows
