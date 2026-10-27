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

    conditions = Q()
    for protocol, port_number in {(p, n) for _, p, n in ar_services if n.isdigit()}:
        conditions |= Q(
            protocol__iexact=protocol,
            port_start__lte=int(port_number),
            port_end__gte=int(port_number),
        )

    matrix_ports = []
    if conditions:
        matrix_ports = list(Port.objects.annotate(
            port_start=Cast(Func(F('port_number'), Value('-'), Value(1),
                                 function='SPLIT_PART', output_field=CharField()), IntegerField()),
            port_end=Cast(Func(F('port_number'), Value('-'), Value(-1),
                               function='SPLIT_PART', output_field=CharField()), IntegerField()),
        ).filter(conditions))

    rows = []
    for ar_number, protocol, port_number in ar_services:
        matches = [
            port for port in matrix_ports
            if port_number.isdigit()
            and port.protocol.lower() == protocol.lower()
            and port.port_start <= int(port_number) <= port.port_end
        ] or [None]
        rows.extend({
            'ar_number': ar_number,
            'ar_protocol': protocol,
            'ar_port_number': port_number,
            'matrix_port': matrix_port,
        } for matrix_port in matches)
    return rows


class PortViewSet(mixins.ListModelMixin, GenericViewSet):
    queryset = Port.objects.all()
    serializer_class = AccessRequestPortSerializer
    permission_classes = [DjangoModelPermissions]
    schema = PortSchema()
    pagination_class = None

    def list(self, request, *args, **kwargs):
        sn_ticket_id = request.query_params.get('sn_ticket_id')
        rows = build_access_request_ports(sn_ticket_id) if sn_ticket_id else []
        serializer = self.get_serializer(rows, many=True)
        return Response(serializer.data)
