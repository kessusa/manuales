class AviWafViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = AviIwafSerializer
    VALID_REGIONS = {"emea", "apac"}
    VALID_ENFORCEMENT = {"detection", "enforcement"}

    def get_queryset(self):
        region = self.request.query_params.get("region", "").lower()
        if region not in self.VALID_REGIONS:
            raise ValidationError(
                {"detail": f"Invalid region '{region}'. Allowed: {sorted(self.VALID_REGIONS)}"}
            )
        q = Q()
        vs_ip = self.request.query_params.get("vs_ip")
        if vs_ip:
            q &= Q(vs_ip__icontains=vs_ip)
        vs_name = self.request.query_params.get("vs_name")
        if vs_name:
            q &= Q(vs_name__icontains=vs_name)
        mode = self.request.query_params.get("enforcement_mode")
        if mode:
            mode = mode.lower()
            if mode not in self.VALID_ENFORCEMENT:
                raise ValidationError(
                    {"detail": f"Invalid enforcement_mode '{mode}'. Use detection|enforcement"}
                )
            q &= Q(waf_policy_mode__iexact=mode)
        return AviIwaf.objects.filter(q, region=region)


class F5WafViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = F5AsmSerializer
    VALID_ENFORCEMENT = {"blocking", "transparent"}

    def get_queryset(self):
        region = self.request.query_params.get("region", "")
        if not region:
            raise ValidationError({"detail": "Missing required query param 'region'."})
        q = Q()
        vservers = self.request.query_params.get("virtual_servers")
        if vservers:
            q &= Q(virtual_servers__contains=[vservers])
        mode = self.request.query_params.get("enforcement_mode")
        if mode:
            mode = mode.lower()
            if mode not in self.VALID_ENFORCEMENT:
                raise ValidationError(
                    {"detail": f"Invalid enforcement_mode '{mode}'. Use blocking|transparent"}
                )
            q &= Q(enforcement_mode__iexact=mode)
        return F5Asm.objects.filter(q, region__iexact=region)
