# ajax_get_avi_waf_data — filtros uno por uno (EMEAPLAYFLOWS-3648)
# Mismo estilo que el codigo existente: getlist -> if -> q &= Q(...)

    context = {}
    q = Q()

    # --- 1. Filter by URL details ---
    urls = request.GET.getlist('url')
    if urls:
        q_url = Q()
        for u in urls:
            q_url |= Q(url__contains=[{'url': u}])
        q &= q_url

    tenant = request.GET.getlist('tenant')
    if tenant:
        q &= Q(tenant__in=tenant)

    vs_names = request.GET.getlist('vs_name')
    if vs_names:
        q &= Q(vs_name__in=vs_names)

    vs_ip = request.GET.getlist('vs_ip')
    if vs_ip:
        q &= Q(vs_ip__in=vs_ip)

    services = request.GET.getlist('services')
    if services:
        q &= Q(services__has_any_keys=services)

    pool_servers = request.GET.getlist('pool_server')
    if pool_servers:
        q &= Q(pool_server__ip_address__in=pool_servers)

    pool_server_status = request.GET.getlist('pool_server_status')
    if pool_server_status:
        q &= Q(pool_servers_status__in=pool_server_status)

    env = request.GET.get('env')
    if env == 'prod':
        q &= Q(env=env)
    elif env == 'no-prod':
        q &= Q(env=env)

    vs_status = request.GET.get('vs_status')
    if vs_status == 'True':
        q &= Q(vs_status=True)
    elif vs_status == 'False':
        q &= Q(vs_status=False)

    region = request.GET.getlist('region')
    if region:
        q &= Q(region__in=region)

    # --- 2. Filter by WAF details ---
    waf_policy = request.GET.getlist('waf_policy')
    if waf_policy:
        q &= Q(waf_policy__in=waf_policy)

    policy_mode = request.GET.getlist('waf_policy_mode')
    if policy_mode:
        q &= Q(waf_policy_mode__in=policy_mode)

    application_profile = request.GET.getlist('application_profile')
    if application_profile:
        q &= Q(application_profile__in=application_profile)

    error_page_profile = request.GET.getlist('error_page_profile')
    if error_page_profile:
        q &= Q(error_page_profile__in=error_page_profile)

    waf_profile = request.GET.getlist('waf_profile')
    if waf_profile:
        q &= Q(waf_profile__in=waf_profile)

    waf_paranoia_level = request.GET.getlist('waf_paranoia_level')
    if waf_paranoia_level:
        q &= Q(waf_paranoia_level__in=waf_paranoia_level)

    waf_crs = request.GET.getlist('waf_crs')
    if waf_crs:
        q &= Q(waf_crs__in=waf_crs)

    # --- 3. Filter by Kona Protection ---
    kona_protection = request.GET.getlist('kona_protection')
    if kona_protection:
        q_kona = Q()
        for kp in kona_protection:
            q_kona |= Q(url__contains=[{'kona_protection': kp}])
        q &= q_kona

    kona_ddos = request.GET.getlist('kona_ddos')
    if kona_ddos:
        q &= Q(kona_ddos__in=kona_ddos)

    kona_waf = request.GET.getlist('kona_waf')
    if kona_waf:
        q &= Q(kona_waf__in=kona_waf)

    kona_siteshield_group_name = request.GET.getlist('kona_siteshield_group_name')
    if kona_siteshield_group_name:
        q &= Q(kona_siteshield_group_name__in=kona_siteshield_group_name)

    # --- 4. Filter by Application (via DPR) ---
    application_auid = request.GET.getlist('application_auid')
    if application_auid:
        q &= Q(dpr__application_auid__in=application_auid)

    application_name = request.GET.getlist('application_name')
    if application_name:
        q &= Q(dpr__application_name__in=application_name)

    app_sec_profile = request.GET.getlist('app_sec_profile')
    if app_sec_profile:
        q &= Q(dpr__app_sec_profile__in=app_sec_profile)

    confidentiality = request.GET.getlist('confidentiality')
    if confidentiality:
        q &= Q(dpr__confidentiality__in=confidentiality)

    vital_application = request.GET.getlist('vital_application')
    if vital_application:
        q &= Q(dpr__vital_application__in=vital_application)

    it_continuity_criticality = request.GET.getlist('it_continuity_criticality')
    if it_continuity_criticality:
        q &= Q(dpr__it_continuity_criticality__in=it_continuity_criticality)

    # --- 5. Filter by Business (via DPR) ---
    business_line = request.GET.getlist('business_line')
    if business_line:
        q &= Q(dpr__business_line__name__in=business_line)

    it_cluster = request.GET.getlist('it_cluster')
    if it_cluster:
        q &= Q(dpr__it_cluster__in=it_cluster)

    sub_it_cluster = request.GET.getlist('sub_it_cluster')
    if sub_it_cluster:
        q &= Q(dpr__sub_it_cluster__in=sub_it_cluster)

    application_manager = request.GET.getlist('application_manager')
    if application_manager:
        q &= Q(dpr__application_manager__in=application_manager)

    production_manager = request.GET.getlist('production_manager')
    if production_manager:
        q &= Q(dpr__production_manager__in=production_manager)

    production_domain_manager = request.GET.getlist('production_domain_manager')
    if production_domain_manager:
        q &= Q(dpr__production_domain_manager__in=production_domain_manager)

    domain_manager = request.GET.getlist('domain_manager')
    if domain_manager:
        q &= Q(dpr__domain_manager__in=domain_manager)

    # --- 6. Filter by Metadata ---
    updated_signature_review = request.GET.getlist('updated_signature_review')
    if updated_signature_review:
        q &= Q(updated_signature_review__in=updated_signature_review)

    itsm_request = request.GET.getlist('itsm_request')
    if itsm_request:
        q &= Q(itsm_request__in=itsm_request)

    contact = request.GET.getlist('contact')
    if contact:
        q &= Q(contact__in=contact)

    assigner = request.GET.getlist('assigner')
    if assigner:
        q &= Q(assigner__in=assigner)

    # Execute the query
    # .distinct() necesario: el filtro por business_line (M2M via DPR)
    # puede duplicar filas de AviIwaf
    object_list = AviIwaf.objects.filter(q).order_by('vs_name').distinct()
