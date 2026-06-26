## Este método devuelve solo los campos necesarios para enriquecer
## los detalles del WAF (F5) y guardarlos en la base de datos.
def get_data_to_enrich_waf_details(self, token, vs_name):
    self.connection_args['headers'] = {**self.headers, 'Authorization': f'Bearer {token}'}

    params = {
        'search_string': vs_name,
        'page': 0,
        'limit': 30,
        'techno': 'All',
    }

    response = requests.get(
        f'{self.base_url}/api/v1/loadbalancer',
        params=params,
        **self.connection_args
    ).json()

    if not response.get('data'):
        return None

    # search_string puede devolver coincidencias parciales -> filtramos por nombre exacto
    item = next(
        (lb for lb in response['data'] if lb.get('name') == vs_name),
        None
    )
    if not item:
        return None

    frontend = item.get('frontend') or {}

    # auid (si existe) -> viene de la parte administrative
    administrative = item.get('administrative') or []
    auid = administrative[0].get('auid') if administrative else None

    # Pool servers -> lista de IPs de los miembros de todos los pools
    pool_servers = [
        member.get('ip')
        for pool in (item.get('pool') or [])
        for member in (pool.get('members') or [])
        if member.get('ip')
    ]

    return {
        'vs_name': item.get('name'),
        'vs_ip': frontend.get('ip'),
        'vs_services': frontend.get('port', []),
        'vs_status': item.get('state'),   # ver nota: ¿'state' a nivel de VS o de pool?
        'pool_servers': pool_servers,
        'auid': auid,
    }
