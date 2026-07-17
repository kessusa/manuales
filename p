# =========================================================================
# METODOS NUEVOS PARA PlayflowsAPI (pegar dentro de la clase, en playflows.py)
# Estilo identico al existente. SOLO LECTURA: show / match, nunca /write.
# =========================================================================

    def match_flows(self, sid, flows, tags, multi_match=False):
        """Reglas que aplican a cada flujo via /commands (match-flow esta
        deprecado). Flujos en formato 'src dst servicio'.
        multi_match=False -> regla EFECTIVA por flujo (first match).
        multi_match=True  -> 'set matchandcontinue': TODAS las reglas que
        matchean, incluida la implicit drop, ordenadas por position."""

        commands = list(flows)
        if multi_match:
            commands = ['set matchandcontinue'] + commands

        params = {
            'sid': sid,
            'commands': commands,
            'tags': list(tags),
            'version': 'upcoming'
        }
        self.connection_args['json'] = params
        response = requests.post(f'{self.base_url}/commands', **self.connection_args).json()

        if response.get('status') != 'success':
            return {}

        result = {}
        for item in response.get('data', []):
            if item.get('type') != 'match-flow':
                continue
            if multi_match:
                result.setdefault(item['flow'], []).append(item)
            else:
                result[item['flow']] = item

        if multi_match:
            for flow in result:
                result[flow].sort(key=lambda r: int(r.get('position') or 999999))

        return result

    def get_tag_rules(self, sid, tag_name):
        """Reglas del tag via 'show objects <tag> rules', con src/dst/service
        (contents y names), position y disabled. Solo lectura."""

        params = {
            'sid': sid,
            'commands': [f"show objects {tag_name} rules"],
            'version': 'upcoming'
        }
        self.connection_args['json'] = params
        response = requests.post(f'{self.base_url}/commands', **self.connection_args).json()

        if response.get('status') != 'success':
            return []

        data = response.get('data', [])
        if not data:
            return []

        # segun version pueden venir en la raiz o anidadas bajo el tag
        rules = data[0].get('rules', [])
        if isinstance(rules, dict):
            rules = rules.get(tag_name, {}).get('upcoming', [])
        if not isinstance(rules, list):
            rules = []

        return rules
