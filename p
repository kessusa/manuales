# describe_object v2 + helpers for the CheckPoint class (paste inside the
# class, replacing the previous describe_object).
#
# When a rule references a group (e.g. source = ADDM_Scanners_ETS), the
# group members come as uids : these helpers resolve every member to its
# real object (network, host, service...) and expand nested groups
# recursively, so the output shows the actual networks / IPs / services
# behind every group.
#
# IMPORTANT : describe_object now needs url and sid to resolve the members,
# so update its calls in get_published_changes accordingly :
#     self.describe_object(url, sid, object_detail)


    # # Resolve member : resolves one member of a group to a readable
    # # summary. The member can come as a uid string or as an object; nested
    # # groups are expanded recursively
    def resolve_member(self, url, sid, member):
        result = None

        # members can come as plain uid strings : fetch the full object
        if isinstance(member, str):
            member = self.get_object_details(url, sid, member)

        if member:
            result = {
                'name': member.get('name', None),
                'type': member.get('type', None)
            }

            # addressing information of the member
            if member.get('ipv4-address', None):
                result['ipv4_address'] = member.get('ipv4-address')

            if member.get('subnet4', None):
                result['subnet'] = f"{member.get('subnet4')}/{member.get('mask-length4', '')}"

            if member.get('port', None):
                result['port'] = member.get('port')

            # nested groups : expand their members recursively. The members
            # of an inline group can be uid strings, so they are resolved too
            if member.get('members', None):
                result['members'] = [
                    self.resolve_member(url, sid, x) for x in member.get('members', [])
                ]

        return result

    # # Describe reference : turns one source / destination / service entry
    # # of a rule into a readable summary, expanding groups to their members
    def describe_reference(self, url, sid, ref):
        result = None

        # references can come as plain uid strings : fetch the full object
        if isinstance(ref, str):
            ref = self.get_object_details(url, sid, ref)

        if ref:
            result = {
                'name': ref.get('name', None),
                'type': ref.get('type', None)
            }

            # groups (network groups, service groups...) : expand their
            # members so the real networks / IPs / services are visible
            if ref.get('members', None) or 'group' in (ref.get('type', '') or ''):

                members = ref.get('members', None)

                # inline objects sometimes come without the members list :
                # fetch the full group from its uid
                if not members and ref.get('uid', None):
                    full_group = self.get_object_details(url, sid, ref.get('uid'))
                    members = full_group.get('members', []) if full_group else []

                result['members'] = [
                    self.resolve_member(url, sid, x) for x in members or []
                ]

        return result

    # # Describe object : turns the full object returned by
    # # get_object_details into a compact human readable summary. Rule
    # # references (sources, destinations, services) are expanded : groups
    # # show the real networks / IPs / services of their members
    def describe_object(self, url, sid, detail):
        result = None

        if detail:
            result = {
                'type': detail.get('type', None),
                'uid': detail.get('uid', None),
                'name': detail.get('name', None)
            }

            # access rules : show the fields a human needs to understand
            # the rule, expanding the groups referenced in each column
            if detail.get('type') == 'access-rule':
                result['source'] = [self.describe_reference(url, sid, x) for x in detail.get('source', [])]
                result['destination'] = [self.describe_reference(url, sid, x) for x in detail.get('destination', [])]
                result['service'] = [self.describe_reference(url, sid, x) for x in detail.get('service', [])]
                result['action'] = detail.get('action', {}).get('name', None) if isinstance(detail.get('action', None), dict) else detail.get('action', None)
                result['enabled'] = detail.get('enabled', None)
                result['policy_packages'] = detail.get('policy_packages', [])

            # network objects : add the addressing fields when present
            else:
                if detail.get('ipv4-address', None):
                    result['ipv4_address'] = detail.get('ipv4-address')

                if detail.get('subnet4', None):
                    result['subnet'] = f"{detail.get('subnet4')}/{detail.get('mask-length4', '')}"

                if detail.get('members', None):
                    result['members'] = [
                        self.resolve_member(url, sid, x) for x in detail.get('members', [])
                    ]

        return result
