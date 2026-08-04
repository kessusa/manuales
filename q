# get_object_details (extended) + get_layer_packages for the CheckPoint
# class (paste them inside the class, replacing the previous
# get_object_details).
# show-changes returns the uid of the changed object; show-object rebuilds
# it; for access rules, the rule belongs to a layer, and the layer belongs
# to one or more policy packages. get_layer_packages resolves that last
# link so every change can be traced back to its package.


    # # Get layer packages : returns the policy packages that contain the
    # # given access layer. A layer can be shared by several packages, so
    # # a list is returned. The sid must belong to a session on the domain
    def get_layer_packages(self, url, sid, layer):
        result = []

        connection_args = {
            'headers': {'Content-Type': 'application/json', 'X-chkp-sid': sid},
            'json': {'details-level': 'full', 'limit': 500},
            'verify': False
        }

        response = requests.post(f'{url}/show-packages', **connection_args)

        if response.status_code == 200:

            for package in response.json().get('packages', []):

                # the layer of a rule can come as a uid or as a name,
                # match against both
                for access_layer in package.get('access-layers', []):

                    if layer in (access_layer.get('uid', None), access_layer.get('name', None)):
                        result.append(package.get('name', None))
                        break

        return result

    # # Get object details : returns the full definition of an object from
    # # its uid, used to rebuild what was created / modified in a published
    # # session. For access rules it also resolves the layer and the policy
    # # packages that contain it. The sid must belong to a session on the domain
    def get_object_details(self, url, sid, uid):
        result = None

        connection_args = {
            'headers': {'Content-Type': 'application/json', 'X-chkp-sid': sid},
            'json': {'uid': uid, 'details-level': 'full'},
            'verify': False
        }

        # step 1 : generic lookup by uid, works for any object type
        response = requests.post(f'{url}/show-object', **connection_args)

        if response.status_code == 200:
            result = response.json().get('object', {})

            # step 2 : access rules have a dedicated command that returns
            # the complete rule (source, destination, service, action,
            # position in the layer, ...). The layer comes in the object
            if result.get('type') == 'access-rule' and result.get('layer', None):
                layer = result.get('layer')

                connection_args['json'] = {
                    'uid': uid,
                    'layer': layer,
                    'details-level': 'full',
                    # resolve source / destination / service uids to names
                    'show-as-ranges': False
                }

                rule_response = requests.post(f'{url}/show-access-rule', **connection_args)

                if rule_response.status_code == 200:
                    result = rule_response.json()

                # step 3 : resolve the policy packages that contain the
                # layer of the rule, so the change can be traced back to
                # its package
                result['policy_packages'] = self.get_layer_packages(url, sid, layer)

        return result
