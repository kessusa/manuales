# nat rules belong to the NAT rulebase of a policy package :
            # show-nat-rule needs the package, which show-object does not
            # return, so we try every package of the domain until found
            if result.get('type') == 'nat-rule':
                packages_args = {
                    'headers': {'Content-Type': 'application/json', 'X-chkp-sid': sid},
                    'json': {'limit': 500},
                    'verify': False
                }
                packages_response = requests.post(f'{url}/show-packages', **packages_args)

                if packages_response.status_code == 200:

                    for package in packages_response.json().get('packages', []):
                        package_name = package.get('name', None)

                        connection_args['json'] = {
                            'uid': uid,
                            'package': package_name,
                            'details-level': 'full'
                        }

                        rule_response = requests.post(f'{url}/show-nat-rule', **connection_args)

                        if rule_response.status_code == 200:
                            result = rule_response.json()
                            result['policy_packages'] = [package_name]
                            break



# nat rules : original / translated columns hold a single
            # object each (not a list like access rules)
            elif detail.get('type') == 'nat-rule':
                result['original_source'] = self.describe_reference(url, sid, detail.get('original-source', None))
                result['original_destination'] = self.describe_reference(url, sid, detail.get('original-destination', None))
                result['original_service'] = self.describe_reference(url, sid, detail.get('original-service', None))
                result['translated_source'] = self.describe_reference(url, sid, detail.get('translated-source', None))
                result['translated_destination'] = self.describe_reference(url, sid, detail.get('translated-destination', None))
                result['translated_service'] = self.describe_reference(url, sid, detail.get('translated-service', None))
                result['method'] = detail.get('method', None)
                result['enabled'] = detail.get('enabled', None)
                result['policy_packages'] = detail.get('policy_packages', [])
