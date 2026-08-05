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
