# schema.py  (coreapi / coreschema / AutoSchema ya importados arriba)

class AviWafSchema(AutoSchema):
    def get_manual_fields(self, path, method):
        if method.lower() != 'get':
            return []

        return [
            coreapi.Field(
                name='region',
                required=True,
                location='query',
                schema=coreschema.String(
                    title='Region',
                    description='Region to query. Required.<br/>'
                                '<small><i>(emea | apac | amer)</i></small>'
                )
            ),
            coreapi.Field(
                name='vs_ip',
                required=False,
                location='query',
                schema=coreschema.String(
                    title='VS IP',
                    description='Filter by virtual server IP (contains).'
                )
            ),
            coreapi.Field(
                name='vs_name',
                required=False,
                location='query',
                schema=coreschema.String(
                    title='VS name',
                    description='Filter by virtual server name (contains).'
                )
            ),
            coreapi.Field(
                name='enforcement_mode',
                required=False,
                location='query',
                schema=coreschema.String(
                    title='Enforcement mode',
                    description='Filter by WAF policy mode.<br/>'
                                '<small><i>(detection | enforcement)</i></small>'
                )
            ),
            coreapi.Field(
                name='crs_overrides',
                required=False,
                location='query',
                schema=coreschema.Boolean(
                    title='Include CRS overrides',
                    description='Include CRS overrides in the response.'
                )
            ),
        ]

    def get_description(self, path, method):
        return 'List of Avi WAF virtual servers by region, with optional filters.'


class F5WafSchema(AutoSchema):
    def get_manual_fields(self, path, method):
        if method.lower() != 'get':
            return []

        return [
            coreapi.Field(
                name='region',
                required=True,
                location='query',
                schema=coreschema.String(
                    title='Region',
                    description='Region to query. Required.<br/>'
                                '<small><i>(emea | apac | amer)</i></small>'
                )
            ),
            coreapi.Field(
                name='enforcement_mode',
                required=False,
                location='query',
                schema=coreschema.String(
                    title='Enforcement mode',
                    description='Filter by ASM enforcement mode.<br/>'
                                '<small><i>(blocking | transparent)</i></small>'
                )
            ),
            coreapi.Field(
                name='virtual_servers',
                required=False,
                location='query',
                schema=coreschema.String(
                    title='Virtual servers',
                    description='Filter by virtual server name (contains).'
                )
            ),
            coreapi.Field(
                name='asm_policy',
                required=False,
                location='query',
                schema=coreschema.String(
                    title='ASM policy',
                    description='Filter by ASM policy name (contains).'
                )
            ),
            coreapi.Field(
                name='instance',
                required=False,
                location='query',
                schema=coreschema.String(
                    title='Instance',
                    description='Filter by F5 instance (contains).'
                )
            ),
        ]

    def get_description(self, path, method):
        return 'List of F5 ASM policies and virtual servers by region, with optional filters.'
