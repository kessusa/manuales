from django.apps import apps
from django.db import connection

with connection.cursor() as cursor:
    db_tables = set(connection.introspection.table_names(cursor))
    for model in apps.get_app_config('rss').get_models():
        if not model._meta.managed:
            continue
        table = model._meta.db_table
        if table not in db_tables:
            print(f'MISSING TABLE  {table}')
            continue
        db_columns = {c.name: c for c in connection.introspection.get_table_description(cursor, table)}
        model_columns = {f.column for f in model._meta.local_concrete_fields}
        for field in model._meta.local_concrete_fields:
            if field.column not in db_columns:
                print(f'MISSING COLUMN {table}.{field.column}  {field.db_type(connection)}  null={field.null}')
        for name, info in db_columns.items():
            if name not in model_columns and not info.null_ok:
                print(f'EXTRA NOT NULL {table}.{name}')
