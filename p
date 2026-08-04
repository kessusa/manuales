# ------------------------------------------------------------------ main
    def handle(self, *args, **options):
        regions = options['regions'] or REGIONS

        folder = Path(settings.MEDIA_ROOT) / FOLDER
        folder.mkdir(parents=True, exist_ok=True)

        for region in regions:
            final_path = folder / f'per_device_mapping_{region}.csv'
            tmp_path = final_path.with_suffix('.csv.tmp')

            table = self.build_table(region)

            if not table:
                final_path.unlink(missing_ok=True)   # limpia el CSV viejo si lo hubiera
                self.stdout.write(self.style.WARNING(
                    f'SKIP {region}: no per-device-mapping objects'))
                continue

            try:
                df = pd.DataFrame(table, columns=HEADERS)
                df.to_csv(tmp_path, index=False, encoding='utf-8-sig')
                os.replace(tmp_path, final_path)
            except Exception:
                Path(tmp_path).unlink(missing_ok=True)
                raise

            self.stdout.write(self.style.SUCCESS(
                f'OK {region}: {len(table)} ADOMs -> {final_path}'))
