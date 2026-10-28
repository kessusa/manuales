            labels = ar_content if ar_content.get('f_labels') else src_labels
            ar['ar_content'].append(
                {
                    'ip_address': src,
                    'side': 'source',
                    **labels,
                    **get_dpr_application_info(src, labels.get('f_labels')),
                }
            )
        del ar['sources']
