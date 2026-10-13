{% regroup result by ar_number as ar_groups %}
{% for group in ar_groups %}
    {% for item in group.list %}
        <tr class="text-nowrap">
            {% if forloop.first %}
                <td rowspan="{{ group.list|length }}" class="fw-normal text-center align-middle">
                    <span class="badge badge-sm badge-outline-secondary">{{ group.grouper|default:'-' }}</span>
                </td>
            {% endif %}
            <td class="fw-normal text-center">
                {{ item.ar_port_number|default:'-' }} - {{ item.ar_protocol|default:'-' }}
            </td>
            <td class="fw-normal text-center">{{ item.port_number|default:'-' }}</td>
            <td class="fw-normal text-center">{{ item.protocol|default:'-' }}</td>
            <td class="fw-normal text-center">
                {% if item.service %}
                    <span class="badge badge-sm badge-info">{{ item.service }}</span>
                {% else %} - {% endif %}
            </td>
            <td class="fw-normal text-center">
                {% if item.category %}
                    <span class="badge badge-sm badge-outline-primary">{{ item.category }}</span>
                {% else %} - {% endif %}
            </td>
            <td class="fw-normal text-center">
                {% if item.sub_category %}
                    <span class="badge badge-sm badge-outline-secondary">{{ item.sub_category }}</span>
                {% else %} - {% endif %}
            </td>
            <td class="fw-normal text-center"><small>{{ item.comments|default:'-' }}</small></td>
            <td class="fw-normal text-center">{{ item.exposition|default:'-' }}</td>
            <td class="fw-normal text-center">{{ item.replaced_by|default:'-' }}</td>
            <td class="fw-normal text-center"><small>{{ item.who_needs_to_approve_exception|default:'-' }}</small></td>
            <td class="fw-normal text-center"><small>{{ item.security_policy_document|default:'-' }}</small></td>
        </tr>
    {% endfor %}
{% empty %}
    <tr class="text-nowrap">
        <td colspan="12" class="text-center">
            <small class="fst-italic mb-2">
                <i class="fas fa-exclamation-circle fa-lg pe-1"></i> No data Found !
            </small>
        </td>
    </tr>
{% endfor %}
