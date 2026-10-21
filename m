{% for subgroup in subgroups %}
    <div class="text-nowrap"><span class="badge bg-light text-dark border me-1">Group</span>{{ subgroup }}</div>
{% endfor %}
{% for value in values|slice:":10" %}
    <div class="text-nowrap">{{ value }}</div>
{% endfor %}
{% if values|length > 10 %}
    <details>
        <summary class="small text-primary">+{{ values|length|add:"-10" }} more</summary>
        {% for value in values|slice:"10:" %}
            <div class="text-nowrap">{{ value }}</div>
        {% endfor %}
    </details>
{% endif %}
