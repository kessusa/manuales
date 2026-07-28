SELECT g.id, g.name, g.type, g.content,
       COUNT(l.tag_id) FILTER (WHERE t.tag_name = 'EMEA_UK_PRD_MGMT') AS links_to_tag
FROM pf_tag_group g
LEFT JOIN pf_tag_group_link l ON l.group_id = g.id
LEFT JOIN pf_tag t ON t.tag_id = l.tag_id
WHERE g.name = 'NS-PVR_INET_MGMT_NETWORKS'
GROUP BY g.id, g.name, g.type, g.content;
