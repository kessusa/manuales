SELECT g.id, g.name, g.type,
       COUNT(l.tag_id) FILTER (WHERE t.tag_name = 'EMEA_UK_PRD_MGMT') AS links_to_tag
FROM pf_tag_group g
LEFT JOIN pf_tag_group_link l ON l.group_id = g.id
LEFT JOIN pf_tag t ON t.tag_id = l.tag_id
WHERE g.name IN ('NS-PVR_INET_MGMT_NETWORKS','NS-PVR_INET_MGMT_FR_NETWORKS','NS-PVR_INET_MGMT_UK_JUMPOFFS')
GROUP BY g.id, g.name, g.type ORDER BY g.name, g.type;
