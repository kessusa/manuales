SELECT g.id, g.name, t.tag_name, t.region, t.deleted
FROM pf_tag_group g
LEFT JOIN pf_tag_group_link l ON l.group_id = g.id
LEFT JOIN pf_tag t ON t.tag_id = l.tag_id
WHERE g.name IN ('NS-PVR_INET_MGMT_FR_NETWORKS', 'NS-PVR_INET_MGMT_UK_JUMPOFFS')
ORDER BY g.id, t.tag_name;


SELECT tag_id, tag_name, region, deleted
FROM pf_tag
WHERE tag_name = 'EMEA_UK_PRD_MGMT';
