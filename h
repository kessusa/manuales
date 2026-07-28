SELECT g.id, g.name, g.type, g.content
FROM pf_tag_group g
JOIN pf_tag_group_link l ON l.group_id = g.id
JOIN pf_tag t ON t.tag_id = l.tag_id
WHERE t.tag_name = 'EMEA_UK_PRD_MGMT'
  AND t.region = 'emea'
  AND (t.deleted = FALSE OR t.deleted IS NULL)
  AND g.name LIKE 'NS-PVR%';


SELECT g.id, g.name, t.tag_name, t.deleted, g.content
FROM pf_tag_group g
LEFT JOIN pf_tag_group_link l ON l.group_id = g.id
LEFT JOIN pf_tag t ON t.tag_id = l.tag_id
WHERE g.name IN (
    'NS-PVR_INET_MGMT_NETWORKS',
    'NS-PVR_INET_MGMT_FR_NETWORKS',
    'NS-PVR_INET_MGMT_UK_JUMPOFFS'
)
ORDER BY g.name, t.tag_name;
