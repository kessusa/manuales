SELECT (SELECT MAX(tag_id) FROM pf_tag) AS max_id,
       (SELECT last_value FROM pf_tag_tag_id_seq) AS seq_value,
       EXISTS (SELECT 1 FROM pf_tag WHERE tag_id = 1) AS tag_1_exists,
       (SELECT COUNT(*) FROM pf_tag_group) AS group_rows;
