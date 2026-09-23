# =============================================================================
# rss/models.py - EMEAPLAYFLOWS-3637 final state
#
# - PlayflowsTag            -> unchanged
# - PlayflowsTagGroup       -> rewritten (tag FK + children M2M + type in unique)
# - PlayflowsTagGroupLink   -> REMOVED (replaced by PlayflowsTagGroup.tag)
# - PlayflowsTagGroupRelation -> REMOVED (replaced by PlayflowsTagGroup.children)
# - TaskUpdateDate          -> unchanged (used by playflows_groups_update)
#
# Tables in DB:
#   pf_tag                 (PlayflowsTag)
#   pf_tag_group           (PlayflowsTagGroup, one row per group and tag)
#   pf_tag_group_children  (auto M2M: from_playflowstaggroup_id = parent,
#                                     to_playflowstaggroup_id   = child)
#   task_date              (TaskUpdateDate)
# =============================================================================


class PlayflowsTagGroup(models.Model):

    class Meta:
        managed = True
        db_table = 'pf_tag_group'
        ordering = ('name',)
        constraints = [
            models.UniqueConstraint(
                fields=['tag', 'name', 'type'],
                name='unique_group_name_type_per_tag',
            ),
        ]

    GROUP_TYPES = [
        ('ip', 'IP Addresses'),
        ('service', 'Services'),
        ('unknown', 'Unknown Type'),
    ]

    tag = models.ForeignKey(
        'PlayflowsTag', on_delete=models.CASCADE, related_name='groups',
    )
    name = models.CharField(max_length=256)
    type = models.CharField(max_length=10, choices=GROUP_TYPES, default='unknown')
    content = models.JSONField(blank=True, default=list)
    children = models.ManyToManyField(
        'self',
        symmetrical=False,
        related_name='parents',
        blank=True,
        db_table='pf_tag_group_children',
    )

    def __str__(self):
        return f'{self.name} ({self.get_type_display()}) - {self.tag.tag_name}'
