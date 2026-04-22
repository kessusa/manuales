import json

from django.contrib.auth.mixins import PermissionRequiredMixin
from django.http import JsonResponse
from django.urls import reverse
from django.views.generic.edit import FormView

from .models import AviIwaf
from .forms import AviWafRulesModifyForm
from .avi_iwaf import AVIIWAFApi


class AviWafRulesModifyView(PermissionRequiredMixin, FormView):
    model = AviIwaf
    form_class = AviWafRulesModifyForm
    permission_required = ('rss.view_waf', 'rss.modify_waf_rules')
    template_name = 'modals/avi_waf_rules_modal.html'

    def get_success_url(self):
        return reverse('hosting_waf')

    def form_valid(self, form):
        waf_policies = form.cleaned_data.get('waf_policies', [])
        if not waf_policies:
            return JsonResponse({
                "success": False,
                "message": "At least one WAF policy must be selected.",
            }, status=400)

        action_data = {
            'action': form.cleaned_data.get('action'),
            'group_type': form.cleaned_data.get('group_type'),
            'group_name': form.cleaned_data.get('group_name'),
            'rule_id': form.cleaned_data.get('rule_id'),
            'rule_name': form.cleaned_data.get('pre_crs_signature_name'),
            'mode': form.cleaned_data.get('mode'),
            'exclusion_data': form.cleaned_data.get('exclusion_data'),
            'signature_code': form.cleaned_data.get('signature_code'),
            'waf_policies': waf_policies,
        }

        success, message = self.modify_waf_rules(action_data)
        return JsonResponse({
            "success": success,
            "message": message,
            "redirect_url": self.get_success_url() if success else None,
        }, status=200 if success else 400)

    def form_invalid(self, form):
        return JsonResponse({
            "success": False,
            "errors": form.errors,
        }, status=400)

    def modify_waf_rules(self, action_data):
        avi_waf = AVIIWAFApi(env='emea', mode='write')
        success = True
        error_messages = []

        exclusion_data = action_data.get('exclusion_data')
        if exclusion_data and isinstance(exclusion_data, str):
            try:
                exclusion_data = json.loads(exclusion_data)
            except json.JSONDecodeError as e:
                error_msg = f"Invalid exclusion data format: {str(e)}. Please provide valid JSON."
                error_messages.append(error_msg)
                return (False, error_msg)

        if exclusion_data and not isinstance(exclusion_data, dict):
            error_msg = "Exclusion data must be a JSON object (dictionary)."
            error_messages.append(error_msg)
            return (False, error_msg)

        group_type = action_data['group_type']

        if action_data['action'] == 'enable':
            if action_data['rule_id']:
                api_action = 'enable_rule'
            else:
                api_action = 'enable_group'
        elif action_data['action'] == 'disable':
            if action_data['rule_id']:
                api_action = 'disable_rule'
            else:
                api_action = 'disable_group'
        elif action_data['action'] == 'add_rule':
            if group_type == 'pre_crs':
                api_action = 'enable_rule'
            else:
                error_msg = "CRS groups can't add a rule"
                error_messages.append(error_msg)
                return (False, error_msg)
        elif action_data['action'] == 'add_exclusion':
            if action_data['rule_id']:
                api_action = 'add_rule_exclusion'
            else:
                api_action = 'add_group_exclusion'
        elif action_data['action'] == 'modify_rule_mode':
            api_action = 'modify_rule_mode'
        else:
            error_msg = f"Unknown action: {action_data['action']}"
            error_messages.append(error_msg)
            return (False, error_msg)

        rule_data = None
        rule_name = action_data.get('rule_name')
        if group_type == 'pre_crs' and exclusion_data and action_data['action'] == 'add_rule':
            rule_data = {
                'rule': exclusion_data.get('rule'),
                'mode': exclusion_data.get('mode', 'WAF_MODE_ENFORCEMENT'),
                'is_sensitive': exclusion_data.get('is_sensitive', False),
            }
            rule_name = exclusion_data.get('name') or rule_name

        for policy in action_data['waf_policies']:
            tenant = policy.tenant
            policy_name = policy.waf_policy

            try:
                params = {
                    'tenant': tenant,
                    'policy_name': policy_name,
                    'group_name': action_data['group_name'],
                    'group_type': group_type,
                }

                if action_data['rule_id']:
                    params['rule_id'] = action_data['rule_id']

                if rule_name:
                    params['rule_name'] = rule_name

                if action_data['mode']:
                    params['new_mode'] = action_data['mode']

                if exclusion_data and not rule_data:
                    params['exclusion_data'] = exclusion_data

                if rule_data:
                    params['rule_data'] = rule_data

                if api_action == 'enable_group':
                    result = avi_waf.modify_group_status(**params, enable=True)
                elif api_action == 'disable_group':
                    result = avi_waf.modify_group_status(**params, enable=False)
                elif api_action == 'enable_rule':
                    result = avi_waf.modify_rule_status(**params, enable=True)
                elif api_action == 'disable_rule':
                    result = avi_waf.modify_rule_status(**params, enable=False)
                elif api_action == 'add_group_exclusion':
                    result = avi_waf.add_group_exclusion(**params)
                elif api_action == 'add_rule_exclusion':
                    result = avi_waf.add_rule_exclusion(**params)
                elif api_action == 'modify_rule_mode':
                    result = avi_waf.modify_rule_mode(**params)

                if not result:
                    error_msg = f"Failed to {api_action.replace('_', ' ')} for policy {policy_name}"
                    error_messages.append(error_msg)
                    success = False

            except Exception as e:
                error_msg = f"Error processing policy {policy_name}: {str(e)}"
                error_messages.append(error_msg)
                success = False

        if success:
            return (True, "WAF rules modified successfully for all selected policies!")

        error_msg = "Some errors occurred while modifying WAF rules:"
        for msg in error_messages:
            error_msg += f"\n- {msg}"
        return (False, error_msg)
