<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="PythonScript" module="Products.PythonScripts.PythonScript"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>Script_magic</string> </key>
            <value> <int>3</int> </value>
        </item>
        <item>
            <key> <string>_bind_names</string> </key>
            <value>
              <object>
                <klass>
                  <global name="NameAssignments" module="Shared.DC.Scripts.Bindings"/>
                </klass>
                <tuple/>
                <state>
                  <dictionary>
                    <item>
                        <key> <string>_asgns</string> </key>
                        <value>
                          <dictionary>
                            <item>
                                <key> <string>name_container</string> </key>
                                <value> <string>container</string> </value>
                            </item>
                            <item>
                                <key> <string>name_context</string> </key>
                                <value> <string>context</string> </value>
                            </item>
                            <item>
                                <key> <string>name_m_self</string> </key>
                                <value> <string>script</string> </value>
                            </item>
                            <item>
                                <key> <string>name_subpath</string> </key>
                                <value> <string>traverse_subpath</string> </value>
                            </item>
                          </dictionary>
                        </value>
                    </item>
                  </dictionary>
                </state>
              </object>
            </value>
        </item>
        <item>
            <key> <string>_body</string> </key>
            <value> <string>from Products.Formulator.Errors import FormValidationError\n
from Products.DCWorkflow.DCWorkflow import ValidationFailed\n
from Products.ERP5Type.Message import translateString\n
portal = context.getPortalObject()\n
request=context.REQUEST\n
\n
form = getattr(context, dialog_id)\n
\n
# Validate the form\n
try:\n
  # It is necessary to force editable_mode before validating\n
  # data. Otherwise, field appears as non editable.\n
  # This is the pending of form_dialog.\n
  editable_mode = request.get(\'editable_mode\', 1)\n
  request.set(\'editable_mode\', 1)\n
  form.validate_all_to_request(request)\n
  request.set(\'editable_mode\', editable_mode)\n
except FormValidationError, validation_errors:\n
  # Pack errors into the request\n
  field_errors = form.ErrorFields(validation_errors)\n
  request.set(\'field_errors\', field_errors)\n
  return form(request)\n
\n
# XXX: this is a duplication from form validation code in Base_callDialogMethod\n
# Correct fix is to factorise this script with Base_callDialogMethod, not to\n
# fix XXXs here.\n
doaction_param_list = {}\n
MARKER = []\n
for f in form.get_fields():\n
  k = f.id\n
  v = getattr(request, k, MARKER)\n
  if v is not MARKER:\n
    if k.startswith(\'your_\'):\n
      k=k[5:]\n
    elif k.startswith(\'my_\'): # compat\n
      k=k[3:]\n
    doaction_param_list[k] = v\n
\n
listbox = request.get(\'listbox\') # XXX: hardcoded field name\n
if listbox is not None:\n
  listbox_line_list = []\n
  listbox = getattr(request,\'listbox\',None) # XXX: hardcoded field name\n
  listbox_keys = listbox.keys()\n
  listbox_keys.sort()\n
  for key in listbox_keys:\n
    listbox_line = listbox[key]\n
    listbox_line[\'listbox_key\'] = key\n
    listbox_line_list.append(listbox[key])\n
  listbox_line_list = tuple(listbox_line_list)\n
  doaction_param_list[\'listbox\'] = listbox_line_list # XXX: hardcoded field name\n
\n
try:\n
  context.portal_workflow.doActionFor(\n
    context,\n
    doaction_param_list[\'workflow_action\'],\n
    **doaction_param_list)\n
except ValidationFailed, error_message:\n
  if getattr(error_message, \'msg\', None):\n
    # use of Message class to store message+mapping+domain\n
    message = error_message.msg\n
    if same_type(message, []):\n
      message = \'. \'.join(\'%s\' % x for x in message)\n
    else:\n
      message = str(message)\n
  else:\n
    message = str(error_message)\n
  return context.ERP5Site_redirect(\n
                  \'%s/view\' % context.absolute_url(),\n
                  keep_items={\'portal_status_message\': message}, **kw)\n
\n
portal_status_message = request.get(\'portal_status_message\', translateString(\'Status changed.\'))\n
\n
# Allow to redirect to another document\n
redirect_document_path = request.get(\'redirect_document_path\', context.getRelativeUrl())\n
redirect_document = context.restrictedTraverse(redirect_document_path)\n
\n
return context.ERP5Site_redirect(\n
                \'%s/view\' % (redirect_document.absolute_url()),\n
                keep_items={\'portal_status_message\': portal_status_message})\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>form_id, dialog_id, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Workflow_statusModify</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
