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
            <value> <string># This script is used in order to retrieve parameter in the listbox Displayed\n
# by Base_viewRelatedObjectList from the relation field\n
result = None\n
\n
request = context.REQUEST\n
\n
if parameter is not None:\n
  field_id = request.get(\'field_id\',None) \\\n
      or request.get(\'field_your_field_id\', None) \\\n
      or request.get(\'form_id\', None)\n
  form_id = request.get(\'original_form_id\',None) \\\n
      or request.get(\'field_your_original_form_id\', None) \\\n
      or request.get(\'form_id\')\n
  listbox = getattr(context, form_id).get_field(field_id)\n
  dialog_id = listbox.get_value(\'relation_form_id\') or \'Base_viewRelatedObjectList\'\n
  result = listbox.get_value(parameter)\n
\n
  if result in [ [], (), None, \'\']:\n
    if parameter == \'proxy_listbox_ids\':\n
      return context.REQUEST.get(\'proxy_listbox_ids\', [])\n
    result = getattr(context, dialog_id, None).get_field( \'listbox\' ).get_orig_value(parameter)\n
\n
  if parameter == \'portal_type\':\n
    portal_type = listbox.get_value(\'portal_type\')\n
    proxied_listbox = None\n
    relation_field_proxy_listbox = context.Base_getRelationFieldProxyListBoxId()\n
    if relation_field_proxy_listbox != \\\n
            \'Base_viewRelatedObjectListBase/listbox\':\n
      proxied_listbox = context.restrictedTraverse(\n
                relation_field_proxy_listbox, None)\n
    if proxied_listbox is None:\n
      return portal_type\n
\n
    proxied_listbox_portal_type = proxied_listbox.get_value(\'portal_types\')\n
    portal_type_first_item_list = [x[0] for x in portal_type]\n
    return [x for x in proxied_listbox_portal_type if x[0] in portal_type_first_item_list] or portal_type\n
\n
return result\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>parameter=None,**kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_getRelatedObjectParameter</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
