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
            <value> <string encoding="cdata"><![CDATA[

request=context.REQUEST\n
portal = context.getPortalObject()\n
Base_translateString = portal.Base_translateString\n
\n
selected_uids = context.portal_selections.updateSelectionCheckedUidList(selection_name,listbox_uid,uids)\n
uids = context.portal_selections.getSelectionCheckedUidsFor(selection_name)\n
\n
if uids == []:\n
  message = Base_translateString("Please select one or more items to delete first.")\n
  qs = \'?portal_status_message=%s\' % message\n
  return request.RESPONSE.redirect( context.absolute_url() + \'/\' + form_id + qs )\n
\n
field_id=\'listbox\'\n
field_selection_name=\'folder_delete_selection\'\n
# XXX If we come from the view mode -> list mode proxy, make sure we don\'t make\n
# another proxy to this proxy.\n
if form_id == \'Base_viewListModeRenderer\':\n
  form_id = context.Base_viewListModeRenderer.listbox.get_value(\'form_id\')\n
  field_id = context.Base_viewListModeRenderer.listbox.get_value(\'field_id\')\n
  field_selection_name = context.Base_viewListModeRenderer.listbox.get_value(\'selection_name\')\n
\n
kw = {\'uid\': uids, \'form_id\': form_id, \'field_id\': field_id}\n
request.set(\'object_uid\', context.getUid())\n
request.set(\'uids\', uids)\n
request.set(\'proxy_form_id\', form_id)\n
request.set(\'proxy_field_id\', field_id)\n
request.set(\'proxy_field_selection_name\', field_selection_name)\n
request.set(\'ignore_hide_rows\', 1)\n
\n
context.portal_selections.setSelectionParamsFor(\'folder_delete_selection\', kw)\n
return context.Folder_viewDeleteDialog(uids=uids, REQUEST=request)\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>selection_index=None,form_id=\'\',uids=[], listbox_uid=[],selection_name=\'\'</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Folder_deleteObjectList</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Delete objects from a folder</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
