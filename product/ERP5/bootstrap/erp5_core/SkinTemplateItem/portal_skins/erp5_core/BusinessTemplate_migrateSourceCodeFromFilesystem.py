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
            <value> <string>request = context.REQUEST\n
object_list = context.portal_selections.getSelectionValueList(selection_name=request[\'listbox_list_selection_name\'],\n
                                                              context=context,\n
                                                              REQUEST=request)\n
\n
listbox_dict = request[\'listbox\']\n
\n
component_dict = {}\n
for object in object_list:\n
  component_dict.setdefault(object.destination_portal_type,\n
                            {})[object.getUid()] = listbox_dict[object.getUrl()][\'version_item_list\']\n
\n
failed_import_dict = context.migrateSourceCodeFromFilesystem(component_dict, erase_existing, **kw)\n
\n
if failed_import_dict:\n
 failed_import_formatted_list = []\n
 for name, error in failed_import_dict.iteritems():\n
  failed_import_formatted_list.append("%s (%s)" % (name, error))\n
\n
 message = "The following component could not be imported: " + \', \'.join(failed_import_formatted_list)\n
 abort_transaction = True\n
else:\n
 message = "All components were successfully imported from filesystem to ZODB. You can now delete them from your instance home."\n
 abort_transaction=False\n
\n
return context.Base_redirect(\'view\',\n
                             keep_items={\'portal_status_message\': message},\n
                             abort_transaction=abort_transaction)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>erase_existing=False, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>BusinessTemplate_migrateSourceCodeFromFilesystem</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
