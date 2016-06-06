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
            <value> <string>listbox = kw.get(\'listbox\', ())\n
update_catalog = update_translation = 0\n
\n
bt_id_list = getattr(context.REQUEST, \'bt_list\', ())\n
bt_dict = {}\n
object_to_update = {}\n
for item in listbox:\n
  # backward compatibility\n
  if not same_type(item[\'choice\'], []):\n
    item[\'choice\'] = [item[\'choice\']]\n
\n
  if item[\'choice\']:\n
    choice = item[\'choice\'][0]\n
  else:\n
    choice = "nothing"\n
  bt_id, object_id = item[\'listbox_key\'].split(\'|\')\n
  bt_dict.setdefault(bt_id, {})[object_id] = choice\n
\n
bt_title_list = []\n
for bt_id in bt_id_list:\n
  try:\n
    object_list = bt_dict[bt_id]\n
  except KeyError:\n
    object_list = {}\n
  if bt_id == bt_id_list[-1]:\n
    update_catalog = kw.get(\'update_catalog\')\n
    update_translation = kw.get(\'update_translation\')\n
  bt = context.portal_templates[bt_id]\n
  bt.install(force=0, object_to_update=object_list, update_catalog=update_catalog,\n
             update_translation=update_translation)\n
  bt_title_list.append(bt.getTitle())\n
\n
REQUEST = container.REQUEST\n
RESPONSE = REQUEST.RESPONSE\n
\n
return RESPONSE.redirect("%s/view?portal_status_message=Business+Template+%s+installed" % \\\n
                         (context.absolute_url(), \',+\'.join(bt_title_list)))\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>**kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>TemplateTool_installBusinessTemplateListAction</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
