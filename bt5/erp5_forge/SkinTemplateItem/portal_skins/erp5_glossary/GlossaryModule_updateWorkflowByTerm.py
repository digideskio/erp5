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
            <value> <string>prefix = \'field_listbox_term_\'\n
prefix_length = len(prefix)\n
suffix = \'_actbox_name\'\n
suffix_length = len(suffix)\n
portal_workflow = context.portal_workflow\n
portal_catalog = context.portal_catalog\n
\n
for i in kw.keys():\n
  is_action = 0\n
  if not(i.startswith(prefix) and kw[i]):\n
    continue\n
\n
  term_uid = int(kw[i])\n
  term = portal_catalog(uid=term_uid)[0].getObject()\n
\n
  wf_item_path = i[prefix_length:]\n
  if wf_item_path.endswith(suffix):\n
    wf_item_path = wf_item_path[:-suffix_length]\n
    is_action = 1\n
  wf_item = portal_workflow.restrictedTraverse(wf_item_path)\n
\n
  if wf_item.meta_type == "Workflow":\n
    wf_item.setProperties(term.getTitle(), description=term.getDescription(), manager_bypass=wf_item.manager_bypass)\n
  elif wf_item.meta_type == "Workflow State":\n
    wf_item.setProperties(term.getTitle(), description=term.getDescription(),\n
        transitions=wf_item.transitions, type_list=wf_item.type_list)\n
  else: # wf_item.meta_type == "Workflow Transition"\n
    guard = getattr(wf_item, \'guard\', None)\n
    if not is_action:\n
      title = term.getTitle()\n
      if wf_item_path.endswith(\'_action\'):\n
        title += \' Action\'\n
      wf_item.setProperties(\n
          title,\n
          wf_item.new_state_id,\n
          description=term.getDescription(),\n
\n
          trigger_type=wf_item.trigger_type,\n
          script_name=wf_item.script_name,\n
          after_script_name=wf_item.after_script_name,\n
          actbox_name = wf_item.actbox_name,\n
          actbox_url = wf_item.actbox_url,\n
          actbox_category = wf_item.actbox_category,)\n
    else:\n
      wf_item.setProperties(\n
          wf_item.title,\n
          wf_item.new_state_id,\n
          description=term.getDescription(),\n
\n
          trigger_type=wf_item.trigger_type,\n
          script_name=wf_item.script_name,\n
          after_script_name=wf_item.after_script_name,\n
          actbox_name = term.getTitle(),\n
          actbox_url = wf_item.actbox_url,\n
          actbox_category = wf_item.actbox_category,)\n
    if guard is not None:\n
      wf_item.Glossary_setGuard(guard)\n
\n
\n
portal_status_message = context.Base_translateString(\'Workflows updated.\')\n
context.Base_redirect(keep_items={\'portal_status_message\':portal_status_message})\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>**kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>GlossaryModule_updateWorkflowByTerm</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
