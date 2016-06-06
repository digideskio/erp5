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
            <value> <string>marker = []\n
prefix = \'erp5_\'\n
language = \'en\'\n
\n
term_dict = {}\n
result = []\n
\n
for bt_id in template_list:\n
  # XXX this might be too simple: some business template include more than one skin folder\n
  bt = context.portal_templates.getInstalledBusinessTemplate(bt_id)\n
  if bt is None: continue\n
  if bt_id.startswith(prefix):\n
    bt_id = bt_id[len(prefix):]\n
\n
  for wf_id in bt.getTemplateWorkflowIdList():\n
    wf = getattr(context.portal_workflow, wf_id)\n
    if getattr(wf, "interactions", marker) is marker: # only way to make sure it is not an interaction workflow ?\n
      term_dict[(wf_id, bt_id, wf.title, wf.description)] = wf_id\n
      for state_id, state in wf.states.items():\n
        term_dict[(state_id, bt_id, state.title, state.description)] = wf_id\n
      for trans_id, trans in wf.transitions.items():\n
        term_dict[(trans_id, bt_id, trans.title, trans.description)] = wf_id\n
        if trans.trigger_type == 1 and trans.actbox_name: # 1 == TRIGGER_USER_ACTION\n
          term_dict[(\'%s_actbox_name\' % trans_id, bt_id, trans.actbox_name, \'\')] = wf_id\n
\n
for (reference, business_field, title, description), workflow_id in term_dict.items():\n
  result.append({\'reference\': reference,\n
                 \'language\': language,\n
                 \'business_field\': business_field,\n
                 \'title\': title,\n
                 \'description\': description,\n
                 \'workflow_id\':workflow_id})\n
\n
return result\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>template_list</string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Authenticated</string>
                <string>Manager</string>
                <string>Member</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>GlossaryModule_getTermDictListFromWorkflow</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
