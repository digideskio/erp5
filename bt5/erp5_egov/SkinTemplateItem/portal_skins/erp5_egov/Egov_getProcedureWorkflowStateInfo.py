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
            <value> <string>if validation_state==None or workflow_id==None:\n
  return \'\'\n
\n
portal_workflow = context.getPortalObject().portal_workflow\n
history_list = context.portal_workflow.getInfoFor(ob=context, \n
                                          name=\'history\', wf_id=workflow_id)\n
wf_detail={}\n
for history_line in history_list:\n
  if history_line.has_key(\'validation_state\') and history_line[\'validation_state\']==validation_state:\n
    wf_detail=history_line\n
\n
return wf_detail\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>workflow_id=None, validation_state=None, **kw</string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Anonymous</string>
                <string>Assignee</string>
                <string>Assignor</string>
                <string>Associate</string>
                <string>Auditor</string>
                <string>Authenticated</string>
                <string>Author</string>
                <string>Manager</string>
                <string>Member</string>
                <string>Owner</string>
                <string>Reviewer</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Egov_getProcedureWorkflowStateInfo</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
