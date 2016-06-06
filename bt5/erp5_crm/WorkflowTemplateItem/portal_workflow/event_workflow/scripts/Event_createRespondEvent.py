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
            <value> <string># this script allows to create a new respond event for\n
# the current event and send message immediately.\n
portal = state_change.getPortal()\n
portal_workflow = portal.portal_workflow\n
event = state_change[\'object\']\n
\n
portal_type = portal_workflow.getInfoFor(event,\n
                                         \'respond_event_portal_type\',\n
                                         wf_id=\'event_workflow\')\n
\n
# Pass Mark Responded transition.\n
if not portal_type:\n
  return\n
\n
title = portal_workflow.getInfoFor(event,\n
                                   \'respond_event_title\',\n
                                   wf_id=\'event_workflow\')\n
resource = portal_workflow.getInfoFor(event,\n
                                      \'respond_event_resource\',\n
                                      wf_id=\'event_workflow\')\n
text_content = portal_workflow.getInfoFor(event,\n
                                          \'respond_event_text_content\',\n
                                          wf_id=\'event_workflow\')\n
\n
event.Event_createRespondEvent(portal_type, title, resource, text_content)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>state_change</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Event_createRespondEvent</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
