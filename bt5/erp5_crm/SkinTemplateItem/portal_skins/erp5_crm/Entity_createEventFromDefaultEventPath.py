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
            <value> <string>portal = context.getPortalObject()\n
\n
event_path = portal.restrictedTraverse(event_path)\n
\n
follow_up = event_path.getParentRelativeUrl()\n
event_portal_type = event_path.getEventPortalType()\n
resource_reference = event_path.getResourceReference()\n
source = event_path.getSource()\n
\n
language = context.getLanguage()\n
if not language:\n
  language = portal.portal_preferences.getPreferredCustomerRelationLanguage()\n
notification_message = portal.notification_message_module.NotificationTool_getDocumentValue(\n
  resource_reference,\n
  language=language)\n
assert notification_message is not None, "%s not found." % resource_reference\n
\n
event = context.Base_addEvent(title=\'\',\n
  direction=\'outgoing\',\n
  portal_type=event_portal_type,\n
  resource=notification_message.getSpecialise(),\n
  notification_message=resource_reference,\n
  keep_draft=keep_draft,\n
  follow_up=follow_up,\n
  source=source,\n
  language=language,\n
  batch_mode=True)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>event_path, keep_draft</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Entity_createEventFromDefaultEventPath</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
