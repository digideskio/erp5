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
            <value> <string>"""\n
  This script creates a new event with given metadata and\n
  attaches it to the current ticket.\n
"""\n
translateString = context.Base_translateString\n
module = context.getDefaultModule(portal_type)\n
\n
# Create a new event\n
event = module.newContent(portal_type=portal_type, description=description, title=title, follow_up=context.getRelativeUrl())\n
\n
# Trigger appropriate workflow action\n
if direction == \'incoming\':\n
  event.receive()\n
else:\n
  event.plan()\n
\n
# Redirect to even\n
portal_status_message = translateString("Created and associated a new ${portal_type} to the ticket.", \n
                                    mapping = dict(portal_type = translateString(portal_type)))\n
event.Base_redirect(\'view\', keep_items = dict(portal_status_message=portal_status_message), **kw)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>portal_type, title, description, direction, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Ticket_newEvent</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
