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
This script creates a new content from any part of a Web Site.\n
Content will be created in the appropriate module. It is\n
intended to be called from the user interface only.\n
"""\n
translateString = context.Base_translateString\n
request = context.REQUEST\n
\n
# Create the new content in appropriate module\n
portal_object = context.getPortalObject()\n
module = portal_object.getDefaultModule(portal_type)\n
new_object = module.newContent(portal_type=portal_type)\n
\n
# Redirect to new content with translated message\n
portal_status_message = translateString("New ${portal_type} created.", mapping = dict(portal_type = portal_type))\n
return new_object.Base_redirect(\'view\', keep_items = dict(portal_status_message=portal_status_message,\n
                                                          editable_mode=1))\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>portal_type</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Site_newContent</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
