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
            <value> <string>"""Add an object of the same type as self in the container, unless\n
this type cannot be added in the container.\n
"""\n
Base_translateString = context.Base_translateString\n
REQUEST=context.REQUEST\n
parent = context.getParentValue()\n
allowed_type_list = parent.getVisibleAllowedContentTypeList()\n
\n
if not allowed_type_list:\n
  return context.ERP5Site_redirect(\'%s/%s\' % (context.absolute_url(), form_id),\n
        keep_items={\'portal_status_message\':Base_translateString("You are not allowed to add new content in this context.")})\n
\n
if context.getPortalType() not in allowed_type_list:\n
  return context.ERP5Site_redirect(\'%s/%s\' % (context.absolute_url(), form_id),\n
        keep_items={\'portal_status_message\':Base_translateString("You are not allowed to add ${portal_type} in this context.",\n
              mapping=dict(portal_type=context.getTranslatedPortalType()))})\n
  \n
new_content = parent.newContent(portal_type=context.getPortalType())\n
return context.ERP5Site_redirect(\'%s/%s\' % (new_content.absolute_url(), form_id),\n
              keep_items={\'portal_status_message\':Base_translateString("Object created.")})\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>form_id=\'view\'</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_createNewDocument</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
