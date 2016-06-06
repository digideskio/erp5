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
  Return true or false based on if document is convertible or not.\n
"""\n
MARKER = (None, \'\',)\n
portal = context.getPortalObject()\n
\n
portal_type = context.getPortalType()\n
allowed_portal_type_list = portal.getPortalDocumentTypeList() + portal.getPortalEmbeddedDocumentTypeList()\n
\n
if portal_type not in allowed_portal_type_list:\n
  return False\n
\n
# XXX hardcoded validation states blacklist. Do State Types?\n
if context.getValidationState() in ["draft", "deleted", "cancelled", "archived"]:\n
  return False\n
\n
# XXX: we do check if "data" methods exists on pretending to be Document portal types\n
# we need a way to do this by introspection\n
return (getattr(context, "getData", None) is not None and context.getData() not in MARKER) or \\\n
       (getattr(context, "getBaseData", None) is not None and context.getBaseData() not in MARKER)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_isConvertible</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
