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
            <value> <string>from Products.PythonScripts.standard import newline_to_br\n
from Products.ERP5Type.Log import log\n
\n
log("Event_getTextContentCorrespondToFormat is deprecated, use Event_getEditorFieldTextContent instead", level=100) # WARNING\n
\n
content_type = context.getContentType()\n
\n
if content_type == \'text/html\' and context.hasFile():\n
  return context.asStrippedHTML()\n
else:\n
  value = context.getTextContent()\n
  if editable:\n
    return value\n
  else:\n
    return newline_to_br(value or "")\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>editable=True</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Event_getTextContentCorrespondToFormat</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>SUPERCEDED by Event_getEditorFieldTextContent</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
