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
            <value> <string>from Products.ERP5Type.Message import Message\n
\n
# XXX for now, we always use the default Base_getODSStyleSheet\n
# we use to have Base_getODSListStyleSheet with a line at the bottom of\n
# the page, for better print display. Now we rather agreed that\n
# ods_style is a style for export, not report and the rendering appearance\n
# was not so important.\n
return context.Base_getODSStyleSheet\n
\n
translate = lambda msg: Message(\'ui\', msg)\n
request = context.REQUEST\n
landscape = int(request.get(\'landscape\', 0))\n
if context.pt != \'form_list\':\n
  if landscape == 1:\n
    #normal style sheet with preview of landscape\n
    return context.Base_getODSStyleSheetLandscape\n
  else:\n
    #preview portrait(Default) \n
    return context.Base_getODSStyleSheet\n
else:\n
  if landscape == 1:\n
    #style sheet for list, there is under line in preview\n
    return context.Base_getODSListStyleSheetLandscape\n
  else:\n
    #preview portrait(Default)\n
    return context.Base_getODSListStyleSheet\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_getDynamicODSStyleSheet</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
