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
            <value> <string>from json import dumps\n
\n
# sometime instead of real knowledge pad object we may get just its relative url \n
# and actually that\'s what we care for\n
if not isinstance(box, str):\n
  box_relative_url = box.getRelativeUrl()\n
else:\n
  box_relative_url = box\n
\n
editable_mode = context.REQUEST.get(\'editable_mode\', 0)\n
if editable_mode:\n
  editable_mode = 1\n
else:\n
  editable_mode = 0\n
\n
js_update_code = """updater(\'%s\', \'%s\', \'%s\', \'%s\', %s, field_prefix=\'%s\');""" %(url, box_relative_url, dom_id, \n
                                                              editable_mode, dumps(params), field_prefix)\n
if box.getValidationState()==\'invisible\':\n
  # we can generate \n
  javascript_code = """invisible_gadgets["%s"]="%s";""" %(dom_id, js_update_code)\n
else:\n
  javascript_code = js_update_code\n
\n
return javascript_code\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>url, box, dom_id, params={}, ignore_security_check=0, field_prefix=\'\'</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>KnowledgePad_generateAjaxCall</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Generate Ajax JavaScript calls</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
