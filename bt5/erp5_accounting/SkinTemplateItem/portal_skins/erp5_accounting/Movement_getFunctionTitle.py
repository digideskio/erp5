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
            <value> <string>movement = context.getObject()\n
function_uid = context.function_uid\n
\n
title_dict = container.REQUEST.get(\n
      \'Movement_getFunctionTitle.function_title_dict\') or {}\n
if function_uid in title_dict:\n
  return title_dict[function_uid]\n
\n
if movement.getSourceFunctionUid() == function_uid:\n
  reference = movement.getSourceFunctionReference()\n
  if reference:\n
    return \'%s - %s\' % (reference, movement.getSourceFunctionTranslatedTitle())\n
  return movement.getSourceFunctionTranslatedTitle()\n
\n
reference = movement.getDestinationFunctionReference()\n
if reference:\n
  return \'%s - %s\' % (reference, movement.getDestinationFunctionTranslatedTitle())\n
return movement.getDestinationFunctionTranslatedTitle()\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Movement_getFunctionTitle</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
