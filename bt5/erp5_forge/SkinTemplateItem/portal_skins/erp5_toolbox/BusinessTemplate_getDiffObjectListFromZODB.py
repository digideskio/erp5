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
            <value> <string>if REQUEST is not None:\n
  raise ValueError("This script cannot be called from the web")\n
\n
import string\n
import random\n
\n
installed_bt_for_diff = context.Base_createCloneDocument(clone=1, batch_mode=1)\n
\n
random_str = \'\'.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))\n
installed_bt_for_diff.setId("installed_bt_for_diff_%s" % random_str)\n
installed_bt_for_diff.build()\n
diff_object_list = context.Base_getBusinessTemplateDiffObjectList(context, installed_bt_for_diff, detailed=detailed)\n
# XXX replace context.getPortalObject().portal_templates by something like context.getParentObject\n
context.getPortalObject().portal_templates.manage_delObjects(ids=[installed_bt_for_diff.getId()])\n
return diff_object_list\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>REQUEST=None, detailed=False</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>BusinessTemplate_getDiffObjectListFromZODB</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
