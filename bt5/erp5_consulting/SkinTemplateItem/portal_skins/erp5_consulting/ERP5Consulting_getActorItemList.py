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
            <value> <string>def sort(a, b):\n
  return cmp(a[0], b[0])\n
\n
# context_portal_type : [actor_portal_type, actor_container_portal_type]\n
# nb: actor_container must be accessible by just going upward in the tree\n
portal_type_convertion = {\'Use Case\' : [\'Use Case Actor\', \'Use Case\'],\n
                          \'Use Case Scenario\' : [\'Use Case Actor\', \'Use Case\'],\n
                          \'Use Case Scenario Step\' : [\'Use Case Actor\', \'Use Case\'],\n
                          \'Test Case\' : [\'Test Case Actor\', \'Test Case\'],\n
                          \'Test Case Step\' : [\'Test Case Actor\', \'Test Case\'],\n
                          \'Test Report\' : [\'Test Report Actor\', \'Test Report\'],\n
                          \'Test Report Step\' : [\'Test Report Actor\',\'Test Report\']}\n
\n
item_list = [[\'\', \'\']]\n
context_obj = context.getObject()\n
item_portal_type = portal_type_convertion.get(context_obj.getPortalType(), [None])\n
\n
if item_portal_type[0] is not None:\n
  while context_obj is not None \\\n
   and hasattr(context_obj, \'getPortalType\') \\\n
   and context_obj.getPortalType() != item_portal_type[1]:\n
    context_obj = context_obj.getParent()\n
  if context_obj is not None \\\n
   and hasattr(context_obj, \'getPortalType\') \\\n
   and context_obj.getPortalType() == item_portal_type[1]:\n
    obj_list = context_obj.contentValues(filter={\'portal_type\': item_portal_type[0]})\n
    for obj in obj_list:\n
      url = obj.getRelativeUrl()\n
      label = obj.getTitle()\n
      item_list.append([label, url])\n
    item_list.sort(sort)\n
\n
return item_list\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Consulting_getActorItemList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
