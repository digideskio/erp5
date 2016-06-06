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
            <value> <string>context_obj = context.getObject()\n
\n
role_type = \'Test Case Actor\'\n
\n
# this list contain all items\n
items = []\n
\n
# get the next int index\n
result = context_obj.searchFolder(portal_type = role_type, sort_on = ((\'int_index\', \'DESC\'),), limit = 1)\n
try:\n
  int_index = result[0].getObject().getIntIndex() + 1\n
except:\n
  int_index = 1\n
\n
# get the user information\n
for line in listbox:\n
  if line.has_key(\'listbox_key\') and line[\'title\'] not in (\'\', None):\n
    line_id = int(line[\'listbox_key\'])\n
    item = {}\n
    item[\'id\'] = line_id\n
    item[\'int_index\'] = int_index\n
    item[\'title\'] = line[\'title\']\n
    item[\'description\'] = line[\'description\']\n
    item[\'location\'] = line[\'location\']\n
    item[\'group_free_text\'] = line[\'group_free_text\']\n
    item[\'role\'] = line[\'role\']\n
    items.append(item)\n
    int_index += 1\n
\n
# sort the list by id to have the same order of the user\n
items.sort(lambda x, y: cmp(x[\'id\'], y[\'id\']))\n
\n
# create corresponding objects\n
for item in items:\n
  context_obj.newContent( portal_type         = role_type\n
                        , int_index           = item[\'int_index\']\n
                        , title               = item[\'title\']\n
                        , description         = item[\'description\']\n
                        , location            = item[\'location\']\n
                        , group_free_text     = item[\'group_free_text\']\n
                        , use_case_actor_role = item[\'role\']\n
                        )\n
\n
# return to the feature module\n
return context.REQUEST.RESPONSE.redirect(context.absolute_url() + \'/TestCase_viewTestCaseActorList?portal_status_message=\' + role_type.replace(\' \', \'+\') + \'s+Added.\')\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>listbox=[], **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>TestCase_generateTestCaseActorList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
