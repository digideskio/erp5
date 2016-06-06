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
            <value> <string encoding="cdata"><![CDATA[

query_dict = {}\n
for key in kw.keys():\n
  if key == "portal_type":\n
    query_dict["portal_type"] = kw[key]\n
  else:\n
    query_dict[key] = dict(query=kw[key], key=\'ExactMatch\')\n
result_list = context.portal_catalog(**query_dict)\n
owner_id = context.portal_membership.getAuthenticatedMember().getId()\n
functional_test_username = context.Zuite_getHowToInfo()[\'functional_test_username\']\n
functional_another_test_username = context.Zuite_getHowToInfo()[\'functional_another_test_username\']\n
\n
for result in result_list:\n
  object = result.getObject()\n
  # check that every property of the research have been well taken in account\n
  for key in kw.keys():\n
    method_name = \'get%s\' % (\'\'.join([x.capitalize() for x in key.split(\'_\')]))\n
    method = getattr(object, method_name)\n
    if strict_check_mode and method() != kw[key]:\n
      raise RuntimeError, "One property is not the same that you wanted : you asked \'%s\' and expecting \'%s\' but get \'%s\'" % (key, kw[key], method())\n
  # check that every object are owner by you\n
  if strict_check_mode and object.Base_getOwnerId() not in [owner_id, functional_test_username, \'System Processes\',\'zope\', functional_another_test_username]:\n
    raise RuntimeError, "You have try to clean an item who haven\'t you as owner : %s is owned by %s and you are %s" % \\\n
         (object.getTitle(), object.Base_getOwnerId(), owner_id)\n
\n
if strict_check_mode and max_count is not None:\n
  if len(result_list) <= max_count:\n
    if len(result_list) == 0:\n
      return None\n
    else:\n
      return result_list    \n
  else:\n
    raise RuntimeError, \'The catalog return more item that you ask.\'\n
\n
if len(result_list) == 0:\n
  return None\n
return result_list\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>max_count=None, strict_check_mode=1, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Zuite_checkPortalCatalog</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
