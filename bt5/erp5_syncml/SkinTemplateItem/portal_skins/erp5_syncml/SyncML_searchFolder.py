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
            <value> <string># This is the default "List Method ID" to use to list object from a module in erp5\n
# this method is optimized to return group of document based on what the syncml engine\n
# required\n
# XXX Some parameter are not managed (context_document, gid, etc)\n
\n
\n
if len(kw):\n
  context.log("kw %s" %(kw,))\n
\n
catalog_kw = {\'limit\' : limit}\n
if min_id and id_list:\n
  raise NotImplementedError\n
\n
if min_id:\n
  catalog_kw[\'id\'] = {\'query\': min_id, \'range\': \'nlt\'}\n
elif id_list:\n
  catalog_kw[\'id\'] = {\'query\': id_list, \'operator\': \'in\'}\n
\n
\n
return context.searchFolder(sort_on=((\'id\',\'ascending\'),), **catalog_kw)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>id_only=False, min_id=None, id_list=None, limit=None, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>SyncML_searchFolder</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
