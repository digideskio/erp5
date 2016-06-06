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
            <value> <string>error_list = []\n
return_list = []\n
\n
for category in context.portal_categories.objectValues():\n
  #print "#### Indexing inside the folder %s ####" % \'portal_categories\'\n
  error_list += context.reindexAll(object=category,request=context)\n
\n
nb_types = {}\n
\n
for error in error_list:\n
  # We count the number of each portal type\n
  if error[1]==\'portal_type\':\n
    type = error[3]\n
    if nb_types.has_key(type):\n
      nb_types[type] = nb_types[type] + 1\n
    else:\n
      nb_types[type] = 1\n
  else: \n
    #print error\n
    return_list.append(error)\n
\n
for type in nb_types.keys():\n
  # Find the number of each portal type in the catalog\n
  count_result = context.portal_catalog.countResults(portal_type=type)\n
  nb_catalog = count_result[0][0]\n
  if nb_types[type] != nb_catalog:\n
    message = "XXX Warning for %s: there is %i lines in the catalog instead of %i" % \\\n
      (type,nb_catalog,nb_types[type])\n
    return_list.append((\'Count Error\', \'PortalRoot_reindexAll\',1,message))\n
  #else: print "%s: %i" % (type,nb_types[type])\n
\n
return return_list\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>request=None</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Site_reindexCategory</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
