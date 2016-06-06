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
            <value> <string>"""Collect all possible (sub contained) Ram Cache Plugins.\n
   This collection will be used in respective report form."""\n
from Products.ERP5Form.Report import ReportSection\n
\n
result = []\n
for ram_cache_plugin in context.getPortalObject().portal_catalog(\n
                                             portal_type = \'Ram Cache\',\n
                                             path =\'%\' + context.getRelativeUrl() +\'%\'):\n
  result.append(ReportSection(path = ram_cache_plugin.getRelativeUrl(), \n
                              form_id = \'RamCache_viewStatisticList\',\n
                              title = \'%s/%s\' %(ram_cache_plugin.getParentValue().getTitle(),\n
                                                ram_cache_plugin.getTitle()),))\n
return result\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>CacheFactory_getAggregatedCachePluginListStatisticList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
