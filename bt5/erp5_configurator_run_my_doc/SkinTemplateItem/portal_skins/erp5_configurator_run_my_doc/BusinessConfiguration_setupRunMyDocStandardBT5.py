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
            <value> <string>configuration_save = context.restrictedTraverse(configuration_save_url)\n
\n
bt5_installation_list = (\'erp5_jquery\',\n
                         \'erp5_web\',\n
                         \'erp5_ingestion_mysql_innodb_catalog\',\n
                         \'erp5_ingestion\',\n
                         \'erp5_ui_test_core\',\n
                         \'erp5_dms\',\n
                         \'erp5_jquery_ui\',\n
                         \'erp5_slideshow_style\',\n
                         \'erp5_knowledge_pad\',\n
                         \'erp5_run_my_doc\',\n
                         \'erp5_run_my_doc_role\')\n
\n
bt5_update_catalog = (\'erp5_ingestion_mysql_innodb_catalog\')\n
\n
for name in bt5_installation_list:\n
  configuration_save.addConfigurationItem("Standard BT5 Configurator Item",\n
                                          title=name, bt5_id=name,\n
                                          update_catalog=(name in bt5_update_catalog)\n
                                          )\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>configuration_save_url=None, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>BusinessConfiguration_setupRunMyDocStandardBT5</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Setup standard ERP5 business templates</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
