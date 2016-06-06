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
group_id = \'my_group\'\n
price_currency = \'EUR;0.01;Euro\'\n
\n
# Setup Categories\n
context.BusinessConfiguration_setupStandardCategory(configuration_save_url)\n
\n
# Setup Portal Type Role\n
context.BusinessConfiguration_setupPortalTypeRole(configuration_save_url)\n
\n
# Setup Organisation\n
context.BusinessConfiguration_setupOrganisation(\n
  configuration_save_url = configuration_save_url,\n
  title = \'ISIH GmbH\',\n
  default_email_text = \'mail@isih-gmbh.de\',\n
  default_telephone_text = \'555-5555\',\n
  default_address_street_address = \'Musterstr. 1\',\n
  default_address_zip_code = \'00001\',\n
  default_address_city = \'Dresden\',\n
  default_address_region = \'region/europe/western_europe/germany\',\n
  price_currency = price_currency\n
  )\n
  \n
# Setup Bank Account\n
configuration_save.addConfigurationItem(\n
  "Bank Account Configurator Item",\n
  title = \'ISIH Bank\',\n
  )\n
  \n
# Setup Employee\n
configuration_save.addConfigurationItem(\n
  "Person Configurator Item", \n
  organisation_id = context.getGlobalConfigurationAttr(\'organisation_id\'),\n
  group_id = group_id,\n
  first_name = \'Herr\',\n
  last_name = \'Admin\',\n
  reference = \'user\',\n
  password = \'test\',\n
  default_email_text = \'herradmin@isih-gmbh.de\',\n
  default_telephone_text = \'\',\n
  function = \'function/company\',\n
  )\n
\n
# Setup Accounting\n
context.BusinessConfiguration_setupAccounting(\n
  configuration_save_url = configuration_save_url,\n
  accounting_plan = \'de\',\n
  period_start_date = DateTime(DateTime().year(), 1, 1),\n
  period_stop_date = DateTime(DateTime().year(), 12, 31),\n
  period_title = DateTime().year()\n
  )\n
  \n
# Setup Preferences\n
context.BusinessConfiguration_setupPreferences(\n
  configuration_save_url = configuration_save_url,\n
  preferred_event_sender_email = \'\',\n
  preferred_date_order = \'dmy\',\n
  lang = [\'erp5_l10n_de\'],\n
  price_currency = price_currency,\n
  )\n
\n
# Setup Simulation\n
context.BusinessConfiguration_setupEBusinessLotseSimulation(\n
                                                  configuration_save_url, **kw)\n
\n
# Catalog Keyword Search Keys are for now hardcoded.\n
configuration_save.addConfigurationItem("Catalog Keyword Key Configurator Item",\n
    key_list=(\'description\', \'title\', \'catalog.description\', \'catalog.title\'))\n
\n
# This could be a customer decision option\n
# configuration_save.addConfigurationItem("Site Property Configurator Item",\n
#     site_property_list=[[[\'email_from_address\', \'email@example.com\', \'string\'],]])\n
\n
# Customize portal type information.\n
# Include Constraints to some Simulation Objects\n
for portal_type in [\'Purchase Order\', \'Sale Order\']:\n
  configuration_save.addConfigurationItem("Portal Type Configurator Item",\n
                                        target_portal_type=portal_type,\n
                                        add_propertysheet_list=(\'TradeOrder\',))\n
\n
for portal_type in [\'Purchase Order Line\', \'Sale Order Line\',\'Sale Packing List Line\']:\n
  configuration_save.addConfigurationItem("Portal Type Configurator Item",\n
                                        target_portal_type=portal_type,\n
                                        add_propertysheet_list=(\'TradeOrderLine\',))\n
\n
configuration_save.addConfigurationItem("Portal Type Configurator Item",\n
                                        target_portal_type=\'Inventory\',\n
                                        add_propertysheet_list=(\'InventoryConstraint\',))\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>configuration_save_url=None, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>BusinessConfiguration_displayEBusinessLotseDownload</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
