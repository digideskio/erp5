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
            <value> <string>order = context\n
\n
# copy categories\n
category_list = [\n
  \'source\', \'source_section\', \'source_decision\',\n
  \'source_administration\', \'source_payment\', \'source_project\',\n
  \'source_carrier\', \'source_referral\', \'source_function\',\n
  \'source_trade\',\n
  \'destination\', \'destination_section\', \'destination_decision\',\n
  \'destination_administration\', \'destination_payment\', \'destination_project\',\n
  \'destination_carrier\', \'destination_referral\', \'destination_function\',\n
  \'destination_trade\',\n
  \'price_currency\', \'incoterm\', \'delivery_mode\',\n
]\n
new_category_dict = {}\n
\n
\n
def getPropertyFromTradeCondition(trade_condition, property_name):\n
  """Get a property from the trade condition, or from a specialised trade\n
  condition\n
  """\n
  v = trade_condition.getProperty(property_name)\n
  if v:\n
    return v\n
  for specialised_trade_condition in trade_condition.getSpecialiseValueList():\n
    v = getPropertyFromTradeCondition(\n
              specialised_trade_condition, property_name)\n
    if v:\n
      return v\n
\n
if not reverse_arrow_category:\n
  for category in category_list:\n
    if force or not order.getPropertyList(category):\n
      v = getPropertyFromTradeCondition(trade_condition, category)\n
      if v:\n
        new_category_dict[category] = v\n
        # for accounting transactions, we also initialize resource with the price\n
        # currency\n
        if category == \'price_currency\' and \\\n
            context.getPortalType() in \\\n
            context.getPortalAccountingTransactionTypeList():\n
          new_category_dict[\'resource\'] = v\n
else:\n
  # Reverse source and destination\n
  # This is useful for Returned Sale/Purchase XXX types.\n
  reverse_dict = {\n
    \'source\':\'destination\',\n
    \'source_section\':\'destination_section\',\n
    \'source_decision\':\'destination_decision\',\n
    \'source_administration\':\'destination_administration\',\n
    \'source_payment\':\'destination_payment\',\n
    \'source_project\':\'destination_project\',\n
    \'source_carrier\':\'destination_carrier\',\n
    \'source_referral\':\'destination_referral\',\n
    \'source_function\':\'destination_function\',\n
    \'destination\':\'source\',\n
    \'destination_section\':\'source_section\',\n
    \'destination_decision\':\'source_decision\',\n
    \'destination_administration\':\'source_administration\',\n
    \'destination_payment\':\'source_payment\',\n
    \'destination_project\':\'source_project\',\n
    \'destination_carrier\':\'source_carrier\',\n
    \'destination_referral\':\'source_referral\',\n
    \'destination_function\':\'source_function\',\n
    }\n
  for category in category_list:\n
    if force or not order.getPropertyList(category):\n
      if category in reverse_dict:\n
        trade_condition_category = reverse_dict[category]\n
      else:\n
        trade_condition_category = category\n
      v = getPropertyFromTradeCondition(trade_condition, trade_condition_category)\n
      if v:\n
        new_category_dict[category] = v\n
        # for accounting transactions, we also initialize resource with the price\n
        # currency\n
        if category == \'price_currency\' and \\\n
            context.getPortalType() in \\\n
            context.getPortalAccountingTransactionTypeList():\n
          new_category_dict[\'resource\'] = v\n
\n
# set specialise\n
new_category_dict[\'specialise\'] = trade_condition.getRelativeUrl()\n
\n
order.edit(**new_category_dict)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>trade_condition, force=0, reverse_arrow_category=0</string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Manager</string>
                <string>Owner</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>guard</string> </key>
            <value>
              <persistent> <string encoding="base64">AAAAAAAAAAI=</string> </persistent>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Order_applyTradeCondition</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="2" aka="AAAAAAAAAAI=">
    <pickle>
      <global name="Guard" module="Products.DCWorkflow.Guard"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>permissions</string> </key>
            <value>
              <tuple>
                <string>Modify portal content</string>
              </tuple>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
