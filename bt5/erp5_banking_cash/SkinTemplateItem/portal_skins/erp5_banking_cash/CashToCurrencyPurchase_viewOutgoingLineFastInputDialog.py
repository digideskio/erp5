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
            <value> <string>request = context.REQUEST\n
source = context.getSource()\n
source_section = context.getSourceSection()\n
\n
#cash_status = [\'valid\', \'new_emitted\']\n
cash_status = [\'valid\']\n
#emission_letter = None\n
#emission_letter = list((context.getSourceValue().getCodification()[0]).lower())\n
emission_letter = context.Baobab_getUserEmissionLetterList()\n
context.log(\'emission_letter\',emission_letter)\n
variation = context.Baobab_getResourceVintageList(banknote=1, coin=1)\n
\n
cash_detail_dict = {\'line_portal_type\'           : \'Outgoing Cash To Currency Purchase Line\'\n
                    , \'operation_currency\'       : context.Baobab_getPortalReferenceCurrencyID()\n
                    , \'cash_status_list\'         : cash_status\n
                    , \'emission_letter_list\'     : emission_letter\n
                    , \'variation_list\'           : variation\n
                    , \'currency_cash_portal_type\': None\n
                    , \'read_only\'                : False\n
                    , \'column_base_category\'     : \'variation\'\n
                    }\n
\n
return context.CashDelivery_generateCashDetailInputDialog(listbox = None\n
                                                          , cash_detail_dict = cash_detail_dict\n
                                                          , destination = context.getObject().absolute_url()\n
                                                          , target_total_price = context.getQuantity()\n
                                                          )\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>CashToCurrencyPurchase_viewOutgoingLineFastInputDialog</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
