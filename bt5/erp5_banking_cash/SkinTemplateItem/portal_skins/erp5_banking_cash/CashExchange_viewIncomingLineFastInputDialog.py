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
a = 1\n
cash_status = [\'to_sort\']\n
cash_detail_dict = { \'line_portal_type\'            : \'Incoming Cash Exchange Line\'             # The portal type that the fastinput will create\n
                     , \'operation_currency\'        : \'XOF\'                          # The operation currently\n
                     , \'cash_status_list\'          : cash_status                    # List of possible cashStatus or None if all\n
                     , \'emission_letter_list\'      : [\'not_defined\',]                # List of possible emissionLetter or None if all\n
                     , \'variation_list\'            : context.Baobab_getResourceVintageList(banknote=1, coin=1)      # List of possible variation or None if all      #[\'2003\']                       # List of possible variation or None if all\n
                     , \'currency_cash_portal_type\' : None                           # \'Coin\' or \'Banknote\' or None if both\n
                     , \'read_only\'                 : False                           # If true, the fastinput will not allow change\n
                     , \'column_base_category\'      : \'variation\'                    # possible values : \'variation\', \'cashStatus\', \'emissionLetter\'\n
}\n
\n
\n
\n
return context.CashDelivery_generateCashDetailInputDialog(listbox = None\n
                                                          , cash_detail_dict = cash_detail_dict\n
                                                          , destination = context.getObject().absolute_url())\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>CashExchange_viewIncomingLineFastInputDialog</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
