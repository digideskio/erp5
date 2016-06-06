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
\n
currency = context.getResourceId()\n
vcurrency = context.getResource()\n
\n
if vcurrency is None :\n
  redirect_url = \'%s/%s?%s\' % ( context.absolute_url()\n
                              , \'view\'\n
                              , \'portal_status_message=Please+select+a+currency.\'\n
                              )\n
  return request.RESPONSE.redirect( redirect_url )\n
\n
if currency != \'XOF\':\n
  cashStatus = [\'valid\']\n
  emissionLetter = [\'not_defined\']\n
  variation = [\'not_defined\']\n
else:\n
  cashStatus = [\'valid\', \'cancelled\', \'to_sort\', \'new_emitted\',\'mutilated\',\'error\']\n
  emissionLetter = None\n
  variation = context.Baobab_getResourceVintageList(banknote=1, coin=1)\n
\n
cash_detail_dict= { \'line_portal_type\'          : \'Incoming Cash Balance Regulation Line\'        # The portal type that the fastinput will create\n
                    , \'operation_currency\'       : currency                            # The operation currently\n
                    , \'cash_status_list\'          : cashStatus                      # List of possible cashStatus or None if all\n
                    , \'emission_letter_list\'      : emissionLetter                                       # List of possible emissionLetter or None if all\n
                    , \'variation_list\'           : variation      # List of possible variation or None if all\n
                    , \'currency_cash_portal_type\': None                                                   # \'Coin\' or \'Banknote\' or None if both\n
                    , \'read_only\'           : False                          # If true, the fastinput will not allow change\n
                    , \'column_base_category\'     : \'variation\'                    # possible values : \'variation\', \'cashStatus\', \'emissionLetter\'\n
                 }\n
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
            <value> <string>CashBalanceRegulation_viewIncomingLineFastInputDialog</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
