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
            <value> <string>CashMovement_cashDetail_parameter = { \'line_portalType\'     : \'Cash Movement Line\'\n
, \'operation_currency\'  : \'EUR\'\n
, \'variation_list\'      : None\n
, \'cashStatus_list\'     : [\'not_defined\']\n
, \'emissionLetter_list\' : None\n
}\n
\n
CashMovement_cashDetail_parameter = { \'line_portalType\' : \'Cash Movement Line\'             # The portal type that the fastinput will create\n
, \'operation_currency\'       : context.Baobab_getPortalReferenceCurrencyID()                      # The operation currency\n
, \'cashStatus_list\'          : None                       # List of possible cashStatus or None if all\n
, \'emissionLetter_list\'      : None                       # List of possible emissionLetter or None if all\n
, \'variation_list\'           : None                       # List of possible variation or None if all\n
, \'currencyCash_portalType\'  : None                       # \'Coin\' or \'Banknote\' or None if both\n
, \'updatePossible\'           : True                       # If true, the fastinput will not allow change\n
, \'columnBase\'               : \'variation\'                # possible values : \'variation\', \'cashStatus\', \'emissionLetter\'\n
#, \'columnBase\'              : \'emissionLetter\'           # possible values : \'variation\', \'cashStatus\', \'emissionLetter\'\n
#, \'columnBase\'              : \'cashStatus\'               # possible values : \'variation\', \'cashStatus\', \'emissionLetter\'\n
}\n
\n
\n
\n
\n
return context.CashDetail_fastInputUpdate( listbox = None\n
                                   , cashDetail_parameter = CashMovement_cashDetail_parameter\n
                                   , destination = context.getObject().absolute_url())\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>CashDetail_loadScript_example</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
