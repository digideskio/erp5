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
source = context.getSource()\n
currency = context.Baobab_getPortalReferenceCurrencyID()\n
source_section = context.getSourceSection()\n
\n
if source is None:\n
  redirect_url = \'%s/%s?%s\' % ( context.absolute_url()\n
                                , \'view\'\n
                                , \'portal_status_message=Please+select+a+source.\'\n
                                )\n
  return request.RESPONSE.redirect( redirect_url )\n
\n
\n
if \'serre\' in source:\n
  cash_status = [\'retired\',\'error\']\n
else:\n
  cash_status = [\'cancelled\',\'mutilated\', \'maculated\',\'error\']\n
\n
# Select the emission letter of the remote site if there is one defined\n
if source_section is None:\n
  emission_letter = context.Baobab_getUserEmissionLetterList() \n
else:\n
  emission_letter = list((context.getSourceSectionValue().getCodification()[0]).lower())\n
\n
\n
variation = context.Baobab_getResourceVintageList(banknote=1, coin=1)\n
\n
#, \'emission_letter_list\'     : emission_letter A REMETTRE APRES LES TESTS\n
cash_detail_dict = {\'line_portal_type\'           : \'Monetary Destruction Line\'\n
                    , \'operation_currency\'       : currency\n
                    , \'cash_status_list\'         : cash_status\n
                    , \'emission_letter_list\'      : emission_letter\n
                    , \'variation_list\'           : variation\n
                    , \'currency_cash_portal_type\': None\n
                    , \'read_only\'                : False\n
                    , \'column_base_category\'     : \'variation\'\n
                    }\n
\n
return context.CashDelivery_generateCashDetailInputDialog(listbox = None\n
                                                          , cash_detail_dict = cash_detail_dict\n
                                                          , destination = context.getObject().absolute_url()\n
                                                          )\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>MonetaryDestruction_viewLineFastInputDialog</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
