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
            <value> <string>\n
portal = context.getPortalObject()\n
howto_dict = context.Zuite_getHowToInfo()\n
\n
# check if there is already the euro curency on the instance\n
currency = context.portal_catalog.getResultValue(portal_type=\'Currency\',\n
                                                 title=howto_dict[\'sale_howto_currency_title\'])\n
\n
# add default sale order trade condition\n
sale_order_trade_condition = context.portal_catalog.getResultValue(portal_type=\'Sale Trade Condition\',\n
                                                                  reference=\'STC-General\')\n
\n
# Get the documents created by setUpSaleOrder\n
product = context.portal_catalog.getResultValue(portal_type=\'Product\',\n
                                             title=howto_dict[\'sale_howto_product_title\'])\n
\n
my_organisation = context.portal_catalog.getResultValue(portal_type=\'Organisation\',\n
                                                        title=howto_dict[\'sale_howto_organisation_title\'])\n
\n
organisation = context.portal_catalog.getResultValue(portal_type=\'Organisation\',\n
                                                     title=howto_dict[\'sale_howto_organisation2_title\'])\n
\n
person = context.portal_catalog.getResultValue(portal_type=\'Person\',\n
                                         title=howto_dict[\'sale_howto_person_title\'])\n
\n
\n
sale_order = portal.sale_order_module.newContent(\n
                                   portal_type=\'Sale Order\',                                   title=\'ZUITE-TEST-SALEORDER-PRODUCT-001\',                                   specialise=sale_order_trade_condition.getRelativeUrl(),\n
                                   destination_section=organisation.getRelativeUrl(),\n
                                   destination=organisation.getRelativeUrl(),\n
                                   source_section=my_organisation.getRelativeUrl(),\n
                                   source=my_organisation.getRelativeUrl(),\n
                                   source_decision=my_organisation.getRelativeUrl(),\n
                                   destination_decision=organisation.getRelativeUrl(),\n
                                   destination_administration=person.getRelativeUrl(),\n
                                   source_administration=my_organisation.getRelativeUrl(),\n
                                   delivery_mode=\'delivery_mode/air\',\n
                                   order=\'order/normal\',\n
                                   start_date=DateTime().earliestTime(),\n
                                   stop_date=DateTime().earliestTime()+1,\n
)\n
sale_order.setPriceCurrency(currency.getRelativeUrl())\n
sale_order.setIncoterm(\'incoterm/cpt\')\n
\n
sale_order.newContent(portal_type=\'Sale Order Line\',\n
                      resource=product.getRelativeUrl(), price=1.0, quantity=100000.0)\n
sale_order.confirm()\n
# Clear cache\n
portal.portal_caches.clearAllCache()\n
\n
return "Init Ok"\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>clean=True</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Zuite_setUpSalePackingListTest</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
