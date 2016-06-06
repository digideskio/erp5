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
            <value> <string>if context.getParentValue().getPortalType() not in context.getPortalResourceTypeList() \\\n
     and getattr(context, \'getValidationState\', lambda: "")() in (\'invalidated\', \'deleted\', \'draft\'):\n
  # If this supply line is contained in a supply or trade condition that is not validated, it does not apply.\n
  return None\n
\n
\n
base_category_tuple = (\'resource\', \'price_currency\')\n
\n
if context.getSourceSection():\n
  base_category_tuple += (\'source_section\',)\n
if context.getDestinationSection():\n
  base_category_tuple += (\'destination_section\',)\n
\n
if context.getSource():\n
  base_category_tuple += (\'source\',)\n
if context.getDestination():\n
  base_category_tuple += (\'destination\',)\n
\n
if context.hasProductLine():\n
  category_list = context.getCategoryList() + [\n
    pl.getRelativeUrl() for pl in context.getProductLineValue().getCategoryChildValueList()]\n
  context = context.asContext(categories=category_list)\n
  base_category_tuple += (\'product_line\', )\n
\n
if context.getParentValue().getPortalType() in (\n
    ## XXX There is no portal type group for trade conditions.\n
    \'Sale Trade Condition\',\n
    \'Purchase Trade Condition\',\n
    \'Internal Trade Condition\'):\n
  # Supply Lines from trade conditions are set as specialise to this trade condition,\n
  # so that we can apply a predicate on movements later. Supply Lines from trade condition\n
  # only apply on movements using these trade conditions.\n
  category_list = context.getCategoryList() + [\'specialise/%s\' % context.getParentValue().getRelativeUrl()]\n
  context = context.asContext(categories=category_list)\n
  base_category_tuple += (\'specialise\', )\n
\n
#backwards compatibility\n
mapped_value_property_list = context.getMappedValuePropertyList()\n
if not \'priced_quantity\' in mapped_value_property_list:\n
  mapped_value_property_list.append(\'priced_quantity\')\n
  context.setMappedValuePropertyList(mapped_value_property_list)\n
\n
return context.generatePredicate(membership_criterion_base_category_list = base_category_tuple,\n
                                                 criterion_property_list = (\'start_date\',))\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>*args,**kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>SupplyLine_asPredicate</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
