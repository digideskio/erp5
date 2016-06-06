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
            <value> <string encoding="cdata"><![CDATA[

result = context.getPriceParameterDict(context=movement, **kw)\n
\n
# Calculate\n
#     ((base_price + SUM(additional_price) +\n
#     variable_value * SUM(variable_additional_price)) *\n
#     (1 - MIN(1, MAX(SUM(discount_ratio) , exclusive_discount_ratio ))) +\n
#     SUM(non_discountable_additional_price)) *\n
#     (1 + SUM(surcharge_ratio))\n
#     Or, as (nearly) one single line :\n
#     ((bp + S(ap) + v * S(vap))\n
#       * (1 - m(1, M(S(dr), edr)))\n
#       + S(ndap))\n
#     * (1 + S(sr))\n
# Variable value is dynamically configurable through a python script.\n
# It can be anything, depending on business requirements.\n
# It can be seen as a way to define a pricing model that not only\n
# depends on discrete variations, but also on a continuous property\n
# of the object\n
\n
base_price = result["base_price"]\n
if base_price in (None, ""):\n
  # XXX Compatibility\n
  # base_price must not be defined on resource\n
  base_price = context.getBasePrice()\n
  if base_price in (None, ""):\n
    return {"price": default,\n
            "base_unit_price": result.get(\'base_unit_price\')}\n
\n
for x in ("additional_price",\n
          "variable_additional_price",\n
          "discount_ratio",\n
          "non_discountable_additional_price",\n
          "surcharge_ratio"):\n
  result[x] = sum(result[x])\n
\n
unit_base_price = result["variable_additional_price"]\n
if unit_base_price:\n
  method = None if movement is None else \\\n
           movement.getTypeBasedMethod("getPricingVariable")\n
  if method is None:\n
    method = context.getTypeBasedMethod("getPricingVariable")\n
  if method is None:\n
    unit_base_price = 0\n
  else:\n
    unit_base_price *= method()\n
\n
unit_base_price += base_price + result["additional_price"]\n
\n
# Discount\n
d_ratio = max(result["discount_ratio"], result[\'exclusive_discount_ratio\'] or 0)\n
if d_ratio > 0:\n
  unit_base_price *= max(0, 1 - d_ratio)\n
\n
# Sum non discountable additional price\n
unit_base_price += result[\'non_discountable_additional_price\']\n
\n
# Surcharge ratio\n
unit_base_price *= 1 + result["surcharge_ratio"]\n
\n
# Divide by the priced quantity\n
priced_quantity = result[\'priced_quantity\']\n
if priced_quantity:\n
  unit_base_price /= priced_quantity\n
\n
result["price"] = unit_base_price\n
return result\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>default=None, movement=None, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Resource_getPriceCalculationOperandDict</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
