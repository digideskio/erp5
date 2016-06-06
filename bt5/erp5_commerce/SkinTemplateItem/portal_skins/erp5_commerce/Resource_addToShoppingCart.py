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

"""\n
  Add resource to shopping cart.\n
"""\n
request = container.REQUEST\n
if resource is None:\n
  resource = context\n
\n
if form_id is not None:\n
  from Products.Formulator.Errors import FormValidationError\n
  form = getattr(context, form_id, None)\n
  quantity = int(request.get(\'field_your_buy_quantity\'))\n
  # FIXME:\n
  # this handling of validation errors should be automatically handled by the \n
  # button itself\n
  try:\n
    params = form.validate_all_to_request(request)\n
  except FormValidationError, validation_errors:\n
    # Pack errors into the request\n
    field_errors = form.ErrorFields(validation_errors)\n
    request.set(\'field_errors\', field_errors)\n
    # Make sure editors are pushed back as values into the REQUEST object\n
    for f in form.get_fields():\n
      field_id = f.id\n
      if request.has_key(field_id):\n
        value = request.get(field_id)\n
        if callable(value):\n
          value(request)\n
    return form(request)\n
\n
shopping_cart = context.SaleOrder_getShoppingCart()\n
shopping_cart_items = context.SaleOrder_getShoppingCartItemList()\n
\n
## check if we don\'t have already such a resource in cart\n
line_found=False\n
for order_line in shopping_cart_items:\n
  if order_line.getResource() == resource.getRelativeUrl():\n
    new_quantity = int(order_line.getQuantity()) + quantity\n
    if new_quantity <= 0:\n
      ## remove items with zero quantity\n
      shopping_cart.manage_delObjects(order_line)\n
    else:\n
      order_line.setQuantity(new_quantity)\n
    line_found=True\n
    break\n
\n
if line_found == False:\n
  ## new Resource so add it to shopping cart\n
  order_line = shopping_cart.newContent(portal_type=\'Sale Order Line\')\n
  order_line.setResource(resource.getRelativeUrl())\n
  order_line.setQuantity(quantity)\n
\n
if( context.getPortalType() == \'Product\'):\n
  context.Base_redirect(\'Resource_viewAsShop\',\n
                      keep_items={\'portal_status_message\':context.Base_translateString("Added to cart.")})\n
else:\n
  context.Base_redirect(\'view\',\n
                      keep_items={\'portal_status_message\':context.Base_translateString("Added to cart.")})\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>resource=None, quantity=1, form_id=None</string> </value>
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
            <key> <string>id</string> </key>
            <value> <string>Resource_addToShoppingCart</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Add resource to shopping cart</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
