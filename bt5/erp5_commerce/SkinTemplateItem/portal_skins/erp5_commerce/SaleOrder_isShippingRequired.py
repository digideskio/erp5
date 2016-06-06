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
            <key> <string>_Change_Python_Scripts_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_Change_bindings_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_Change_cache_settings_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_Change_permissions_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_Change_proxy_roles_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_Copy_or_Move_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_Delete_objects_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_Manage_WebDAV_Locks_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_Manage_properties_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_Take_ownership_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_Undo_changes_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_View_History_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_View_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_View_management_screens_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_WebDAV_Lock_items_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_WebDAV_Unlock_items_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
        </item>
        <item>
            <key> <string>_WebDAV_access_Permission</string> </key>
            <value>
              <list>
                <string>Manager</string>
              </list>
            </value>
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

\'\'\'\n
If all product have no Weight, it don\'t need to be sheep. \n
\'\'\'\n
return False\n
shopping_cart_items = context.SaleOrder_getShoppingCartItemList()\n
\n
weight = 0\n
for order_line in shopping_cart_items:\n
  resource = order_line.getResourceValue()\n
  weight  += resource.getBaseWeight(0)\n
\n
return weight > 0\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Assignor</string>
                <string>Manager</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>SaleOrder_isShippingRequired</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Is shipping required for current shopping cart?</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
