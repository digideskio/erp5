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
            <value> <string>from Products.ERP5Type.Message import translateString\n
free_subscription = context.getPortalObject().free_subscription_module.newContent(\n
  portal_type=\'Free Subscription\',\n
  destination_value=context,\n
  source=source,\n
  resource=resource,\n
  effective_date=start_date,\n
  title=title)\n
\n
free_subscription.validate()\n
\n
if batch_mode:\n
  return free_subscription\n
  \n
return context.Base_redirect(form_id, keep_items=dict(\n
  portal_status_message=translateString("New free subscription created")))\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>source, resource, start_date, title="", batch_mode=False, form_id=None, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Entity_createFreeSubscription</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
