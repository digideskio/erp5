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
            <value> <string># Manually force restricted mode in the ERP5Document_getHateoas\n
# Can not be done quickly with Security handling, as it redirects the request to the login form\n
\n
new_skin_name = "Hal"\n
context.getPortalObject().portal_skins.changeSkin(new_skin_name)\n
if REQUEST is None:\n
  REQUEST = context.REQUEST\n
REQUEST.set(\'portal_skin\', new_skin_name)\n
\n
return context.ERP5Document_getHateoas(\n
  REQUEST=REQUEST,\n
  response=response,\n
  view=view,\n
  mode=mode,\n
  query=query,\n
  select_list=select_list,\n
  limit=limit,\n
  form=form,\n
  relative_url=relative_url,\n
  list_method=list_method,\n
  default_param_json=default_param_json,\n
  form_relative_url=form_relative_url,\n
  bulk_list=bulk_list,\n
  sort_on=sort_on,\n
  local_roles=local_roles,\n
  restricted=1\n
)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>REQUEST=None, response=None, view=None, mode=\'root\', query=None, select_list=None, limit=10, local_roles=None, form=None, relative_url=None, list_method=None, default_param_json=None, form_relative_url=None, bulk_list="[]", sort_on=None</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Document_getHateoas</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
