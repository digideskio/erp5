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
            <value> <string>import json\n
\n
form = context.REQUEST.form\n
portal = context.getPortalObject()\n
\n
if len(portal.portal_catalog(portal_type="Person",\n
                             reference=form.get("login_name"))):\n
  return json.dumps(None)\n
\n
person = portal.person_module.newContent(portal_type="Person")\n
person.edit(first_name=form.get("firstname"),\n
            last_name=form.get("lastname"),\n
            email_text=form.get("email"),\n
            password=form.get("password"),\n
            reference=form.get("login_name"))\n
\n
assignment = person.newContent(portal_type=\'Assignment\')\n
assignment.setFunction("ung_user")\n
assignment.open()\n
\n
person.validate()\n
\n
return json.dumps(True)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
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
            <value> <string>ERPSite_createUNGUser</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
