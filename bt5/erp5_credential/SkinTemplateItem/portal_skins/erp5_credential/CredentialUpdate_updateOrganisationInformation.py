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
            <value> <string>"""Copy subscription information to related person"""\n
\n
organisation = context.getDestinationDecisionValue(portal_type="Organisation")\n
\n
#Mapping\n
organisation_mapping = (\n
    # (subscription, organisation)\n
    (\'default_email_text\', \'default_email_text\'),\n
    (\'default_telephone_text\', \'default_telephone_text\'),\n
    (\'default_fax_text\', \'default_fax_text\'),\n
    (\'default_address_street_address\', \'default_address_street_address\'),\n
    (\'default_address_zip_code\', \'default_address_zip_code\'),\n
    (\'default_address_city\', \'default_address_city\'),\n
    (\'default_address_region\', \'default_address_region\'),\n
    (\'default_mobile_telephone_text\', \'default_mobile_telephone_text\'),\n
    (\'activity_list\', \'activity_list\'),\n
    (\'description\', \'description\'),\n
    )\n
\n
context.Credential_copyRegistredInformation(organisation, organisation_mapping)\n
\n
#Update the logo\n
context.CredentialUpdate_copyDefaultImage()\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>CredentialUpdate_updateOrganisationInformation</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
