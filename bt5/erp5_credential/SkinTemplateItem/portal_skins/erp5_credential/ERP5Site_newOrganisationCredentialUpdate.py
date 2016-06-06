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
            <value> <string>"""Create a new credential update"""\n
portal_status_message=""\n
person = context.ERP5Site_getAuthenticatedMemberPersonValue()\n
if person is None:\n
  portal_status_message = context.Base_translateString("Can\'t find corresponding person, it\'s not possible to update your credentials.")\n
else:\n
  organisation = person.getSubordinationValue()\n
  if organisation is None:\n
    portal_status_message = context.Base_translateString("Can\'t find corresponding organisation, it\'s not possible to update your credentials.")\n
  else:\n
    # create the credential update\n
    module = context.getDefaultModule(portal_type=\'Credential Update\')\n
    credential_update = module.newContent(\n
        portal_type="Credential Update",\n
                    default_email_text=default_email_text,\n
                    default_telephone_text=default_telephone_text,\n
                    default_mobile_telephone_text=default_mobile_telephone_text,\n
                    default_fax_text=default_fax_text,\n
                    default_address_street_address=default_address_street_address,\n
                    default_address_city=default_address_city,\n
                    default_address_zip_code=default_address_zip_code,\n
                    default_address_region=default_address_region,\n
                    activity_list=activity_list,\n
                    destination_decision=organisation.getRelativeUrl(),\n
                    default_image_file=default_image_file,\n
                    description=description)\n
\n
    credential_update.submit()\n
    portal_status_message = context.Base_translateString("Credential Update Created.")\n
\n
return context.Base_redirect(dialog_id, keep_items = dict(portal_status_message=portal_status_message ))\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>default_email_text=None, default_telephone_text=None, default_mobile_telephone_text=None, default_fax_text=None, activity_list=None, default_address_city=None, default_address_street_address=None, default_address_zip_code=None,default_address_region=None, default_image_file=None,description=None,dialog_id=\'\', **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Site_newOrganisationCredentialUpdate</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
