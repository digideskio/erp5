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
            <value> <string>changed_object = state_change[\'object\']\n
\n
portal = changed_object.getPortalObject()\n
organisation_module = portal.getDefaultModule(portal_type=\'Organisation\')\n
\n
\n
result = changed_object.portal_catalog(portal_type=\'Organisation\',\n
           vat_code=changed_object.getCompanyNineaNumber())\n
\n
# if the organisation don\'t exists, create it\n
if not len(result):\n
  organisation = organisation_module.newContent(\\\n
      portal_type=\'Organisation\',\n
      title=changed_object.getCompanyName(),\n
      corporate_name=changed_object.getCompanyName(),\n
      address_street_address=changed_object.getCompanyAddress(),\n
      address_city=changed_object.getCityName(),\n
      corporate_registration_code=changed_object.getCompanyRccmNumber(),\n
      vat_code=changed_object.getCompanyNineaNumber(),\n
      activity_code=changed_object.getCompanyCofiNumber(),\n
      default_email_text=changed_object.getCompanyEmail(),\n
      acronym=changed_object.getCompanySigle(),\n
      default_telephone_text=changed_object.getCompanyPhoneNumber(),\n
      default_fax_text=changed_object.getCompanyFaxNumber(),\n
      )\n
else:\n
  organisation = result[0].getObject()\n
\n
# create the person wich represent the company\n
person_module = portal.getDefaultModule(portal_type=\'Person\')\n
accountant = person_module.newContent(portal_type=\'Person\',\n
                         title=changed_object.getAccountantName(),\n
                         default_telephone_text=changed_object.getAccountantTelNumber(),\n
                         default_fax_text=changed_object.getAccountantFax(),\n
                         default_email_text=changed_object.getAccountantEmail(),\n
                         address_street_address=changed_object.getAccountantAddress(),\n
                         address_city=changed_object.getAccountantCity(),\n
                         career_subordination_value=organisation)\n
\n
 \n
# create an assignment to be able to login :\n
from DateTime import DateTime\n
assignment = accountant.newContent(portal_type=\'Assignment\')\n
assignment.setStartDate(DateTime())\n
assignment.setStopDate(DateTime()+365)\n
assignment.setCareerFunction(changed_object.getAccountantFunction())\n
assignment.open()\n
\n
# set the login and password required a manager role, so a script with a \n
# proxy role is used\n
login = context.generateNewLogin(text=changed_object.getAccountantName())\n
password = changed_object.Person_generatePassword()\n
context.EGov_setLoginAndPasswordAsManager(accountant, login, password)\n
accountant.immediateReindexObject()\n
\n
accountant.Person_sendCrendentialsByEMail()\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>state_change</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>SubscriptionForm_createAccount</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
