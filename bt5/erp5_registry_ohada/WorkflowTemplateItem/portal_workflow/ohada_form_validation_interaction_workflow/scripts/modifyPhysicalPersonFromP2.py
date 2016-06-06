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
This script collects *all* filled properties in the P2\n
request_eform and updates the person and the organisation already\n
created with the P0.\n
"""\n
\n
# Initalize some useful variables\n
from Products.ZSQLCatalog.SQLCatalog import ComplexQuery\n
from Products.ZSQLCatalog.SQLCatalog import Query\n
from Products.DCWorkflow.DCWorkflow import ValidationFailed\n
request_eform = state_change[\'object\']\n
portal = request_eform.getPortalObject()\n
organisation_module = portal.organisation_module\n
person_module = portal.person_module\n
\n
date = request_eform.getDate()\n
#Custom method used to create custom-made corporate_registration_codes for the companies\n
def attachLocationYearInfo(last_id):\n
  location_info = request_eform.getSite().split(\'/\')[0]\n
  if location_info == \'dakar\':\n
    location_initials = \'DKR\'\n
  elif location_info == \'thies\':\n
    location_initials = \'TH\'\n
  elif location_info == \'saint-louis\':\n
    location_initials = \'SL\'\n
  year = str(date.year())\n
  type_of_form = \'M\'\n
  attach_info = \'SN\' + location_initials + year + type_of_form\n
  last_corporate_registration_code = str(str(last_id).split(\'-\').pop())\n
  new_corporate_registration_code  = \'%05d\' % int(str(int(last_corporate_registration_code)+1))\n
  return (\'-\'.join([\'SN\', location_initials, year, type_of_form,new_corporate_registration_code]))\n
\n
# We shall now allocate a new registry number\n
# using the custom method attachLocationYearInfo\n
# we use corporate_registry for corporations and\n
# merchant_registry for merchants.\n
# the id_group is extended with the group path so that\n
# each local registry has a different sequence\n
default_address_city = request_eform.getPlace()\n
group = (date.year(),)\n
new_registry_number = request_eform.portal_ids.generateNewId(\n
                                     id_group = group,\n
                                     method = attachLocationYearInfo)\n
\n
#variable used to store activity of the organisation,activities should be separated with commas, and no space between them\n
activity_list=[]\n
request_eform.setTitle(request_eform.getOwnerFirstName()+\' \'+request_eform.getOwnerLastName())\n
#build a query to search for the merchant\n
query=ComplexQuery(Query(title=request_eform.getTitle()),\n
             Query(birth_date=request_eform.getOwnerBirthday()),\n
             Query(birthplace_city=request_eform.getOwnerBirthplace()),\n
             operator="AND")\n
person_list=[person.getObject() for person in \\\n
       context.portal_catalog(portal_type=\'Person\',query=query)]\n
\n
if len(person_list) >1 :\n
  raise ValidationFailed, "Error : There is more than one person with the "\\\n
            " title \'%s\', birth date \'%s\' and birthplace \'%s\'" % (\n
                request_eform.getTitle(),\n
                request_eform.getOwnerBirthday(),\n
                request_eform.getOwnerBirthplace())\n
elif len(person_list) == 0:\n
  raise ValidationFailed, "Error : There is nobody with the "\\\n
            " title \'%s\', birth date \'%s\' and birthplace \'%s\'" % (\n
                request_eform.getTitle(),\n
                request_eform.getOwnerBirthday(),\n
                request_eform.getOwnerBirthplace())\n
\n
else:\n
  # Modify person based on properties filled in P2\n
  person = person_list[0]\n
  person.edit(first_name=request_eform.getOwnerFirstName(),\n
              last_name=request_eform.getOwnerLastName(),\n
              start_date=request_eform.getOwnerBirthday(),\n
              default_birthplace_address_city=request_eform.getOwnerBirthplace(),\n
              default_address_street_address=request_eform.getOwnerAddress(),\n
              nationality=request_eform.getOwnerCitizenship())\n
  if request_eform.getOwnerMarriedCheck():\n
    person.edit(marital_status=\'married\')\n
  elif request_eform.getOwnerDivorcedCheck():\n
    person.edit(marital_status=\'divorced\')\n
  elif request_eform.getOwnerSingleCheck():\n
    person.edit(marital_status=\'single\')\n
  elif request_eform.getOwnerWidowerCheck():\n
    person.edit(marital_status=\'widowed\')\n
  # Modify also the person\'s organisation whether its activities are changed, or its\n
  #address, or its corporate name or whether the P2 form is used to create another\n
  #company for the person\n
  if request_eform.getCompanyModifications():\n
    corporate_registration_code = request_eform.getCompanyCorporateRegistrationCode()\n
    request_eform.edit(corporate_registration_code=corporate_registration_code)\n
    organisation_list = [organisation.getObject() for organisation in \\\n
        organisation_module.searchFolder(corporate_registration_code=request_eform.getCorporateRegistrationCode())]\n
    for organisation in organisation_list:\n
      activity_free_text = organisation.getActivityFreeText()\n
      activity_list = activity_free_text and activity_free_text.split(\',\') or []\n
      if request_eform.getTransferCheck():\n
        organisation.edit(default_address_street_address = request_eform.getCompanyAddress())\n
        organisation.getDefaultAddress().transfer()\n
\n
      elif request_eform.getActivityCheck():\n
        if request_eform.getCompanyModifiedRemovedActivities() != None:\n
          removed_activities_list = request_eform.getCompanyModifiedRemovedActivities().split(\',\')\n
          for removed_activities in removed_activities_list:\n
            if removed_activities in activity_list:\n
              activity_list.remove(removed_activities)\n
              organisation.edit(activity_free_text = \',\'.join(activity_list))\n
        if request_eform.getCompanyModifiedAddedActivities() != None:\n
          activity_list.append(request_eform.getCompanyModifiedAddedActivities())\n
          organisation.edit(activity_free_text = \',\'.join(activity_list))\n
\n
      elif request_eform.getCompanyModifiedName() != None:\n
        if request_eform.getCompanyOldName() == None:\n
          organisation_module = context.getPortalObject().organisation_module\n
          second_organisation = organisation_module.newContent(portal_type=\'Organisation\')\n
          second_organisation.edit(title=request_eform.getCompanyModifiedName(),\n
                                   corporate_name = request_eform.getCompanyModifiedName(),\n
                                   corporate_registration_code = new_registry_number,\n
                                   activity_free_text = request_eform.getCompanyModifiedAddedActivities(),\n
                                   role=\'commerce/siege\',)\n
          assignment = person.newContent(portal_type=\'Assignment\')\n
          assignment.edit(function = \'commerce/commercant\',\n
                     destination_form_value = request_eform,\n
                     destination_value = second_organisation)\n
          assignment.openSubmit()\n
          assignment.open()\n
        else:\n
          organisation.edit(title = request_eform.getCompanyModifiedName(),\n
                            corporate_name = request_eform.getCompanyModifiedName())\n
  #If the person has secondaries organisations,\n
  #modify the secondaries organisations for the person\n
  elif request_eform.getEstablishmentModification():\n
    corporate_registration_code = request_eform.getEstablishmentRegistrationCode()\n
    request_eform.edit(corporate_registration_code=corporate_registration_code)\n
    organisation_list = [organisation.getObject() for organisation in \\\n
        organisation_module.searchFolder(corporate_registration_code=request_eform.getCorporateRegistrationCode())]\n
    for organisation in organisation_list:\n
      if request_eform.getClosingCheck():\n
        organisation.getDefaultAddress().close()\n
      elif request_eform.getTransferCheck():\n
        organisation.edit(default_address_street_address = request_eform.getCompanyAddress())\n
        organisation.getDefaultAddress().transfer()\n
      elif request_eform.getBuyersName() != None:\n
        organisation.getDefaultAddress().sell()\n
      else:\n
        organisation.edit(activity_free_text = request_eform.getModifiedAddedActivities())\n
        organisation.getDefaultAddress().modify()\n
\n
\n
# Update the request_eform with the allocated number\n
request_eform.edit(registration_number = new_registry_number)\n
# Update the registration date of the request_eform with the time when the registry officer\n
#validates the transition\n
history_list = context.portal_workflow.getInfoFor(request_eform,\n
                                                  \'history\',\n
                                                  wf_id=\'egov_form_validation_workflow\')\n
for history in history_list:\n
  if history[\'action\'] == \'validate_action\':\n
    request_eform.edit(registration_date=history[\'time\'])\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>state_change</string> </value>
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
            <value> <string>modifyPhysicalPersonFromP2</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
