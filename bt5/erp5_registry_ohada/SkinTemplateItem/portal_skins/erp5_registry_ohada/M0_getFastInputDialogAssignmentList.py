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
            <value> <string>"""\n
  This script creates a list Person objects based\n
  on the M0 form information. It updates the list of persons\n
  based on fast input entries.\n
"""\n
from string import zfill\n
global result_list\n
global uid\n
uid = 0\n
result_list = []\n
request = context.REQUEST\n
listbox = getattr(request, \'listbox\', None) # Retrieve the fast input data if any\n
\n
\n
def addPerson(first_name=None, last_name=None,\n
              start_date=None, default_birthplace_address_city=\'\',\n
              default_address_text=\'\', description=None, \n
              function=None, **kw):\n
  """\n
   This creates a single temporary person with all appropriate parameters\n
  """\n
  # don\'t add person if there is no first_name\n
  if not first_name:\n
    return\n
\n
  global result_list\n
  global uid\n
  if not (first_name or last_name):\n
    return\n
  uid_string = \'new_%s\' % zfill(uid, 3)\n
  if listbox is not None:\n
    # Use input parameters instead of default\n
    # if available in listbox\n
    line = listbox[zfill(uid, 3)]\n
    if line.has_key(\'last_name\') and line.has_key(\'first_name\') :\n
      first_name = line[\'first_name\']\n
      last_name = line[\'last_name\']\n
\n
  person = context.getPortalObject().person_module.newContent(\n
    portal_type=\'Person\',\n
    uid=uid_string,\n
    first_name=first_name,\n
    last_name=last_name,\n
    start_date=start_date,\n
    default_birthplace_address_city=default_birthplace_address_city,\n
    default_address_text=default_address_text,\n
    function=function,\n
    description=description,\n
    temp_object=1,\n
    is_indexable=0,\n
  )\n
  result_list.append(person)\n
  uid += 1\n
\n
\n
\n
#Create Shareholders\n
addPerson(first_name=context.getFirstAssociateFirstname(),\n
          last_name=context.getFirstAssociateLastname(),\n
          start_date=context.getFirstAssociateBirthday(),\n
          default_address_text=context.getFirstAssociateAddress(),\n
          default_birthplace_address_city=context.getFirstAssociateBirthplace(),)\n
\n
addPerson(first_name=context.getSecondAssociateFirstname(),\n
          last_name=context.getSecondAssociateLastname(),\n
          start_date=context.getSecondAssociateBirthday(),\n
          default_address_text=context.getSecondAssociateAddress(),\n
          default_birthplace_address_city=context.getSecondAssociateBirthplace(),)\n
\n
addPerson(first_name=context.getThirdAssociateFirstname(),\n
          last_name=context.getThirdAssociateLastname(),\n
          start_date=context.getThirdAssociateBirthday(),\n
          default_address_text=context.getThirdAssociateAddress(),\n
          default_birthplace_address_city=context.getThirdAssociateBirthplace(),)\n
\n
# only if there is M0 bis form :\n
m0_bis_result = context.contentValues(portal_type=\'M0 Bis\')\n
number_list = (\'Fourth\', \'Fifth\', \'Sixth\', \'Seventh\',\n
    \'Eighth\', \'Ninth\', \'Tenth\', \'Eleventh\', \'Twelfth\',\n
    \'Thirteenth\', \'Fourteenth\', \'Fifteenth\', \'Sixteenth\',\n
    \'Seventeenth\')\n
\n
if len(m0_bis_result):\n
  for m0 in m0_bis_result:\n
    for number in number_list:\n
      associateFirstName = getattr(m0, \'get%sAssociateFirstname\' % number, None)\n
      associateLastName = getattr(m0, \'get%sAssociateLastname\' % number, None)\n
      associateBirthday = getattr(m0, \'get%sAssociateBirthday\' % number, None)\n
      associateBirthPlace = getattr(m0, \'get%sAssociateBirthplace\' % number, None)\n
      associateAnotherInfo = getattr(m0, \'get%sAssociateAnotherInfo\' % number, None)\n
\n
      addPerson(first_name=associateFirstName(),\n
                last_name=associateLastName(),\n
                start_date=associateBirthday(),\n
                default_birthplace_address_city=associateBirthPlace(),\n
                description=associateAnotherInfo(),)\n
\n
\n
\n
\n
#Create Managers\n
addPerson(first_name=context.getFirstAdministratorFirstname(),\n
          last_name=context.getFirstAdministratorLastname(),\n
          start_date=context.getFirstAdministratorBirthday(),\n
          default_birthplace_address_city=context.getFirstAdministratorBirthplace(),\n
          default_address_text=context.getFirstAdministratorAddress(),\n
          function=context.getFirstAdministratorFunction(),)\n
\n
addPerson(first_name=context.getSecondAdministratorFirstname(),\n
          last_name=context.getSecondAdministratorLastname(),\n
          start_date=context.getSecondAdministratorBirthday(),\n
          default_birthplace_address_city=context.getSecondAdministratorBirthplace(),\n
          default_address_text=context.getSecondAdministratorAddress(),\n
          function=context.getSecondAdministratorFunction(),)\n
\n
# only if there is M0 bis form :\n
number_list = (\'Third\', \'Fourth\', \'Fifth\', \'Sixth\', \'Seventh\',\n
    \'Eighth\', \'Ninth\', \'Tenth\', \'Eleventh\', \'Twelfth\',\n
    \'Thirteenth\', \'Fourteenth\', \'Fifteenth\', \'Sixteenth\')\n
\n
if len(m0_bis_result):\n
  for m0 in m0_bis_result:\n
    for number in number_list:\n
      administratorFirstName = getattr(m0, \'get%sAdministratorFirstname\' % number, None)\n
      administratorLastName = getattr(m0, \'get%sAdministratorLastname\' % number, None)\n
      administratorBirthday = getattr(m0, \'get%sAdministratorBirthday\' % number, None)\n
      administratorBirthPlace = getattr(m0, \'get%sAdministratorBirthplace\' % number, None)\n
      administratorAnotherInfo = getattr(m0, \'get%sAdministratorAnotherInfo\' % number, None)\n
\n
      addPerson(first_name=administratorFirstName(),\n
                last_name=administratorLastName(),\n
                start_date=administratorBirthday(),\n
                default_birthplace_address_city=administratorBirthPlace(),\n
                description=administratorAnotherInfo(),)\n
\n
\n
#Create Auditors\n
addPerson(first_name=context.getFirstAuditorFirstname(),\n
          last_name=context.getFirstAuditorLastname(),\n
          start_date=context.getFirstAuditorBirthday(),\n
          default_birthplace_address_city=context.getFirstAuditorBirthplace(),\n
          default_address_text=context.getFirstAuditorAddress(),)\n
\n
addPerson(first_name=context.getSecondAuditorFirstname(),\n
          last_name=context.getSecondAuditorLastname(),\n
          start_date=context.getSecondAuditorBirthday(),\n
          default_birthplace_address_city=context.getSecondAuditorBirthplace(),\n
          default_address_text=context.getSecondAuditorAddress(),)\n
\n
return result_list\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>lines_num=8, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>M0_getFastInputDialogAssignmentList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
