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
            <key> <string>_Cacheable__manager_id</string> </key>
            <value> <string>my_test</string> </value>
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
  This script creates assignments based on the fast input information.\n
  It should take into account any assignment which were already created\n
  so that they are not duplicated.\n
"""\n
portal = context.getPortalObject()\n
person_module = context.getPortalObject().person_module\n
items = []\n
for line in listbox:\n
  if line.has_key(\'listbox_key\') and line[\'last_name\'] not in (\'\', None):\n
    line_id = int(line[\'listbox_key\'])\n
    item = {}\n
    item[\'id\'] = line_id\n
   # item[\'title\']= line[\'title\']\n
    item[\'first_name\'] = line[\'first_name\']\n
    item[\'last_name\'] = line[\'last_name\']\n
    item[\'start_date\'] = line[\'start_date\']\n
    item[\'default_birthplace_address_city\'] = line[\'default_birthplace_address_city\']\n
    item[\'function\'] = line[\'function\']\n
    item[\'choice\'] = line[\'choice\']\n
    item[\'status\'] = line[\'status\']\n
    item[\'old_function\'] = line[\'old_function\']\n
    items.append(item)\n
items.sort(lambda x, y: cmp(x[\'id\'], y[\'id\']))\n
context_obj = context.getObject()\n
if context_obj.getPortalType()==\'M2 Bis\':\n
   context_obj= context_obj.getParentValue()\n
   form_id = \'M2Bis_view\'\n
\n
# create corresponding assignment\n
for item in items:\n
  portal = context.getPortalObject()\n
  new_items=[]\n
#if the person in the fast input is a new person, create assignment\n
  if item[\'status\'] == \'_new_action\' :\n
    if item[\'choice\'] == \'_action_create\':\n
      person_module = context.getPortalObject().person_module\n
      person_title = item[\'first_name\'] + \' \' + item[\'last_name\']\n
      person_third_party = person_module.newContent(portal_type=\'Person\',\n
                                                   title=person_title,\n
                                                   first_name=item[\'first_name\'],\n
                                                   last_name =item[\'last_name\'],\n
                                                   start_date=item[\'start_date\'],\n
             default_birthplace_address_city=item[\'default_birthplace_address_city\'],)\n
      person_third_party_assignment = \\\n
             person_third_party.newContent(portal_type=\'Assignment\',\n
                                          function=item[\'function\'],\n
                                          destination_form_value=context_obj) \n
      person_third_party_assignment.openSubmit()\n
    else:\n
      person = portal.restrictedTraverse(item[\'choice\'])\n
      assignment = person.newContent(portal_type=\'Assignment\',\n
                                     function=item[\'function\'],\n
                                     destination_form_value=context_obj)\n
      assignment.openSubmit()\n
  elif item[\'status\'] == \'_action_maintain\':\n
    pass\n
  elif item[\'status\'] == \'_action_modify\':\n
    person = portal.restrictedTraverse(item[\'choice\'])\n
    corporate_registration_code = context_obj.getCorporateRegistrationCode()\n
    organisation_list = [organisation.getObject() for organisation in portal.portal_catalog(parent_uid=portal.organisation_module.getUid(), \n
                         corporate_registration_code=corporate_registration_code)]\n
    #function_relative_url = \'/\'.join((\'function\', item[\'old_function\']))\n
    for organisation in organisation_list:\n
      # XXX for assignment in assignment_list:\n
      for assignment in person.contentValues(portal_type=\'Assignment\',\n
                                              checked_permission=\'View\'):\n
        if assignment.getValidationState() ==\'open\' and \\\n
            assignment.getFunction() == item[\'old_function\'] and \\\n
            organisation in assignment.getDestinationValueList():\n
          assignment.edit(function=item[\'function\'],\n
                          destination_value=organisation,)\n
  elif item[\'status\']==\'_go_action\':\n
    person = portal.restrictedTraverse(item[\'choice\'])\n
    corporate_registration_code = context_obj.getCorporateRegistrationCode()\n
    organisation_list = [organisation.getObject() for organisation in portal.portal_catalog(parent_uid=portal.organisation_module.getUid(), \n
                         corporate_registration_code=corporate_registration_code)]\n
    for organisation in organisation_list:\n
      for assignment in person.contentValues(portal_type=\'Assignment\',\n
                                               checked_permission=\'View\'):\n
        if assignment.getValidationState() ==\'open\' and \\\n
              assignment.getFunction() == item[\'old_function\'] and \\\n
              organisation in assignment.getDestinationValueList():\n
          assignment.edit(destination_form_value=context_obj)\n
          assignment.cancel()\n
\n
role_type = \'Assignment\' \n
if context_obj.getPortalType()==\'M2\':\n
 form_id = \'M2_view\'\n
elif context_obj.getPortalType()==\'P2\':\n
 form_id = \'P2_view\'\n
ignore_layout = 0\n
editable_mode = 1\n
ignore_layout = int(ignore_layout)\n
editable_mode = int(editable_mode)\n
message = role_type.replace(\' \', \'+\') + \'(s)+added.\'\n
redirect_url = \'%s/%s?ignore_layout:int=%s&editable_mode:int=%s&portal_status_message=%s\' % (\n
                                  context.absolute_url(),\n
                                  form_id,\n
                                  ignore_layout,\n
                                  editable_mode,\n
                                  message)\n
# return to the feature module\n
return context.REQUEST.RESPONSE.redirect(redirect_url)\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>listbox=[], **kw</string> </value>
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
            <value> <string>M2_setAssignmentList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
