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
            <value> <string># this script allow to assign attachments to a form\n
portal = context.getPortalObject()\n
current_object = context.getObject()\n
m0_module = context.getPortalObject().m0_module\n
report_number = current_object.getReportNumber()\n
form_list = [x.getObject() for x in portal.portal_catalog(portal_type=[\'M0\',\'M2\',\'M4\',\'P0\',\'P2\',\'P4\'],\n
                      source_reference=report_number)]\n
\n
for form in form_list:\n
  if form.getPortalType()==\'P0\' or form.getPortalType()==\'P2\' or form.getPortalType()==\'P4\':\n
    form.setTitle(form.getFirstName() +\' \' +form.getLastName())\n
    form.edit(follow_up_value=current_object)\n
  elif form.getPortalType()==\'P2\' or form.getPortalType()==\'P4\':\n
    form.setTitle(form.getOwnerFirstName() +\' \' +form.getOwnerLastName())\n
    form.edit(follow_up_value=current_object)\n
  else:\n
    form.edit(follow_up_value=current_object)\n
  group_list = current_object.getGroupList()\n
  function_list = current_object.getFunctionList()\n
  site_list = current_object.getSiteList()\n
  classification = current_object.getClassification()\n
  publication_section_list = current_object.getPublicationSectionList()\n
  owner = current_object.getSourceValue()\n
\n
# Build metadata dict\n
  metadata = {}\n
  if group_list: metadata[\'group_list\'] = group_list\n
  if function_list: metadata[\'function_list\'] = function_list\n
  if site_list: metadata[\'site_list\'] = site_list \n
  if classification: metadata[\'classification\'] = classification \n
  if publication_section_list: metadata[\'publication_section_list\'] = publication_section_list\n
\n
# Ingest attachments\n
  for attachment_item in current_object.getAttachmentInformationList():\n
  # We do not care about files without name\n
    file_name = attachment_item.get(\'file_name\')\n
  # We do not take into account the message itself\n
  # XXX - this implementation is not acceptable in\n
  # the long term. Better approach to defining the\n
  # body of a message is required\n
    if file_name and not file_name.startswith(\'part\'):\n
      index = attachment_item[\'index\']\n
      data = current_object.getAttachmentData(index)\n
      if attachment_item[\'file_name\'].endswith(\'pdf\'):\n
        portal_type = \'PDF\'\n
      elif attachment_item[\'file_name\'].endswith(\'jpg\'):\n
        portal_type = \'Image\'\n
      else:\n
        portal_type = \'File\'\n
    # XXX - too bad we are not using content_type here\n
      d = form.newContent(data=data, source_reference=file_name,portal_type=portal_type)\n
      current_object.setAggregateList(context.getAggregateList() + [d.getRelativeUrl()])\n
  current_object.edit(follow_up_value= form)\n
if form_list:\n
  current_object.assignToForm()\n
return current_object.EmailDocument_viewAttachmentListRenderer()\n
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
            <value> <string>Event_assignToForm</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
