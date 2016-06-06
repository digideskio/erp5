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
            <value> <string>portal = context.getPortalObject()\n
N_ = portal.Base_translateString\n
\n
# If we create one portal type per attachment... no need\n
# but if attachment can be text, image, etc. We can not\n
# A simple solution: use title to group\n
type_list = map(lambda x: x.getId(), context.allowedContentTypes())\n
\n
file_type_list = (\'Image\', \'File\')\n
sub_form_type_list = filter(lambda x: x not in file_type_list, type_list)\n
\n
# A simple solution: use title to group\n
viewable_content_list = context.contentValues(portal_type=type_list, checked_permission=\'View\',validation_state = \'embedded\')\n
\n
content_group_dict = {}\n
for content in viewable_content_list:\n
  if content.getValidationState() in [\'embedded\',\'draft\']:\n
    title = content.getTitle()\n
    content_group_dict.setdefault(title, [])\n
    content_group_dict[title].append(content)\n
\n
# Now sort every group by creation date (to be done)\n
# XXXX\n
\n
\n
# Define some hard coded values\n
\n
attachement_method = getattr(context, \'PDFDocument_getApplicationIncomeDict\')\n
attachement_type_dict = attachement_method()\n
\n
# add other group title\n
for group_title in attachement_type_dict.keys():\n
  content_group_dict.setdefault(group_title,[])\n
\n
# Now create a sorted list of titles of attachments\n
title_list = content_group_dict.keys()\n
title_list.sort()\n
\n
# Now build the report sections\n
from Products.ERP5Form.Report import ReportSection\n
result = []\n
for title in title_list:\n
  if attachement_type_dict.has_key(title):\n
    description = attachement_type_dict[title].get(\'description\', \'No description\')\n
    requirement = attachement_type_dict[title].get(\'requirement\', \'No requirement\')\n
  else:\n
    description = \'No description\'\n
    requirement = \'Requirement not found\'\n
\n
  selection_params={\'title\': title,\n
                    \'description\': N_(description),\n
                    \'attachment_list\' : content_group_dict[title]}\n
\n
  # XXX display requirement word only on required attachments\n
  if requirement == \'Required\':\n
    selection_params.update({\'requirement\': N_(requirement)})\n
  else:\n
    selection_params.update({\'requirement\': \'\'})\n
  \n
\n
  result.append(\n
    ReportSection(\n
      path=context.getPhysicalPath(),\n
#      title=title,\n
      level=1,\n
      form_id=\'PDFDocument_viewAttachmentReportSection\',\n
      selection_name=\'attachment_selection\',\n
      selection_params=selection_params,\n
      listbox_display_mode=\'FlatListMode\')\n
  )\n
\n
\n
return result\n
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
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>PDFDocument_getReportSectionList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
