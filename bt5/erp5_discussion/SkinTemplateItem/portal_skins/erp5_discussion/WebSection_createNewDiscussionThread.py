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
 This script allows to create a new Discussion Thread.\n
"""\n
from zExceptions import Unauthorized\n
\n
MARKER = [\'\', None, []]\n
\n
portal = context.getPortalObject()\n
person = portal.ERP5Site_getAuthenticatedMemberPersonValue()\n
\n
version = \'001\'\n
language = portal.Localizer.get_selected_language()\n
has_website = context.getWebSiteValue() is not None\n
\n
try:\n
  user_assignment_dict = portal.ERP5Site_getPersonAssignmentDict()\n
except Unauthorized:\n
  # not in all cases current logged in user may access its details\n
  user_assignment_dict = {\'group_list\': [], \'site_list\':[]}\n
\n
if group_list in MARKER:\n
  group_list = user_assignment_dict[\'group_list\']\n
if site_list in MARKER:\n
  site_list = user_assignment_dict[\'site_list\']\n
\n
# set predicate settings for current Web Section\n
if has_website:\n
  membership_criterion_category_list = context.getMembershipCriterionCategoryList()\n
  multimembership_criterion_base_category_list = context.getMultimembershipCriterionBaseCategoryList()\n
\n
reference = context.Base_generateReferenceFromString(title)\n
\n
if has_website:\n
  existing_document = context.getDocumentValue(reference)\n
  existing_web_section_list = portal.portal_catalog(id=reference, portal_type=[\'Web Site\', \'Web Section\'])\n
  existing_module_list = portal.portal_catalog(id=reference, parent_uid=portal.getUid())\n
  if existing_document is not None \\\n
    or len(existing_web_section_list) \\\n
    or len(existing_module_list):\n
    # if there are other document or any tarversal objects (module, web section)\n
    # which ID or reference duplicates just add some random part\n
    # so we can distinguish)\n
    reference = \'%s-%s\' %(context.Base_generateRandomString(), reference)\n
\n
category_list = []\n
create_kw = dict(title = title,\n
                 source_value = person,\n
                 reference = reference,\n
                 version = version,\n
                 language = language,\n
                 description=description,\n
                 subject_list=subject_list,\n
                 classification=classification,\n
                 group_list=group_list,\n
                 site_list=site_list)\n
\n
if has_website:\n
  for base_category in multimembership_criterion_base_category_list:\n
    #create_kw[\'%s_list\' %base_category] = [x for x in membership_criterion_category_list if x.startswith(base_category)]\n
    category_list.extend([x for x in membership_criterion_category_list if x.startswith(base_category)])\n
\n
discussion_thread = portal.discussion_thread_module.newContent(\n
                      portal_type = "Discussion Thread",\n
                      **create_kw)\n
# as we create a thread under a "root" predicate web section copy\n
# all categories from it to create thread, this way thread will be part\n
# of web section (through getDocumentValue API)\n
discussion_thread.setCategoryList(category_list)\n
\n
# predecessor\n
if predecessor is None:\n
  redirect_url = context.getAbsoluteUrl()\n
else:\n
  predecessor_object = context.restrictedTraverse(predecessor)\n
  predecessor_portal_type = predecessor_object.getPortalType()\n
  redirect_url = predecessor_object.getAbsoluteUrl()\n
\n
  # predecessor will only be set on document = web section default page\n
  if predecessor_portal_type == \'Web Section\':\n
    predecessor_default_page = predecessor_object.getAggregate()\n
    if predecessor_default_page is not None:\n
      predecessor_document = context.restrictedTraverse(predecessor_default_page)\n
      discussion_thread.setPredecessorValueList([predecessor_document])\n
  \n
  # set predecessor on document\n
  if predecessor_portal_type == \'Web Page\':\n
    discussion_thread.setPredecessorValueList([predecessor_object])\n
\n
discussion_post = discussion_thread.newContent(\n
                      portal_type = "Discussion Post",\n
                      title = title,\n
                      text_content = text_content,\n
                      source_value = person,\n
                      version = version,\n
                      language = language)\n
\n
# depending on security model Thread and Post can be directly published or shared\n
portal_status_message = "New discussion thread created."\n
discussion_thread.publish()\n
\n
# handle attachments\n
if getattr(file, \'filename\', \'\') != \'\':\n
  document_kw = {\'batch_mode\': True,\n
                 \'redirect_to_document\': False,\n
                 \'file\': file}\n
  document = context.Base_contribute(**document_kw)\n
\n
  # set relation between post and document\n
  discussion_post.setSuccessorValueList([document])\n
\n
  # depending on security model this should be changed accordingly\n
  document.publish()\n
\n
if send_notification_text not in (\'\', None):\n
  # we can send notifications\n
  person_list = []\n
  notification_list = send_notification_text.split(\'\\n\')\n
  for notification in notification_list:\n
    # we can assume user wanted to specify Person\'s title\n
    person_list.extend(portal.portal_catalog(portal_type=\'Person\',\n
                                             title=notification,\n
                                             default_email_text=\'!=\'))\n
  if len(person_list):\n
    #Get message from catalog\n
    notification_reference = \'forum-new-thread\'\n
    notification_message = context.NotificationTool_getDocumentValue(notification_reference, \'en\')\n
    if notification_message is None:\n
      raise ValueError, \'Unable to found Notification Message with reference "%s".\' % notification_reference\n
\n
    notification_mapping_dict = {\'subject\': discussion_thread.getTitle(),\n
                                 \'url\': discussion_thread.absolute_url(),\n
                                 \'sender\': portal.email_from_name }\n
    #Preserve HTML else convert to text\n
    if notification_message.getContentType() == "text/html":\n
      mail_text = notification_message.asEntireHTML(\n
        substitution_method_parameter_dict={\'mapping_dict\':notification_mapping_dict})\n
    else:\n
      mail_text = notification_message.asText(\n
        substitution_method_parameter_dict={\'mapping_dict\':notification_mapping_dict})\n
    sender = portal.ERP5Site_getAuthenticatedMemberPersonValue()\n
    #Send email\n
    for recipient in person_list:\n
      portal.portal_notifications.sendMessage(\n
        sender=sender,\n
        recipient=recipient,\n
        subject=notification_message.getTitle(),\n
        message=mail_text,\n
        message_text_format=notification_message.getContentType(),\n
        store_as_event=False)\n
\n
return context.Base_redirect(redirect_url=redirect_url,\n
         keep_items = dict(portal_status_message=context.Base_translateString(portal_status_message),\n
                           thread_relative_url=discussion_thread.getRelativeUrl()))\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>title, text_content, form_id=\'view\', predecessor=None, description=None, subject_list=None, classification=None, group_list=None, site_list=None, send_notification_text=None, reference=None, file=None, **kw</string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Assignor</string>
                <string>Manager</string>
                <string>Owner</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>WebSection_createNewDiscussionThread</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
