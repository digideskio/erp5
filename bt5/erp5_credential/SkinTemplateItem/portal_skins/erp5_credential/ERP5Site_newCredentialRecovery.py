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
  This script is used to create the new credential recovery\n
  Proxy : Manager proxy role is required to make possible for\n
anonymous to create a new Credential Recovery\n
"""\n
\n
def createCredentialRecovery(**kw):\n
  module = portal.getDefaultModule(portal_type=\'Credential Recovery\')\n
  credential_recovery = module.newContent(\n
                portal_type="Credential Recovery",\n
                **kw)\n
  credential_recovery.submit()\n
\n
portal = context.getPortalObject()\n
portal_preferences = portal.portal_preferences\n
keep_items = {}\n
web_site = context.getWebSiteValue()\n
document_reference = None\n
if default_email_text is not None:\n
  # Case for recovery of username\n
  if person_list is None:\n
    query_kw = {\'email.url_string\':{\'query\':default_email_text, \'key\':\'ExactMatch\'}}\n
    result = portal.portal_catalog(portal_type="Email", parent_portal_type="Person", **query_kw)\n
    if len(result) == 0:\n
      portal_status_message = portal.Base_translateString("Can\'t find corresponding person, it\'s not possible to update your credentials.")\n
      if web_site is not None:\n
        return web_site.Base_redirect(\'login_form\', keep_items = dict(portal_status_message=portal_status_message ))\n
      return portal.Base_redirect(\'login_form\', keep_items = dict(portal_status_message=portal_status_message ))\n
\n
    person_list = [x.getObject().getParentValue() for x in result]\n
\n
  # Create recovery\n
  message = "We have sent you an email containing your username(s). Please check your inbox and your junk/spam mail for this email."\n
  if web_site:\n
    document_reference = web_site.getCredentialUsernameRecoveryMessageReference()  \n
  createCredentialRecovery(default_email_text=default_email_text,\n
                           destination_decision_value_list=person_list,\n
                           document_reference=document_reference,\n
                           language=portal.Localizer.get_selected_language())\n
else:\n
  # Case for recovery of password\n
  if person_list is None:\n
    person_module = portal.getDefaultModule(\'Person\')\n
    result = person_module.searchFolder(reference={\'query\':reference, \'key\':\'ExactMatch\'})\n
    if len(result) != 1:\n
      portal_status_message = portal.Base_translateString("Can\'t find corresponding person, it\'s not possible to recover your credentials.")\n
      if web_site is not None:\n
        return web_site.Base_redirect(\'\', keep_items = dict(portal_status_message=portal_status_message ))\n
      return portal.Base_redirect(\'\', keep_items = dict(portal_status_message=portal_status_message ))\n
\n
    person_list = [result[0].getObject(),]\n
\n
  # Check the response\n
  person = person_list[0]\n
  question_free_text = person.getDefaultCredentialQuestionQuestionFreeText()\n
  question_title = person.getDefaultCredentialQuestionQuestionTitle()\n
  question_answer = person.getDefaultCredentialQuestionAnswer()\n
  question_answer = question_answer and question_answer.lower()\n
  answer = default_credential_question_answer and default_credential_question_answer.lower() or \'\'\n
  message = "We have sent you an email to enable you to reset your password. Please check your inbox and your junk/spam mail for this email and follow the link to reset your password."\n
  if web_site:\n
    document_reference = web_site.getCredentialPasswordRecoveryMessageReference()\n
\n
  if (question_title or question_free_text) and (answer == question_answer):\n
    createCredentialRecovery(reference=reference,\n
                  default_credential_question_answer=default_credential_question_answer,\n
                  destination_decision_value_list=person_list,\n
                  document_reference=document_reference,\n
                  language=portal.Localizer.get_selected_language())\n
  elif (question_free_text is None and question_answer is None) or \\\n
    not portal_preferences.isPreferredAskCredentialQuestion():\n
    createCredentialRecovery(reference=reference,\n
                  destination_decision_value_list=person_list,\n
                  document_reference=document_reference,\n
                  language=portal.Localizer.get_selected_language())\n
  else:\n
    message = "You didn\'t enter the correct answer."\n
    keep_items = {\'default_credential_question_question_free_text\': question_free_text,\n
                  \'default_credential_question_question_title\': question_title,\n
                  \'reference\': reference}\n
\n
keep_items[\'portal_status_message\'] = portal.Base_translateString(message)\n
if web_site is not None:\n
  return web_site.Base_redirect(form_id=\'login_form\', keep_items=keep_items)\n
return portal.Base_redirect(form_id=\'login_form\', keep_items=keep_items)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>reference=None, default_email_text=None, person_list=None, default_credential_question_answer=None, dialog_id=None, **kw</string> </value>
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
            <value> <string>ERP5Site_newCredentialRecovery</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
