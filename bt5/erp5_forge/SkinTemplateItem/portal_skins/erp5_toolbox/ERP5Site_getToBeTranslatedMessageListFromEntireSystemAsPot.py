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
            <value> <string>from Products.ERP5Type.Utils import getMessageIdWithContext\n
message_dict = {}\n
\n
def add_message(message, comment):\n
  \n
  if not message:\n
    return\n
  message = message.decode(\'utf-8\')\n
  if message in message_dict:\n
    comment_list = message_dict[message]\n
  else:\n
    comment_list = message_dict[message] = []\n
  if comment not in comment_list:\n
    comment_list.append(comment)\n
\n
\n
\n
portal_url = context.portal_url\n
\n
# Collect skin objects\n
python_script_list = []\n
form_list = []\n
listbox_list = []\n
page_template_list = []\n
def iterate(obj):\n
  for i in obj.objectValues():\n
    if i.meta_type==\'Script (Python)\':\n
      python_script_list.append(i)\n
    elif i.meta_type==\'ERP5 Form\':\n
      form_list.append(i)\n
    elif i.meta_type==\'ListBox\' or i.id==\'listbox\':\n
      listbox_list.append(i)\n
    elif i.meta_type in (\'Page Template\',\n
                         \'ERP5 PDF Template\',\n
                         \'ERP5 OOo Template\'):\n
      page_template_list.append(i)\n
    if i.isPrincipiaFolderish:\n
      iterate(i)\n
iterate(context.portal_skins)\n
\n
# Collect python script from workflow objects.\n
for workflow in context.portal_workflow.objectValues():\n
  for i in workflow.scripts.objectValues():\n
    if i.meta_type==\'Script (Python)\':\n
      python_script_list.append(i)\n
\n
#\n
# Python Script\n
#\n
FUNC_NAME_LIST = (\'N_\',\n
                  \'Base_translateString\',\n
                  \'translateString\',\n
                  )\n
\n
Base_getFunctionFirstArgumentValue = context.Base_getFunctionFirstArgumentValue\n
for i in python_script_list:\n
  source = i.body()\n
  for func_name in FUNC_NAME_LIST:\n
    call_func_name = \'%s(\' % func_name\n
    if call_func_name in source:\n
      for m in Base_getFunctionFirstArgumentValue(func_name, source):\n
        add_message(m, portal_url.getRelativeContentURL(i))\n
\n
#\n
# Python in Products\n
#\n
for message, path in context.Base_findMessageListFromPythonInProduct(FUNC_NAME_LIST):\n
  add_message(message, path)\n
\n
#\n
# ERP5 Form title, Field title and editable Field description\n
#\n
for i in form_list:\n
  if (i.getId().endswith(\'FieldLibrary\')):\n
    continue\n
  add_message(i.title, portal_url.getRelativeContentURL(i))\n
  for group, list in i.groups.items():\n
    if group == \'hidden\':\n
      continue\n
    for j in (i[x] for x in list):\n
      add_message(j.get_value(\'title\'), portal_url.getRelativeContentURL(j))\n
      if j.get_value(\'editable\'):\n
        add_message(j.get_value(\'description\'), portal_url.getRelativeContentURL(j))\n
\n
#\n
# ListBox title, columns\n
#\n
for i in listbox_list:\n
  if i.get_tales(\'title\')==\'\':\n
    add_message(i.title(), portal_url.getRelativeContentURL(i))\n
  for value, label in i.get_value(\'columns\') or ():\n
    add_message(label, portal_url.getRelativeContentURL(i))\n
  for value, label in i.get_value(\'all_columns\') or ():\n
    add_message(label, portal_url.getRelativeContentURL(i))\n
\n
#\n
# Page Template\n
#\n
Base_findStaticTranslationText = context.Base_findStaticTranslationText\n
for i in page_template_list:\n
  for m in Base_findStaticTranslationText(i, FUNC_NAME_LIST):\n
    add_message(m, portal_url.getRelativeContentURL(i))\n
\n
#\n
# Workflow\n
#\n
s_title_list = []\n
for i in context.portal_workflow.objectValues():\n
  add_message(i.title_or_id(), portal_url.getRelativeContentURL(i))\n
  \n
  if not i.states:\n
    continue\n
  for s in i.states.values():\n
     s_title = s.title\n
     if s_title:\n
       # adding a context in msg_id for more precise translation\n
       msg_id = getMessageIdWithContext(s_title,\'state\',i.id)      \n
       add_message(msg_id, portal_url.getRelativeContentURL(s))\n
       # also use state title as msg_id for compatibility\n
       add_message(s_title, portal_url.getRelativeContentURL(s))\n
  \n
  if not i.transitions:\n
    continue\n
  for t in i.transitions.values():\n
    if t.actbox_name:\n
      #adding a context in msg_id for more precise translation\n
      msg_id = getMessageIdWithContext(t.actbox_name,\'transition\',i.id)\n
      add_message(msg_id, portal_url.getRelativeContentURL(t))\n
      # also use action box name as msg_id for compatibility\n
      add_message(t.actbox_name, portal_url.getRelativeContentURL(t))\n
    if t.title:\n
      #adding a context in msg_id for more precise translation\n
      msg_id = getMessageIdWithContext(t.title,\'transition\',i.id)\n
      add_message(msg_id, portal_url.getRelativeContentURL(t))\n
      # also use transition title as msg_id for compatibility\n
      add_message(t.title, portal_url.getRelativeContentURL(t))\n
  for worklist in i.worklists.objectValues():\n
    add_message(worklist.actbox_name, portal_url.getRelativeContentURL(worklist))\n
\n
\n
#\n
# Portal Type\n
#\n
for i in context.portal_types.objectValues():\n
  add_message(i.id, \'portal type\')\n
\n
\n
#\n
# Action\n
#\n
for action_title, action_provider_id in context.Base_getActionTitleListFromAllActionProvider(context.getPortalObject()):\n
  add_message(action_title, action_provider_id)\n
\n
#\n
# ZODB Property Sheet\n
#\n
for property_sheet in context.portal_property_sheets.objectValues():\n
  for property_ in property_sheet.objectValues():\n
    if property_.getId().endswith(\'constraint\'):\n
      for key, value in property_.showDict().items():\n
        if key.startswith(\'message_\'):\n
          add_message(value, portal_url.getRelativeContentURL(property_))\n
\n
#\n
# Output\n
#\n
def format(string):\n
  line_list = string.split(\'\\n\')\n
  length = len(line_list)\n
  if length==1:\n
    return \'"%s"\' % string.replace(\'"\', \'\\\\"\')\n
  else:\n
    return \'\\n\'.join([\'""\']+[format(i) for i in line_list])\n
\n
print \'\'\'msgid ""\n
msgstr "Content-Type: text/plain; charset=UTF-8"\n
\n
\'\'\'\n
\n
MESSAGE_TEMPLATE = \'\'\'\\\n
%s\n
msgid %s\n
msgstr ""\n
\'\'\'\n
message_list = message_dict.keys()\n
message_list.sort()\n
for message in message_list:\n
  comment_list = message_dict[message]\n
  comment_list.sort()\n
  comment = \'\\n\'.join([(\'#: %s\' % i) for i in comment_list])\n
  print MESSAGE_TEMPLATE % (comment, format(message))\n
\n
RESPONSE = context.REQUEST.RESPONSE\n
RESPONSE.setHeader(\'Content-disposition\', \'attachment;filename=translation.pot\')\n
RESPONSE.setHeader(\'Content-Type\', \'text/x-gettext-translation-template;charset=utf-8\')\n
\n
return printed\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Site_getToBeTranslatedMessageListFromEntireSystemAsPot</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
