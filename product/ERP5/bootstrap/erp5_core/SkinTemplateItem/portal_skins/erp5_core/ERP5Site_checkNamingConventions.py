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

# This script checks for naming validity.\n
#\n
# NOTE: Do not rely on this script too much! After all, human must take care.\n
\n
# TODO:\n
# - Add more abbriviation words.\n
# - Check language dependencies (e.g. "Account Of" should not be allowed, because it cannot be\n
#   translated naturally for other languages).\n
# - Check skin names.\n
# - Check script names (from skin folders and workflows).\n
import re\n
ABBREVIATION_WORD_SET = ((\n
  "BBAN", "BIC", "BOM", "CAD", "CRM", "CSS", "CSV", "CTX", "DMS", "DNS",\n
  "EAN", "ERP5", "FAX", "GAP", "GID", "GPG", "HTML", "HTTP", "IBAN", "ID",\n
  "IMAP", "IP", "KM", "MIME", "MRP", "NVP", "ODT", "PDF", "PDM", "PO",\n
  "RAM", "RSS", "SMS", "SOAP", "SQL", "SVN", "TALES", "TCP", "TSV", "UBM",\n
  "UID", "UOM", "URI", "URL", "VADS", "VAT", "VCS", "VPN", "XML", "ZODB",\n
))\n
\n
# List of words that do not need to be titlecased\n
LOWERCASE_WORD_SET = set((\'g\', \'cm\', \'kg\', \'%\', \'/\', \'...\', \'m\', \'-\', \'g/m2\', \'iCalendar\', \'m&#179;\', \'kB\'))\n
\n
# List of words that should not be modified\n
SPECIALCASE_WORD_SET = set(("ChangeLog", "EGov", "iCal", "included",\n
  "JavaScript", "LibreOffice", "OAuth", "OpenAM", "OpenOffice", "SyncML",\n
  "TioSafe", "will"))\n
\n
CLOSED_CLASS_WORD_LIST = """\n
  a about above across after against all along alongside already although\n
  amid among amongst an and another any anybody anyone anything are around as\n
  at be because been before behind below beneath beside between beyond both but\n
  by concerning could despite did do does down during each either enough every\n
  everybody everyone everything except few fewer following for former from\n
  goodbye half has have he her hers herself him himself his if in including\n
  inside instead into is it its itself latter less like little lots many me\n
  mine minus more most much my myself near neither no nobody none nor not\n
  nothing now of off on once one only onto opposite or our ours ourselves out\n
  outside over own past per plenty plus rather regarding round same several she\n
  should since so some somebody someone something soon such than that the their\n
  theirs them themselves there these they this those though through throughout\n
  to too toward towards under underneath unless unlike until up upon us via we\n
  well what whatever when where whereas whether which while whilst who whoever\n
  whom whose with within without worth would yes you your yours yourself\n
  """.split()\n
CLOSED_CLASS_WORD_SET = set(CLOSED_CLASS_WORD_LIST)\n
assert len(CLOSED_CLASS_WORD_SET) == len(CLOSED_CLASS_WORD_LIST)\n
SENTENCE_PART_LIST = (\n
  "doesn\'t",\n
\n
  "according to", "ahead of", "apart from", "as long as", "as opposed to",\n
  "away from", "be triggered on", "by means of", "by way of", "contrary to", "depending on",\n
  "due to", "each other", "even if", "even though", "even when", "given that",\n
  "in accordance with", "in addition to", "in case", "in charge of",\n
  "in conjunction with", "in connection with", "in favour of", "in front of",\n
  "in line with", "in relation to", "in respect of", "in response to",\n
  "in search of", "in spite of", "in support of", "in terms of",\n
  "in the light of", "in touch with", "in view of", "let alone", "next to",\n
  "on behalf of", "on the part of", "on top of", "other than", "prior to",\n
  "provided that", "relative to", "so long as", "subject to", "with regard to",\n
  "with respect to",\n
)\n
SENTENCE_PART_SET = set(SENTENCE_PART_LIST)\n
assert len(SENTENCE_PART_SET) == len(SENTENCE_PART_LIST)\n
\n
# List of allowed characters, usefull to detect non-english strings\n
ALLOWED_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789%/. ()-_?&\'#,;")\n
\n
def checkField(folder, form, field):\n
  """\n
    Generic function that test the validity of ERP5Form fields.\n
  """\n
  path = folder.id + \'/\' + form.id\n
  error_message = checkTitle(path, field.id, field.title(), field)\n
  template_field = getFieldFromProxyField(field)\n
  if path.endswith("FieldLibrary"):\n
    if not(template_field is field):\n
      if not(1 in [field.id.startswith(x) for x in (\'my_view_mode_\',\n
                           \'my_core_mode_\', \'my_report_mode_\', \'my_list_mode_\', \'my_dialog_mode_\')]):\n
        error_message += "%s: %s : Bad ID for a Field Library Field" % (path, field.id)\n
  if template_field is None:\n
    if field.get_value(\'enabled\'):\n
      error_message += "Could not get a field from a proxy field %s" % field.id\n
  else:\n
    if isListBox(field):\n
      a = template_field.getListMethodName()\n
      path += \'/listbox\'\n
      for x in \'columns\', \'all_columns\':\n
        for id, title in field.get_value(x):\n
          error_message += checkTitle(path, x, title, field, form)\n
      if a not in (None, "portal_catalog", "searchFolder", "objectValues",\n
                   "contentValues", "ListBox_initializeFastInput"):\n
        if not a.endswith(\'List\'):\n
          if 0:\n
            error_message += "%s : %s : %r Bad Naming Convention\\n" % (path, id, a)\n
  return error_message\n
\n
def isListBox(field):\n
  template_field = getFieldFromProxyField(field)\n
  return template_field is not None and template_field.meta_type == \'ListBox\'\n
\n
def getFieldFromProxyField(field):\n
  if field.meta_type == \'ProxyField\':\n
    field = field.getRecursiveTemplateField()\n
  return field\n
\n
titlecase_sub = re.compile(r"[A-Za-z]+(\'[A-Za-z]+)?").sub\n
titlecase_repl = lambda mo: mo.group(0)[0].upper() + mo.group(0)[1:].lower()\n
titlecase = lambda s: titlecase_sub(titlecase_repl, s)\n
\n
def checkTitle(path, id, title, field=None, form=None):\n
  """\n
    Generic function that test the validity of a title.\n
  """\n
  error_message = \'\'\n
  if (form is not None and form.pt not in (\'form_dialog\', \'folder_workflow_action_dialog\')) or form is None:\n
    if (field is not None and not field.get_value(\'hidden\') and \\\n
     (title is None or len(title.strip()) == 0)) or (field is None and (title is None or len(title.strip()) == 0)):\n
      return "%s : %s : can\'t be empty\\n" % (path, id)\n
\n
  for c in title:\n
    if c.lower() not in ALLOWED_CHARS:\n
      return "%s : %s : %r character not allowed\\n" % (path, id, c)\n
\n
  title = re.sub(re.compile(r"\\b(" + "|".join(re.escape(x) for x in SENTENCE_PART_SET) + r")\\b"), "", title)\n
\n
  word_list = title.split(\' \')\n
  for word in word_list:\n
    word = word.strip(\'()\')\n
\n
    if word.isdigit():\n
      continue\n
\n
    if word.upper() in ABBREVIATION_WORD_SET:\n
      if not word.isupper():\n
        error_message += \'%s : %s : %r is not upper case even though it is an abbriviation\\n\' % (path, id, word)\n
    elif word.endswith(\'s\') and word[:-1].upper() in ABBREVIATION_WORD_SET:\n
      if not word[:-1].isupper():\n
        error_message += \'%s : %s : %r is not upper case even though it is an abbriviation\\n\' % (path, id, word)\n
    elif "-" in word and word.split("-")[0].upper() in ABBREVIATION_WORD_SET:\n
      if not word.split("-")[0].isupper():\n
        error_message += \'%s : %s : %r is not upper case even though it is an abbriviation\\n\' % (path, id, word)\n
    else:\n
      if word.lower() in CLOSED_CLASS_WORD_SET and word != word_list[0] :\n
        if (word.capitalize()== word or titlecase(word)== word):\n
          error_message += \'%s : %s : %r is a closed-class word and should not be titlecased\\n\' % (path, id, word)\n
      elif (word.capitalize()!= word and titlecase(word)!= word) and \\\n
         word not in LOWERCASE_WORD_SET and word not in SPECIALCASE_WORD_SET and word not in CLOSED_CLASS_WORD_SET :\n
          error_message += \'%s : %s : %r is not titlecased\\n\' % (path, id, word)\n
  if len(word_list) > 1 and word_list[-1].upper() == \'LIST\' and word_list[-2].upper() != \'PACKING\':\n
    error_message += \'%s : %s : %r is a jargon\\n\' % (path, id, title)\n
  return error_message\n
\n
\n
\n
message_list = []\n
\n
\n
# Test portal_skins content\n
for folder in context.portal_skins.objectValues(spec=(\'Folder\',)):\n
  if not folder.id.startswith(\'erp5_\'):\n
    continue\n
  for form in folder.objectValues(spec=(\'ERP5 Form\',)):\n
    if form.pt in (\'embedded_form_render\', \'ical_view\', \'rss_view\'):\n
      continue\n
    message = checkTitle(\'/\'.join([folder.id, form.id]), \'Title of the Form itself\', form.title)\n
    if message:\n
      message_list.append(message)\n
    if form.id.endswith("FieldLibrary"):\n
      if not(form.id.startswith("Base_")):\n
        message_list.append("%s/%s : Bad Form ID for a Field Library Form" % (folder.id, form.id))\n
    for group in form.get_groups():\n
      if group == \'hidden\':\n
        continue\n
      for field in form.get_fields_in_group(group, include_disabled=True):\n
        if field.get_value(\'hidden\') or field.id == \'matrixbox\':\n
          continue\n
        message = checkField(folder, form, field)\n
        if message:\n
          message_list.append(message)\n
\n
\n
# Test worflow related stuff\n
for wf in context.portal_workflow.objectValues():\n
\n
  # Test workflow states\n
  wf_states = wf.states\n
  message = \'\'\n
  if wf_states not in (None, (), [], \'\'):\n
    for state in wf_states.objectValues() :\n
      message += checkTitle(\'/\'.join([\'portal_workflow\', wf.id, \'states\', state.id]), \'title\', state.title)\n
    if message:\n
      message_list.append(message)\n
\n
#   # Test workflow states\n
#   wf_scripts = wf.scripts\n
#   message = \'\'\n
#   if wf_scripts not in (None, (), [], \'\'):\n
#     for script in wf_scripts.objectValues():\n
#       message += checkTitle(\'/\'.join([\'portal_workflow\', wf.id, \'scripts\', script.id]), \'id\', script.id)\n
#     if message:\n
#       message_list.append(message)\n
\n
\n
# Test portal types\n
IGNORE_PORTAL_TYPE_SET = set(("Application Id Generator",\n
  "Conceptual Id Generator", "DateTime Divergence Tester",\n
  "Distributed Ram Cache", "Fax", "Fax Message", "Id Tool", "OAuth Tool",\n
  "OOo Document", "Ram Cache", "SQL Non Continuous Increasing Id Generator",\n
  "Url Registry Tool", "ZODB Continuous Increasing Id Generator"))\n
for ptype in context.portal_types.objectValues():\n
  pt_id = ptype.id\n
  if pt_id in IGNORE_PORTAL_TYPE_SET:\n
    continue\n
  pt_title = ptype.title\n
  message = \'\'\n
  if pt_title not in (None, \'\'):\n
    message += checkTitle(\'/\'.join([\'portal_types\', pt_id]), \'title\', pt_title)\n
  #else:\n
  #  message += checkTitle(\'/\'.join([\'portal_types\', pt_id]), \'id\', pt_id)\n
  if message:\n
    message_list.append(message)\n
\n
if batch_mode:\n
  return message_list\n
if message_list:\n
  return ("%d problems found:\\n\\n" % len(message_list)) + \'\\n\'.join(message_list)\n
return "OK"\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>batch_mode=False</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Site_checkNamingConventions</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
