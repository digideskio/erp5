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
  This script generates a sections list to filter the document on UNG Docs.\n
"""\n
\n
from Products.ERP5Type.Cache import CachingMethod\n
\n
def getAvailableSubjectList(subject_list=()):\n
  """\n
    Returns the list of available subjects for all documents\n
    located in the current container (if defined) and which\n
    already match all subjects of subject_list\n
  """\n
  subject_list = ()\n
  portal_type_list = ["Web Table", "Web Page", "Web Illustration"]\n
  kw = dict(portal_type=portal_type_list,\n
            subject="!=",)\n
  subject_len = len(subject_list)\n
  result_list = context.portal_catalog(**kw)\n
\n
  subject_list = []\n
  for keyword_list in  filter(lambda x: x not in subject_list, \n
                       map(lambda r: r.subject, result_list)):\n
     for keyword in keyword_list:\n
       if keyword not in subject_list:\n
         subject_list.append(keyword)\n
\n
  return subject_list\n
\n
def appendTempDomain(id, \n
                     title,\n
                     property_dict,\n
                     parent=parent,\n
                     membership_criterion_base_category=(),\n
                     membership_criterion_category=()):\n
  domain = parent.generateTempDomain(id=id)\n
  domain.edit(title=title,\n
              domain_generator_method_id=script.id,\n
              membership_criterion_base_category=membership_criterion_base_category,\n
              membership_criterion_category=membership_criterion_category) \n
\n
  domain.setCriterionPropertyList(property_dict.keys())\n
  for key, value in property_dict.items():\n
    domain.setCriterion(key, value)\n
\n
  domain_list.append(domain)\n
\n
domain_list = []\n
\n
if depth > 1:\n
  return domain_list\n
\n
getAvailableSubjectListCached = CachingMethod(getAvailableSubjectList, \n
                                              id=\'%s_%s\' % (script.id, \'subject_list_cached\'),\n
                                              cache_factory=\'erp5_ui_short\')\n
\n
subject_list = getAvailableSubjectListCached()\n
\n
for subject in subject_list:\n
  appendTempDomain("subject_" + subject,\n
                   subject.capitalize(),\n
                   dict(subject=subject),\n
                   parent,\n
                   ("by_subject",),\n
                   ("by_subject",))\n
\n
\n
return domain_list\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>depth, parent, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Site_generateDomain</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
