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
            <value> <string>miss = (None, None)\n
\n
if not value:\n
  return miss\n
\n
# length of portal type name must be less than 100.\n
value_first_lowered = value[:100].lower()\n
\n
if not \':\' in value_first_lowered:\n
  return miss\n
\n
Base_translateString = context.Base_translateString\n
language_list = context.Localizer.get_supported_languages()\n
translated_portal_type_list = []\n
\n
def addCandidateTypeName(name, portal_type):\n
  translated_portal_type_list.append((name, portal_type))\n
  if \' \' in name:\n
    alternative = name.split(\' \')[0]\n
    translated_portal_type_list.append((alternative, portal_type))\n
\n
for type_name in context.getPortalEventTypeList():\n
  addCandidateTypeName(type_name, type_name)\n
  for language in language_list:\n
    translated = Base_translateString(type_name, lang=language)\n
    if translated != type_name:\n
      addCandidateTypeName(translated, type_name)\n
\n
for translated, type_name in translated_portal_type_list:\n
  prefix = \'%s:\' % translated.lower()\n
  if value_first_lowered.startswith(prefix):\n
    return type_name, translated\n
\n
return miss\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>value</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Base_findPortalTypeNameAndMatchedValueForEvent</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
