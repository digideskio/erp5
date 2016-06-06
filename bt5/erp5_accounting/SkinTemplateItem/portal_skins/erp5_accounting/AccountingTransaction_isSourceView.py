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
            <value> <string>source = context.getSourceSectionValue()\n
section_category = context.portal_preferences\\\n
         .getPreferredAccountingTransactionSectionCategory()\n
section_category_strict = context.portal_preferences\\\n
         .getPreferredAccountingSectionCategoryStrict()\n
\n
# If the source is an organisation member of the preferred section category,\n
# then we\'ll show the source view\n
if source is not None and section_category:\n
  if source.getPortalType() == \'Person\':\n
    return False\n
  if source.isMemberOf(section_category,\n
                       strict_membership=section_category_strict):\n
    return True\n
\n
# Else, if the destination is an organisation member of the preferred section category,\n
# then we\'ll not show source view\n
destination = context.getDestinationSectionValue()\n
if destination is not None and section_category:\n
  if destination.getPortalType() == \'Person\':\n
    return True\n
  if destination.isMemberOf(section_category,\n
                            strict_membership=section_category_strict):\n
    return False\n
\n
# If we reach this point, none of the sections are member of the preferred section\n
# category, we\'ll then show source view, default for this script\n
return True\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>AccountingTransaction_isSourceView</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
