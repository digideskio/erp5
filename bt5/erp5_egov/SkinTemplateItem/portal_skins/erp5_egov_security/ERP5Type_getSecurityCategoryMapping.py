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
Understand this and make it suit your needs\n
"""\n
return (\n
# This one combines function, type of procedure and destination to generate a security group\n
  (\'ERP5Type_getSecurityCategoryFromAssignmentStrict\', [\'destination\', \'function\', \'publication_section\', ] ),\n
# This one is the usual group and function security\n
  (\'ERP5Type_getSecurityCategoryFromAssignmentStrict\', [\'function\', \'group\',] ),\n
  (\'ERP5Type_getSecurityCategoryFromAssignmentParentGroup\', [\'function\', \'group\',  ]),\n
# This one is the usual group, function and site security, needed if access rights depend on site\n
  (\'ERP5Type_getSecurityCategoryFromAssignmentStrict\', [\'function\', \'group\', \'site\'] ),\n
# This one is the usual group security\n
  (\'ERP5Type_getSecurityCategoryFromAssignmentStrict\', [\'group\',] ),\n
  (\'ERP5Type_getSecurityCategoryFromAssignmentParent\', [\'group\',] ),\n
\n
# This one is the usual function security\n
  (\'ERP5Type_getSecurityCategoryFromAssignment\', [\'function\'] ),\n
# This one is the usual role security\n
  (\'ERP5Type_getSecurityCategoryFromEntity\', [\'role\'] ),\n
  (\'ERP5Type_getSecurityCategoryFromAssignmentStrict\', [\'role\', ]),\n
# This one combines role and publication_section\n
  (\'ERP5Type_getSecurityCategoryFromAssignmentStrict\', [\'publication_section\', \'role\', ] ),\n
\n
)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Type_getSecurityCategoryMapping</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
