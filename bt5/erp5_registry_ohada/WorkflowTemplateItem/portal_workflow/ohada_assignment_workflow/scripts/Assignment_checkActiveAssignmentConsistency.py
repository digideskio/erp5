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
            <value> <string># XXX\n
# This script is given as a possible example of consistency checking.\n
# So for now, it is not called by any transition, but if you want to use it,\n
# please use it in the "Script (before)" of the "open_action" transition.\n
# In this case we want to be sure that open assignments share the same site category.\n
# XXX\n
\n
from Products.DCWorkflow.DCWorkflow import ValidationFailed\n
\n
# Get the assignment object and its parent\n
assignment_object = state_change[\'object\']\n
person_object     = assignment_object.getParentValue()\n
\n
# Add the current assignment site\n
assignment_site_list = [assignment_object.getSite()]\n
\n
# Get the list of site property from open assignments\n
for assignment in person_object.contentValues(filter={\'portal_type\': \'Assignment\'}):\n
  if assignment.getValidationState() == \'open\':\n
    assignment_site = assignment.getSite()\n
    if assignment_site not in assignment_site_list:\n
      assignment_site_list.append(assignment_site)\n
\n
# The only case when several assignments can be started at the same time is when they share the same \'site\' value.\n
if len(assignment_site_list) != 1:\n
  raise ValidationFailed, "Error: started assignments must have the same site value."\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>state_change</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Assignment_checkActiveAssignmentConsistency</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
