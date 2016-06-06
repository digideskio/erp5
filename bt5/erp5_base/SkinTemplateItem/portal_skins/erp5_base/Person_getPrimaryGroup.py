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
  Returns a group category based on career\n
  and or assignments in such way that the returned\n
  value describes the most accurately the default group\n
  which a person has been assigned to.\n
\n
  Default implementation considers the list of\n
  valid assigned groups, if any, and returns the most recent\n
  one. Else, it returns the career group.\n
\n
  Implementation is based on Person_getAssignedGroupList.\n
  (to be implemented).\n
"""\n
\n
if REQUEST is not None:\n
  # This script has proxy roles, so we don\'t allow users to call it directly\n
  from AccessControl import getSecurityManager\n
  from zExceptions import Unauthorized\n
  if not \'Manager\' in getSecurityManager().getUser().getRoles():\n
    raise Unauthorized(script)\n
\n
from DateTime import DateTime\n
now = DateTime()\n
\n
existing_group_set = {}\n
for assignment in context.contentValues(portal_type=\'Assignment\'):\n
  if assignment.getGroup() \\\n
      and assignment.getValidationState() == \'open\' \\\n
      and ( assignment.getStartDate() is None or\n
            assignment.getStartDate() <= now <= assignment.getStopDate()):\n
   existing_group_set[assignment.getGroup()] = 1\n
\n
# If we have multiple groups defined on assignments, this scripts does not\n
# try to guess, and fallback to the default career\'s group\n
if len(existing_group_set.keys()) == 1:\n
  return existing_group_set.keys()[0]\n
\n
# no group found on open assignments, returns the default group\n
# (on a person document this is acquired on the default career\'s subordination)\n
return context.getGroup()\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>REQUEST=None</string> </value>
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
            <value> <string>Person_getPrimaryGroup</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
