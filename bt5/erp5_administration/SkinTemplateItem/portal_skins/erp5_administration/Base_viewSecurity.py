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
            <value> <string>from AccessControl import getSecurityManager\n
from zExceptions import Unauthorized\n
from pprint import pformat\n
\n
u = getSecurityManager().getUser()\n
\n
print \'User:\', u\n
print \'Is owner:\', u.allowed(context,(\'Owner\',))\n
print \'User roles:\', u.getRoles()\n
print \'User roles in context:\', u.getRolesInContext(context)\n
print \'Permissions:\'\n
for permission in [\n
  \'Access contents information\',\n
  \'Add portal content\',\n
  \'Delete objects\',\n
  \'Modify portal content\',\n
  \'View\',\n
  \'Manage portal\',\n
]:\n
  print " ", permission, u.has_permission(permission, context)\n
\n
print\n
try:\n
  print "User groups:\\n", pformat(u.getGroups())\n
except AttributeError:\n
  print \'no getGroups\'\n
\n
print\n
print \'Local roles on document:\\n\', pformat(context.get_local_roles())\n
\n
print \'\'\'\n
----------------\n
Security mapping\n
----------------\'\'\'\n
if u.getId() is not None:\n
  try:\n
    print context.Base_viewSecurityMappingAsUser(u.getId())\n
  except Unauthorized:\n
    print "user doesn\'t have permission to security mapping in this context"\n
\n
return printed\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
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
            <value> <string>Base_viewSecurity</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
