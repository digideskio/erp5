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
            <value> <string>from Products.ERP5Type.Message import translateString\n
from Products.ERP5Type.Document import newTempDocument\n
return_list = []\n
i = 1\n
portal = context.getPortalObject()\n
for worklist in context.portal_workflow.listActionInfos():\n
  # XXX worklist translation process is a bit tricky. We translate only the first part of "XXX to Validate (count)"\n
  title = worklist[\'title\']\n
  title, count = title.split(\' (\', 1)\n
  title = "%s (%s" % ( translateString(title), count )\n
  o = newTempDocument(portal, str(i))\n
  o.edit(\n
    count=worklist[\'count\'],\n
    title=title,\n
    worklist_url=worklist[\'url\']\n
  )\n
  return_list.append(o)\n
  i+=1\n
\n
return return_list\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>*args, **kwargs</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>ERP5Site_getWorklistObjectList</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
