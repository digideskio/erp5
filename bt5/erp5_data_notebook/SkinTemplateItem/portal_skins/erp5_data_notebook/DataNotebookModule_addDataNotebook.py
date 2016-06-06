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
Python script to add a new notebook to Data Notebook module.\n
This script also concerns for assigning an Active Process for each data notebook\n
created.\n
"""\n
from Products.CMFActivity.ActiveResult import ActiveResult\n
\n
# Comment out person in case addition of person required to Data Notebook object\n
#person = context.ERP5Site_getAuthenticatedMemberPersonValue()\n
\n
# Create new ActiveProcess object and getting its id\n
active_process = context.portal_activities.newActiveProcess()\n
active_process_id = active_process.getId()\n
\n
# Creating new dictionary via external method to save results in ZODB\n
new_dict = context.Base_addLocalVariableDict()\n
# Add new ActiveResult object and add it to the activeprocess concerned with ...\n
# Data Notebook in concern\n
result = ActiveResult(summary=new_dict)\n
active_process.activateResult(result)\n
\n
# Create new notebook\n
notebook = context.newContent(\n
    title=title,\n
    reference=reference,\n
    process=active_process_id,\n
    portal_type=\'Data Notebook\'\n
  )\n
\n
# Return notebook for batch_mode, used in tests\n
if batch_mode:\n
  return notebook\n
\n
# Add status message to be displayed after new notebook creation\n
translateString = context.Base_translateString\n
portal_status_message = translateString(\n
  "New Notebook created"\n
)\n
\n
# Redirect the notebook view with the status message being displayed\n
return notebook.Base_redirect(\'view\',\n
  keep_items=dict(portal_status_message=portal_status_message), **kw)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>title, reference, batch_mode=False, **kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>DataNotebookModule_addDataNotebook</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
