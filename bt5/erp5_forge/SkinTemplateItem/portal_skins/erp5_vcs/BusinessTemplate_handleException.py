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
            <value> <string>from Products.ERP5VCS.Git import GitLoginError\n
from Products.ERP5VCS.SubversionClient import SubversionSSLTrustError, SubversionLoginError\n
\n
try:\n
  raise exception\n
except SubversionSSLTrustError, e:\n
  message = \'SSL Certificate was not recognized\'\n
  kw = dict(trust_dict=e.getTrustDict())\n
  method = \'BusinessTemplate_viewSvnSSLTrust\'\n
except SubversionLoginError, e:\n
  message = \'Server needs authentication, no cookie found\'\n
  kw = dict(realm=e.getRealm(), username=context.getVcsTool().getPreferredUsername())\n
  method = \'BusinessTemplate_viewSvnLogin\'\n
except GitLoginError, e:\n
  message = str(e)\n
  kw = dict(remote_url=context.getVcsTool().getRemoteUrl())\n
  method = \'BusinessTemplate_viewGitLogin\'\n
\n
context.REQUEST.set(\'portal_status_message\', message)\n
return getattr(context.asContext(**kw), method)(caller=caller, caller_kw=caller_kw)\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>exception, caller, **caller_kw</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>BusinessTemplate_handleException</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
