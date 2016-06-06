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

request=context.REQUEST\n
\n
\n
# check captcha\n
if not context.isCaptchaTextCorrect(captcha_text):\n
  message = "text entered at the right of the picture is wrong"\n
  translated_message = context.Base_translateString(message)\n
  return request[\'RESPONSE\'].redirect(\n
             "%s/view?portal_status_message=%s" %\n
             (context.absolute_url(), translated_message))\n
\n
web_site_url = context.getWebSiteValue().absolute_url()\n
\n
portal_type = request.get(\'portal_type\',\'\')\n
\n
if portal_type == \'\': \n
  return request[\'RESPONSE\'].redirect(web_site_url) \n
\n
 \n
# create a new anonymous procedure\n
module = context.getDefaultModule(portal_type=portal_type)\n
form = module.newContent(portal_type=portal_type)\n
\n
module_id = module.getId()\n
new_object_id = form.getId()\n
\n
redirect_url = "%s/%s/%s" % (web_site_url, module_id, new_object_id)\n
\n
# set a login on the new form\n
form.setReference(new_object_id)\n
\n
# set a password\n
password = context.Person_generatePassword()\n
form.setPassword(password)\n
\n
# the ownership is the form itself\n
form.manage_addLocalRoles(new_object_id, [\'Owner\',\'Agent\'])\n
\n
\n
# login with this new form\n
# set in the request wich module is used for this annonymous application\n
# this is use in PAS\n
redirect_url = \'%s/logged_in?__ac_name=%s&__ac_password=%s&anonymous_module=%s\' % (redirect_url, new_object_id, password, module.getId())\n
\n
result = request[\'RESPONSE\'].redirect(redirect_url) \n
return result\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>captcha_text=\'\', **kw</string> </value>
        </item>
        <item>
            <key> <string>_proxy_roles</string> </key>
            <value>
              <tuple>
                <string>Manager</string>
                <string>Owner</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>EGov_register</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
