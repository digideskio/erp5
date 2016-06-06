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
            <value> <string># this is made to be sure that captcha image will not be cached\n
container.REQUEST.RESPONSE.setHeader(\'Pragma\', \'no-cache\')\n
\n
request = context.REQUEST\n
now = DateTime()\n
expire_timeout_days = 90\n
session_id = request.get(\'erp5_captcha_session_id\', None)\n
if session_id is None:\n
  ## first call so generate session_id and send back via cookie\n
  session_id = context.browser_id_manager.getBrowserId(create=1) # generate it yourself\n
  request.RESPONSE.setCookie(\'erp5_captcha_session_id\', session_id, expires=(now +expire_timeout_days).fCommon(), path=\'/\') \n
\n
# get session\n
session = context.portal_sessions[session_id]\n
\n
captcha_file_path = context.getTempFileName()\n
bg_file = context.generateBgFile(120, 40)\n
captcha_text = context.getRandomText()\n
image_data = context.makeCaptcha(text=captcha_text, bg_file=bg_file,\n
            captcha_file_path=captcha_file_path)\n
\n
session[\'captcha_text\']=captcha_text\n
session[\'captcha_image_path\']=captcha_file_path\n
\n
return image_data\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Captcha_getCaptchaFile</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
