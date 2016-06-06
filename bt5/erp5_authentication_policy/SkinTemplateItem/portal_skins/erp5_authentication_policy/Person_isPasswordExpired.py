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
  Returns if user account is Person\'s password is expired.\n
  Start password recovery process for expired password (if configured).\n
"""\n
from Products.ERP5Type.Cache import CachingMethod\n
\n
request = context.REQUEST\n
portal = context.getPortalObject()\n
\n
def _isPasswordExpired():\n
  from DateTime import DateTime\n
  one_hour = 1/24.0\n
  now = DateTime()\n
  max_password_lifetime_duration = portal.portal_preferences.getPreferredMaxPasswordLifetimeDuration()\n
  password_lifetime_expire_warning_duration = portal.portal_preferences.getPreferredPasswordLifetimeExpireWarningDuration()\n
  last_password_event = portal.portal_catalog.getResultValue(\n
                                                portal_type = \'Password Event\',\n
                                                default_destination_uid = context.getUid(),\n
                                                validation_state = \'confirmed\',\n
                                                sort_on = ((\'creation_date\', \'DESC\',),))\n
  expire_date_warning = 0 \n
  if last_password_event is not None:\n
    last_password_modification_date = last_password_event.getCreationDate()\n
    expire_date = last_password_modification_date + max_password_lifetime_duration*one_hour \n
    if password_lifetime_expire_warning_duration not in (0, None,):\n
      # calculate early warning period\n
      if now > expire_date - password_lifetime_expire_warning_duration*one_hour and \\\n
         expire_date > now:\n
        expire_date_warning =  expire_date\n
    if expire_date < now:\n
      # password is expired\n
      #context.log(\'expired %s\' %context.getReference())\n
      return True, expire_date_warning\n
  return False, expire_date_warning\n
\n
_isPasswordExpired = CachingMethod(_isPasswordExpired,\n
                                   id=\'Person_isPasswordExpired_%s\' %context.getReference(),\n
                                   cache_factory=\'erp5_content_short\')\n
is_password_expired, expire_date = _isPasswordExpired()\n
\n
request.set(\'is_user_account_password_expired\', is_password_expired)\n
request.set(\'is_user_account_password_expired_expire_date\', expire_date)\n
\n
return is_password_expired\n


]]></string> </value>
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
            <value> <string>Person_isPasswordExpired</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
