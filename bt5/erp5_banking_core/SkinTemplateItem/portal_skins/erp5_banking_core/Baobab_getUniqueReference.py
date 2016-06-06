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
            <value> <string># first try to get the reference\n
try:\n
  reference = context.getSourceReference()\n
except AttributeError:\n
  return \'\'\n
\n
application_id = \'BA\'\n
\n
N_ = context.Base_translateString\n
\n
# if it\'s not defined, try to generate it\n
if reference in (None, \'\') or not str(reference).startswith(application_id):\n
  date = context.getCreationDate()\n
  if date in (None, \'\'):\n
    message = N_("No date defined")\n
    return message\n
  year = date.strftime(\'%Y\')\n
\n
  # codification\n
  source = context.getSourceValue()\n
  if source not in (None, \'\'):\n
    codification = source.getCodification()\n
    if codification in (None, \'\'):\n
      return \'\'\n
  else:\n
    # get from document site\n
    site = context.getSiteValue()\n
    if site not in (None, \'\'):\n
      codification = site.getCodification()\n
      if codification in (None, \'\'):\n
        return \'\'\n
    else:\n
      # get source from user site\n
      site_list = context.Baobab_getUserAssignedSiteList()\n
      if len(site_list) == 0:\n
        return \'\'\n
      else:\n
        site = site_list[0]\n
        site_value = context.restrictedTraverse(\'portal_categories/%s\' %(site,))\n
        codification = site_value.getCodification()\n
        if codification in (None, \'\'):\n
          return \'\'\n
\n
  # actual generation\n
  #if reference in (None, \'\'): \n
  #XXX is it necessary to concatenate to an old reference ?\n
  # this make reference look strange when using different script to\n
  # generate reference based on criteria the user can play with\n
  baobab_id_group = (application_id, codification, year)\n
  new_id = context.portal_ids.generateNewLengthId(id_group = baobab_id_group,  default=1)\n
\n
  # affectation\n
  reference = "%s-%s-%s-%s" % (application_id, codification, year, new_id)\n
  context.setSourceReference(reference)\n
\n
# finally, return it\n
return reference\n
</string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>Baobab_getUniqueReference</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
