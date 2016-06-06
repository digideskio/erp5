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

from Products.DCWorkflow.DCWorkflow import ValidationFailed\n
from Products.ERP5Type.Message import Message\n
\n
# Check new catalog or catalog is the same as previous archive\n
# Check date\n
# Check connection definition\n
\n
archive = state_change[\'object\']\n
min_stop_date = archive.getStopDateRangeMin().Date()\n
catalog_id = archive.getCatalogId()\n
\n
if "deferred" not in archive.getDeferredConnectionId():\n
  msg = Message(domain=\'ui\', message=\'Deferred connection ID choose is not a deferred connection.\')\n
  raise ValidationFailed, (msg,)\n
\n
def sort_max_date(a, b):\n
  return cmp(a.getStopDateRangeMax(), b.getStopDateRangeMax())\n
\n
\n
if archive.getStopDateRangeMax() is not None:\n
\n
  previous_archive_list = [x.getObject() for x in archive.portal_catalog(portal_type="Archive",\n
                                                                         validation_state=\'validated\')]\n
  previous_archive_list.sort(sort_max_date)\n
\n
  if len(previous_archive_list) > 0:\n
    # Check the date\n
    for x in xrange(len(previous_archive_list)):\n
      previous_archive = previous_archive_list[x]\n
      # find a previous archive which was not for current catalog\n
      if previous_archive.getStopDateRangeMax() is not None:\n
        break\n
    if previous_archive.getStopDateRangeMax().Date() != min_stop_date:\n
      msg = Message(domain=\'ui\', message=\'Archive are not contiguous.\')\n
      raise ValidationFailed, (msg,)\n
else:\n
  previous_archive_list = [x.getObject() for x in archive.portal_catalog(portal_type="Archive",\n
                                                                         validation_state=\'ready\')]\n
  previous_archive_list.sort(sort_max_date)\n
\n
  if len(previous_archive_list) > 0:\n
    # Check the date\n
    for x in xrange(len(previous_archive_list)):\n
      previous_archive = previous_archive_list[x]\n
      # find a previous archive which was not for current catalog\n
      if previous_archive.getStopDateRangeMax() is not None:\n
        break\n
    if previous_archive.getStopDateRangeMax().Date() != min_stop_date:\n
      msg = Message(domain=\'ui\', message=\'Archive are not contiguous.\')\n
      raise ValidationFailed, (msg,)\n
\n
\n
# Check the catalog\n
previous_archive_list = [x.getObject() for x in archive.portal_catalog(portal_type="Archive",\n
                                                                       validation_state=[\'validated\', \'ready\'])]\n
\n
for arch in previous_archive_list:\n
  if arch.getCatalogId() == catalog_id and arch is not previous_archive:\n
    msg = Message(domain=\'ui\', message=\'Use of a former catalog is prohibited.\')\n
    raise ValidationFailed, (msg,)\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string>state_change</string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>checkArchive</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
