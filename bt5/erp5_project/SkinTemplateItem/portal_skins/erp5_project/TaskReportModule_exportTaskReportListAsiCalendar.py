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

"""Export the current selection in task report module in iCalendar format.\n
"""\n
# XXX bypass CookieCrumbler\n
if context.REQUEST.AUTHENTICATED_USER.getUserName() == \'Anonymous User\': \n
  if context.REQUEST.get(\'disable_cookie_login__\', 0) \\\n
          or context.REQUEST.get(\'no_infinite_loop\', 0)  :\n
    raise \'Unauthorized\', context\n
  return context.REQUEST.RESPONSE.redirect(script.id + "?disable_cookie_login__=1&no_infinite_loop=1")\n
\n
def formatDate(date):\n
  d = "%04d%02d%02d" % (date.year(), date.month(), date.day())\n
  if date.hour() and date.minute():\n
    d += "T%02d%02d%02d" % (date.hour(), date.minute(), date.second())\n
  return d\n
\n
def foldContent(s):\n
  """ fold a content line (cf RFC 2445) """\n
  s = s.replace(\',\', \'\\\\,\')\n
  s = s.replace(\'/\', \'\\\\/\')\n
  s = s.replace(\'"\', \'\\\\"\')\n
  s = s.replace(\'\\n\', \'\\\\n\')\n
  # FIXME: really fold, for now we return a big line, it works for most clients\n
  return s\n
\n
def printTask(task) :\n
  print """BEGIN:VTODO\n
DCREATED:%(creation_date)s\n
UID:%(uid)s\n
SEQUENCE:1\n
LAST-MODIFIED:%(modification_date)s\n
SUMMARY:%(title)s\n
STATUS:%(status)s\n
PRIORITY:%(priority)s""" % ( {\n
        \'creation_date\': formatDate(task.getCreationDate()),\n
        \'uid\': task.getPath(),\n
        \'title\': foldContent(task.getTitle()),\n
        \'modification_date\': formatDate(task.getModificationDate()),\n
        \'status\': task.getSimulationState() == \'delivered\' and \'COMPLETED\' or \'NEEDS_ACTION\',\n
        \'priority\': task.getProperty(\'int_index\', 3),\n
  } )\n
  if task.hasComment():\n
    print "DESCRIPTION:" + foldContent(task.getComment())\n
  if task.hasStartDate():\n
    print "DTSTART;VALUE=DATE:" + formatDate(task.getStartDate())\n
  if task.hasStopDate():\n
    print "DUE;VALUE=DATE:" + formatDate(task.getStopDate())\n
  organizer = task.getDestinationValue(portal_type=\'Person\')\n
  if organizer:\n
    print "ORGANIZER;CN=%s:MAILTO:%s" % (organizer.getTitle(), organizer.getDefaultEmailText())\n
    print "X-ORGANIZER:MAILTO:%s" % (organizer.getDefaultEmailText())\n
  for attendee in task.getSourceValueList( portal_type = \'Person\') :\n
    print "ATTENDEE;CN=%s:MAILTO:%s" % (attendee.getTitle(), attendee.getDefaultEmailText())\n
  print "ATTACH;FMTTYPE=text/html:%s/%s/view" % (context.ERP5Site_getAbsoluteUrl(), task.getRelativeUrl())\n
\n
  print "END:VTODO"\n
  return printed\n
\n
print """BEGIN:VCALENDAR\n
PRODID:-//ERP5//NONSGML Task Report Module//EN \n
VERSION:2.0"""\n
obj_list = context.getPortalObject().portal_selections.callSelectionFor("task_report_module_selection")\n
for obj in obj_list : \n
  print printTask(obj.getObject())\n
print "END:VCALENDAR"\n
\n
context.REQUEST.RESPONSE.setHeader(\'Content-Type\', \'text/calendar\')\n
context.REQUEST.RESPONSE.setHeader(\'Content-disposition\',  \'attachment; filename=ERP5.ics\')\n
return printed\n


]]></string> </value>
        </item>
        <item>
            <key> <string>_params</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>TaskReportModule_exportTaskReportListAsiCalendar</string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
