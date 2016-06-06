<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="Web Script" module="erp5.portal_type"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>_Access_contents_information_Permission</string> </key>
            <value>
              <tuple>
                <string>Anonymous</string>
                <string>Assignee</string>
                <string>Assignor</string>
                <string>Associate</string>
                <string>Auditor</string>
                <string>Manager</string>
                <string>Owner</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>_Add_portal_content_Permission</string> </key>
            <value>
              <tuple>
                <string>Assignee</string>
                <string>Assignor</string>
                <string>Manager</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>_Change_local_roles_Permission</string> </key>
            <value>
              <tuple>
                <string>Assignor</string>
                <string>Manager</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>_Modify_portal_content_Permission</string> </key>
            <value>
              <tuple>
                <string>Assignee</string>
                <string>Assignor</string>
                <string>Manager</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>_View_Permission</string> </key>
            <value>
              <tuple>
                <string>Anonymous</string>
                <string>Assignee</string>
                <string>Assignor</string>
                <string>Associate</string>
                <string>Auditor</string>
                <string>Manager</string>
                <string>Owner</string>
              </tuple>
            </value>
        </item>
        <item>
            <key> <string>content_md5</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>default_reference</string> </key>
            <value> <string>gadget_erp5_field_datetime.js</string> </value>
        </item>
        <item>
            <key> <string>description</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>rjs_gadget_erp5_datetimefield_js</string> </value>
        </item>
        <item>
            <key> <string>language</string> </key>
            <value> <string>en</string> </value>
        </item>
        <item>
            <key> <string>portal_type</string> </key>
            <value> <string>Web Script</string> </value>
        </item>
        <item>
            <key> <string>short_title</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>text_content</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*global window, rJS, RSVP, document, loopEventListener */\n
/*jslint indent: 2 */\n
(function (window, rJS, RSVP, document, loopEventListener) {\n
  "use strict";\n
  rJS(window)\n
    .ready(function (gadget) {\n
      return gadget.getElement()\n
        .push(function (element) {\n
          gadget.element = element;\n
          gadget.props = {};\n
        });\n
    })\n
    .declareAcquiredMethod("notifyInvalid", "notifyInvalid")\n
    .declareAcquiredMethod("notifyValid", "notifyValid")\n
    .declareMethod(\'getTextContent\', function () {\n
      return this.element.querySelector(\'input\').getAttribute(\'value\') || "";\n
    })\n
    .declareMethod(\'render\', function (options) {\n
      var input = this.element.querySelector(\'input\'),\n
        date,\n
        tmp,\n
        timezone,\n
        tmp_year,\n
        tmp_month,\n
        tmp_date,\n
        tmp_hour,\n
        tmp_minute,\n
        select,\n
        time = "",\n
        leapyear,\n
        i,\n
        field_json = options.field_json || {},\n
        lastDateOfMonth = [[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31],\n
                           [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]],//leapyear\n
        select_options = ["GMT-12", "GMT-11", "GMT-10", "GMT-9", "GMT-8", "GMT-7", "GMT-6",\n
                   "GMT-5", "GMT-4", "GMT-3", "GMT-2", "GMT-1", "GMT", "GMT+1",\n
                   "GMT+2", "GMT+3", "GMT+4", "GMT+5", "GMT+6", "GMT+7", "GMT+8",\n
                   "GMT+9", "GMT+10", "GMT+11", "GMT+12"],\n
        select_option,\n
        value = field_json.value || field_json.default || "";\n
      this.props.field_json = field_json;\n
\n
\n
      if (field_json.timezone_style) {\n
        //change date to local\n
        select = document.createElement("select");\n
        for (i = 0; i < select_options.length; i += 1) {\n
          select_option = document.createElement("option");\n
          select_option.value = select_options[i];\n
          select_option.innerHTML = select_options[i];\n
          select.appendChild(select_option);\n
        }\n
        select.setAttribute("class", "gmt_select");\n
        select.selectedIndex = 12;\n
        this.element.appendChild(select);\n
      }\n
      if (field_json.date_only === 0) {\n
        input.setAttribute("type", "datetime-local");\n
      }\n
      //Change type to datetime/datetime local if configured in the field\n
      if (value !== "") {\n
        tmp = new Date(value);\n
        //get date without timezone\n
        tmp_date = tmp.getUTCDate();\n
        tmp_month = tmp.getUTCMonth() + 1;\n
        tmp_year = tmp.getUTCFullYear();\n
\n
        tmp_hour = tmp.getUTCHours();\n
        tmp_minute = tmp.getUTCMinutes();\n
\n
        //timezone required\n
        //convert time to GMT\n
        timezone = parseInt(value.slice(-5), 10) / 100;\n
\n
        if (field_json.timezone_style) {\n
          select.selectedIndex = timezone + 12;\n
        }\n
        leapyear = (tmp_year % 4 === 0 && tmp_year % 100 !== 0) ? 1 : 0;\n
        if (timezone !== 0) {\n
          tmp_hour += timezone;\n
          if (tmp_hour < 0) {\n
            tmp_hour += 24;\n
            tmp_date -= 1;\n
            if (tmp_date === 0) {\n
              tmp_month -= 1;\n
              if (tmp_month === 0) {\n
                tmp_month = 12;\n
                tmp_year -= 1;\n
              }\n
              tmp_date = lastDateOfMonth[leapyear][tmp_month - 1];\n
            }\n
          } else if (tmp_hour > 23) {\n
            tmp_hour -= 24;\n
            tmp_date += 1;\n
            if (tmp_date > lastDateOfMonth[leapyear][tmp_month - 1]) {\n
              tmp_date = 1;\n
              tmp_month += 1;\n
              if (tmp_month > 12) {\n
                tmp_month = 1;\n
                tmp_year += 1;\n
              }\n
            }\n
          }\n
        }\n
        if (field_json.date_only === 0) {\n
          time = "T" + Math.floor(tmp_hour / 10) + tmp_hour % 10 + ":"\n
              + Math.floor(tmp_minute / 10) +  (tmp_minute % 10) + ":00";\n
        }\n
        date = tmp_year + "-" + Math.floor(tmp_month / 10) + (tmp_month % 10) + "-"\n
               +  Math.floor(tmp_date / 10) + (tmp_date % 10);\n
\n
        input.setAttribute(\n
          \'value\',\n
          date + time\n
        );\n
      }\n
      input.setAttribute(\'name\', field_json.key);\n
      input.setAttribute(\'title\', field_json.title);\n
      if (field_json.required === 1) {\n
        input.setAttribute(\'required\', \'required\');\n
      }\n
      if (field_json.editable !== 1) {\n
        input.setAttribute(\'readonly\', \'readonly\');\n
        input.setAttribute(\'data-wrapper-class\', \'ui-state-disabled ui-state-readonly\');\n
        input.setAttribute(\'disabled\', \'disabled\');\n
      }\n
    })\n
    .declareMethod(\'getContent\', function () {\n
      var input = this.element.querySelector(\'input\'),\n
        result = {},\n
        select,\n
        year,\n
        month,\n
        field_json = this.props.field_json,\n
        date,\n
        hour,\n
        minute,\n
        value = input.value;\n
      if (value !== "") {\n
        if (field_json.date_only === 0) {\n
          value += "+0000";\n
        }\n
        value = new Date(value);\n
        year = value.getUTCFullYear();\n
        month = value.getUTCMonth() + 1;\n
        date = value.getUTCDate();\n
        if (field_json.hide_day === 1) {\n
          date = 1;\n
        }\n
        //get time\n
        if (field_json.date_only === 0) {\n
          if (field_json.allow_empty_time === 1) {\n
            hour = 0;\n
            minute = 0;\n
          } else {\n
            hour = value.getUTCHours();\n
            minute = value.getUTCMinutes();\n
          }\n
          if (field_json.ampm_time_style === 1) {\n
            if (hour > 12) {\n
              result[field_json.subfield_ampm_key] = "pm";\n
              hour -= 12;\n
            } else {\n
              result[field_json.subfield_ampm_key] = "am";\n
            }\n
          }\n
          result[field_json.subfield_hour_key] = hour;\n
          result[field_json.subfield_minute_key] = minute;\n
        }\n
\n
        if (field_json.hidden_day_is_last_day === 1) {\n
          if (month === 12) {\n
            year += 1;\n
            month = 1;\n
          } else {\n
            month += 1;\n
          }\n
        }\n
        result[field_json.subfield_year_key] = year;\n
        result[field_json.subfield_month_key] = month;\n
        result[field_json.subfield_day_key] = date;\n
        if (field_json.timezone_style) {\n
          //set timezone\n
          select = this.element.querySelector("select");\n
          result[field_json.subfield_timezone_key] = select.options[select.selectedIndex].value;\n
        }\n
      } else {\n
        //if no value, return empty data\n
        if (field_json.date_only === 0) {\n
          result[field_json.subfield_hour_key] = "";\n
          result[field_json.subfield_minute_key] = "";\n
        }\n
        result[field_json.subfield_year_key] = "";\n
        result[field_json.subfield_month_key] = "";\n
        result[field_json.subfield_day_key] = "";\n
      }\n
      return result;\n
    })\n
    .declareMethod(\'checkValidity\', function () {\n
      var gadget = this,\n
        valide = true,\n
        start_datetime = false,\n
        end_datetime = false,\n
        datetime_string,\n
        select = gadget.element.querySelector("select"),\n
        datetime,\n
        input = gadget.element.querySelector(\'input\'),\n
        field_json = gadget.props.field_json;\n
      if (!input.checkValidity()) {\n
        return false;\n
      }\n
      return new RSVP.Queue()\n
        .push(function () {\n
          return gadget.notifyValid();\n
        })\n
        .push(function () {\n
          return gadget.getContent();\n
        })\n
        .push(function (result) {\n
          datetime_string = result[field_json.subfield_month_key];\n
          datetime_string += "," + result[field_json.subfield_day_key];\n
          datetime_string += "," + result[field_json.subfield_year_key];\n
          if (field_json.date_only === 0) {\n
            if (result[field_json.subfield_ampm_key] === "pm") {\n
              result[field_json.subfield_hour_key] += 12;\n
            }\n
            datetime_string += " " + result[field_json.subfield_hour_key];\n
            datetime_string += ":" + result[field_json.subfield_minute_key] + ":00";\n
            datetime_string += "+0000";\n
          }\n
          if (datetime_string.indexOf("NaN") !== -1) {\n
            valide = false;\n
            return gadget.notifyInvalid("Invalide DateTime");\n
          }\n
          if (field_json.start_datetime) {\n
            start_datetime = Date.parse(field_json.start_datetime);\n
          }\n
          if (field_json.end_datetime) {\n
            end_datetime = Date.parse(field_json.end_datetime);\n
          }\n
          if ((start_datetime === false) && (end_datetime === false)) {\n
            return;\n
          }\n
          datetime = Date.parse(datetime_string);\n
          datetime -= (select.selectedIndex - 12) * 60 * 60 * 1000;\n
          if (start_datetime) {\n
            if (start_datetime > datetime) {\n
              valide = false;\n
              return gadget.notifyInvalid("The date and time you entered earlier than the start time");\n
            }\n
          }\n
          if (end_datetime) {\n
            if (end_datetime <= datetime) {\n
              valide = false;\n
              return gadget.notifyInvalid("The date and time you entered later than the end time");\n
            }\n
          }\n
        })\n
        .push(function () {\n
          return valide;\n
        });\n
    })\n
     .declareService(function () {\n
      ////////////////////////////////////\n
      // Inform when the field input is invalid\n
      ////////////////////////////////////\n
      var field_gadget = this;\n
\n
      function notifyInvalid(evt) {\n
        return field_gadget.notifyInvalid(evt.target.validationMessage);\n
      }\n
\n
      // Listen to input change\n
      return loopEventListener(\n
        field_gadget.element.querySelector(\'input\'),\n
        \'invalid\',\n
        false,\n
        notifyInvalid\n
      );\n
    });\n
\n
}(window, rJS, RSVP, document, loopEventListener));

]]></string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Gadget ERP5 Datetimefield JS</string> </value>
        </item>
        <item>
            <key> <string>version</string> </key>
            <value> <string>001</string> </value>
        </item>
        <item>
            <key> <string>workflow_history</string> </key>
            <value>
              <persistent> <string encoding="base64">AAAAAAAAAAI=</string> </persistent>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="2" aka="AAAAAAAAAAI=">
    <pickle>
      <global name="PersistentMapping" module="Persistence.mapping"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>data</string> </key>
            <value>
              <dictionary>
                <item>
                    <key> <string>document_publication_workflow</string> </key>
                    <value>
                      <persistent> <string encoding="base64">AAAAAAAAAAM=</string> </persistent>
                    </value>
                </item>
                <item>
                    <key> <string>edit_workflow</string> </key>
                    <value>
                      <persistent> <string encoding="base64">AAAAAAAAAAQ=</string> </persistent>
                    </value>
                </item>
                <item>
                    <key> <string>processing_status_workflow</string> </key>
                    <value>
                      <persistent> <string encoding="base64">AAAAAAAAAAU=</string> </persistent>
                    </value>
                </item>
              </dictionary>
            </value>
        </item>
      </dictionary>
    </pickle>
  </record>
  <record id="3" aka="AAAAAAAAAAM=">
    <pickle>
      <global name="WorkflowHistoryList" module="Products.ERP5Type.patches.WorkflowTool"/>
    </pickle>
    <pickle>
      <tuple>
        <none/>
        <list>
          <dictionary>
            <item>
                <key> <string>action</string> </key>
                <value> <string>publish_alive</string> </value>
            </item>
            <item>
                <key> <string>actor</string> </key>
                <value> <string>romain</string> </value>
            </item>
            <item>
                <key> <string>comment</string> </key>
                <value> <string></string> </value>
            </item>
            <item>
                <key> <string>error_message</string> </key>
                <value> <string></string> </value>
            </item>
            <item>
                <key> <string>time</string> </key>
                <value>
                  <object>
                    <klass>
                      <global name="DateTime" module="DateTime.DateTime"/>
                    </klass>
                    <tuple>
                      <none/>
                    </tuple>
                    <state>
                      <tuple>
                        <float>1423152745.26</float>
                        <string>GMT</string>
                      </tuple>
                    </state>
                  </object>
                </value>
            </item>
            <item>
                <key> <string>validation_state</string> </key>
                <value> <string>published_alive</string> </value>
            </item>
          </dictionary>
        </list>
      </tuple>
    </pickle>
  </record>
  <record id="4" aka="AAAAAAAAAAQ=">
    <pickle>
      <global name="WorkflowHistoryList" module="Products.ERP5Type.patches.WorkflowTool"/>
    </pickle>
    <pickle>
      <tuple>
        <none/>
        <list>
          <dictionary>
            <item>
                <key> <string>action</string> </key>
                <value> <string>edit</string> </value>
            </item>
            <item>
                <key> <string>actor</string> </key>
                <value> <string>zope</string> </value>
            </item>
            <item>
                <key> <string>comment</string> </key>
                <value>
                  <none/>
                </value>
            </item>
            <item>
                <key> <string>error_message</string> </key>
                <value> <string></string> </value>
            </item>
            <item>
                <key> <string>serial</string> </key>
                <value> <string>949.15487.9675.47530</string> </value>
            </item>
            <item>
                <key> <string>state</string> </key>
                <value> <string>current</string> </value>
            </item>
            <item>
                <key> <string>time</string> </key>
                <value>
                  <object>
                    <klass>
                      <global name="DateTime" module="DateTime.DateTime"/>
                    </klass>
                    <tuple>
                      <none/>
                    </tuple>
                    <state>
                      <tuple>
                        <float>1455899218.47</float>
                        <string>UTC</string>
                      </tuple>
                    </state>
                  </object>
                </value>
            </item>
          </dictionary>
        </list>
      </tuple>
    </pickle>
  </record>
  <record id="5" aka="AAAAAAAAAAU=">
    <pickle>
      <global name="WorkflowHistoryList" module="Products.ERP5Type.patches.WorkflowTool"/>
    </pickle>
    <pickle>
      <tuple>
        <none/>
        <list>
          <dictionary>
            <item>
                <key> <string>action</string> </key>
                <value> <string>detect_converted_file</string> </value>
            </item>
            <item>
                <key> <string>actor</string> </key>
                <value> <string>romain</string> </value>
            </item>
            <item>
                <key> <string>comment</string> </key>
                <value> <string></string> </value>
            </item>
            <item>
                <key> <string>error_message</string> </key>
                <value> <string></string> </value>
            </item>
            <item>
                <key> <string>external_processing_state</string> </key>
                <value> <string>converted</string> </value>
            </item>
            <item>
                <key> <string>serial</string> </key>
                <value> <string>0.0.0.0</string> </value>
            </item>
            <item>
                <key> <string>time</string> </key>
                <value>
                  <object>
                    <klass>
                      <global name="DateTime" module="DateTime.DateTime"/>
                    </klass>
                    <tuple>
                      <none/>
                    </tuple>
                    <state>
                      <tuple>
                        <float>1423152685.03</float>
                        <string>GMT</string>
                      </tuple>
                    </state>
                  </object>
                </value>
            </item>
          </dictionary>
        </list>
      </tuple>
    </pickle>
  </record>
</ZopeData>
