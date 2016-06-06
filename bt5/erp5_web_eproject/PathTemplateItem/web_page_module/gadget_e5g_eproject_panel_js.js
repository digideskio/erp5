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
            <value> <string>gadget_e5g_eproject_panel.js</string> </value>
        </item>
        <item>
            <key> <string>description</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>gadget_e5g_eproject_panel_js</string> </value>
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

/*jslint nomen: true, indent: 2, maxerr: 3 */\n
/*global window, rJS, Handlebars, jQuery, RSVP, loopEventListener */\n
(function (window, rJS, Handlebars, $, RSVP, loopEventListener) {\n
  "use strict";\n
\n
  /////////////////////////////////////////////////////////////////\n
  // temlates\n
  /////////////////////////////////////////////////////////////////\n
  // Precompile templates while loading the first gadget instance\n
  var gadget_klass = rJS(window),\n
    source_header = gadget_klass.__template_element\n
                         .getElementById("panel-template-header")\n
                         .innerHTML,\n
    panel_template_header = Handlebars.compile(source_header),\n
    source_body = gadget_klass.__template_element\n
                         .getElementById("panel-template-body")\n
                         .innerHTML,\n
    panel_template_body = Handlebars.compile(source_body);\n
\n
  gadget_klass\n
\n
    /////////////////////////////////////////////////////////////////\n
    // ready\n
    /////////////////////////////////////////////////////////////////\n
    // Init local properties\n
    .ready(function (g) {\n
      g.props = {};\n
    })\n
\n
    //////////////////////////////////////////////\n
    // acquired method\n
    //////////////////////////////////////////////\n
    .declareAcquiredMethod("translateHtml", "translateHtml")\n
    .declareAcquiredMethod("changeLanguage", "changeLanguage")\n
    .declareAcquiredMethod("getLanguageList", "getLanguageList")\n
    .declareAcquiredMethod(\n
      "whoWantToDisplayThisFrontPage",\n
      "whoWantToDisplayThisFrontPage"\n
    )\n
\n
    // Assign the element to a variable\n
    .ready(function (g) {\n
      return g.getElement()\n
        .push(function (element) {\n
          g.props.element = element;\n
          g.props.jelement = $(element.querySelector("div"));\n
        });\n
    })\n
\n
    .ready(function (g) {\n
      g.props.jelement.panel({\n
        display: "overlay",\n
        position: "left",\n
        theme: "d"\n
        // animate: false\n
      });\n
    })\n
\n
    .ready(function (g) {\n
      return new RSVP.Queue()\n
        .push(function () {\n
          return RSVP.all([\n
            g.whoWantToDisplayThisFrontPage("front"),\n
            g.whoWantToDisplayThisFrontPage("history"),\n
            g.getLanguageList()\n
          ]);\n
        })\n
        .push(function (all_result) {\n
          var raw_language_list = JSON.parse(all_result[2]),\n
            len = raw_language_list.length,\n
            i,\n
            i_len,\n
            language_list,\n
            tmp;\n
\n
          // XXX: Customize panel header!\n
          tmp = panel_template_header();\n
\n
          // languages\n
          if (len > 0) {\n
            language_list = [];\n
            for (i = 0, i_len = len; i < i_len; i += 1) {\n
              language_list.push({"count": i, "lang": language_list[i]});\n
            }\n
          }\n
\n
          tmp += panel_template_body({\n
            "module_href": all_result[0],\n
            "history_href": all_result[1],\n
            "language_list": language_list\n
          });\n
          return tmp;\n
        })\n
        .push(function (my_translated_or_plain_html) {\n
          g.props.jelement.html(my_translated_or_plain_html);\n
          g.props.jelement.trigger("create");\n
        });\n
    })\n
\n
    /////////////////////////////////////////////////////////////////\n
    // declared methods\n
    /////////////////////////////////////////////////////////////////\n
    .declareMethod(\'toggle\', function () {\n
      this.props.jelement.panel("toggle");\n
    })\n
\n
    .declareMethod(\'render\', function () {\n
      var panel_gadget = this;\n
\n
      if (panel_gadget.props.set_search === true) {\n
        return panel_gadget;\n
      }\n
\n
      return new RSVP.Queue()\n
        .push(function () {\n
          return panel_gadget.declareGadget("gadget_erp5_searchfield.html", {\n
            "scope": "search"\n
          });\n
        })\n
        .push(function (my_search_gadget) {\n
          var parent_node, search_option_dict = {};\n
\n
          panel_gadget.props.set_search = true;\n
\n
          // XXX disable for now\n
          search_option_dict.disabled = true;\n
          search_option_dict.theme = "d";\n
          search_option_dict.extended_search = "";\n
          parent_node = panel_gadget.__element.querySelector(".ui-content");\n
\n
          parent_node.insertBefore(\n
            my_search_gadget.__element,\n
            parent_node.firstChild\n
          );\n
          return my_search_gadget.render(search_option_dict);\n
        })\n
        .push(function () {\n
          return panel_gadget;\n
        });\n
    })\n
\n
    /////////////////////////////////////////////////////////////////\n
    // declared services\n
    /////////////////////////////////////////////////////////////////\n
    .declareService(function () {\n
      var panel_gadget,\n
        form_list,\n
        event_list,\n
        handler,\n
        i,\n
        len;\n
\n
      function translate(my_event) {\n
        return panel_gadget.changeLanguage(my_event.target.lang.value);\n
      }\n
\n
      function formSubmit() {\n
        panel_gadget.toggle();\n
      }\n
\n
      panel_gadget = this;\n
      form_list = panel_gadget.props.element.querySelectorAll(\'form\');\n
      event_list = [];\n
      handler = [formSubmit];\n
\n
      // XXX: not robust - Will break when search field is active\n
      for (i = 0, len = form_list.length; i < len; i += 1) {\n
        event_list[i] = loopEventListener(\n
          form_list[i],\n
          \'submit\',\n
          false,\n
          handler[i] || translate\n
        );\n
      }\n
\n
      return new RSVP.Queue()\n
        .push(function () {\n
          return RSVP.all(event_list);\n
        });\n
    });\n
\n
}(window, rJS, Handlebars, jQuery, RSVP, loopEventListener));\n


]]></string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Gadget E5G Eproject Panel JS</string> </value>
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
                <value> <string>publish</string> </value>
            </item>
            <item>
                <key> <string>actor</string> </key>
                <value> <string>sven</string> </value>
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
                        <float>1428487373.54</float>
                        <string>GMT</string>
                      </tuple>
                    </state>
                  </object>
                </value>
            </item>
            <item>
                <key> <string>validation_state</string> </key>
                <value> <string>published</string> </value>
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
                <value> <string>943.10881.65296.43776</string> </value>
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
                        <float>1432213723.7</float>
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
                <value> <string>sven</string> </value>
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
                        <float>1428487332.24</float>
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
