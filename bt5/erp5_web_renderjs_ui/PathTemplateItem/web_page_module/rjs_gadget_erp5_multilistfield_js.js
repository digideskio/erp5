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
            <value> <string>gadget_erp5_field_multilist.js</string> </value>
        </item>
        <item>
            <key> <string>description</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>rjs_gadget_erp5_multilistfield_js</string> </value>
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

/*global window, rJS, Handlebars, document, RSVP, loopEventListener*/\n
/*jslint nomen: true, indent: 2, maxerr: 3 */\n
(function (window, rJS, Handlebars, document, RSVP) {\n
  \'use strict\';\n
  /////////////////////////////////////////////////////////////////\n
  // Handlebars\n
  /////////////////////////////////////////////////////////////////\n
  // Precompile the templates while loading the first gadget instance\n
  var gadget_klass = rJS(window),\n
    option_source = gadget_klass.__template_element\n
                      .getElementById("option-template")\n
                      .innerHTML,\n
    option_template = Handlebars.compile(option_source),\n
    selected_option_source = gadget_klass.__template_element\n
                               .getElementById("selected-option-template")\n
                               .innerHTML,\n
    selected_option_template = Handlebars.compile(selected_option_source);\n
  gadget_klass\n
    .ready(function (g) {\n
      g.props = {};\n
    })\n
    // Assign the element to a variable\n
    .ready(function (g) {\n
      return g.getElement()\n
        .push(function (element) {\n
          g.props.element = element;\n
        });\n
    })\n
    .declareAcquiredMethod("translateHtml", "translateHtml")\n
    .declareMethod(\'render\', function (options) {\n
      var gadget = this,\n
        selects = [],\n
        tmp,\n
        template,\n
        container,\n
        field_json = options.field_json,\n
        i,\n
        j;\n
      gadget.props.field_json = field_json;\n
      container = gadget.props.element.querySelector(".ui-controlgroup-controls");\n
      field_json.default[field_json.default.length] = "";\n
      for (i = 0; i < field_json.default.length; i += 1) {\n
        tmp = "";\n
        selects[i] = document.createElement("select");\n
        container.appendChild(selects[i]);\n
        for (j = 0; j < field_json.items.length; j += 1) {\n
          if (field_json.items[j][1] === field_json.default[i]) {\n
            template = selected_option_template;\n
          } else {\n
            template = option_template;\n
          }\n
          tmp += template({\n
            value: field_json.items[j][1],\n
            text: field_json.items[j][0]\n
          });\n
        }\n
        selects[i].innerHTML = tmp;\n
      }\n
      return new RSVP.Queue()\n
        .push(function () {\n
          var list = [];\n
          for (i = 0; i < selects.length; i += 1) {\n
            list.push(gadget.translateHtml(selects[i].outerHTML));\n
          }\n
          return RSVP.all(list);\n
        })\n
        .push(function (translated_htmls) {\n
          var select_div,\n
            wrapper_class_string,\n
            div = document.createElement("div");\n
          for (i = 0; i < translated_htmls.length; i += 1) {\n
            div.innerHTML = translated_htmls[i];\n
            select_div = div.querySelector("select");\n
            selects[i].innerHTML = select_div.innerHTML;\n
            if (field_json.editable !== 1) {\n
              selects[i].setAttribute(\'readonly\', \'readonly\');\n
              wrapper_class_string = wrapper_class_string || "";\n
              wrapper_class_string += \'ui-state-readonly \';\n
            }\n
            // XXX add first + last class, needs to be improved\n
            if (i === 0) {\n
              wrapper_class_string = wrapper_class_string || "";\n
              wrapper_class_string += \'ui-first-child\';\n
            }\n
            if (i === translated_htmls.length - 1) {\n
              wrapper_class_string = wrapper_class_string || "";\n
              wrapper_class_string += \'ui-last-child\';\n
            }\n
            if (wrapper_class_string) {\n
              selects[i].setAttribute(\'data-wrapper-class\', wrapper_class_string);\n
              wrapper_class_string = undefined;\n
            }\n
          }\n
        });\n
    })\n
    .declareMethod(\'getContent\', function () {\n
      var gadget = this,\n
        result = {},\n
        tmp = [],\n
        selects = this.props.element.querySelectorAll(\'select\'),\n
        i;\n
\n
      for (i = 0; i < selects.length; i += 1) {\n
        tmp.push(selects[i].options[selects[i].selectedIndex].value);\n
      }\n
      result[gadget.props.field_json.sub_select_key] = tmp;\n
      result[gadget.props.field_json.sub_input_key] = 0;\n
      return result;\n
    });\n
}(window, rJS, Handlebars, document, RSVP));

]]></string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Gadget ERP5 MultiListField JS</string> </value>
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
                <value> <string>xiaowu</string> </value>
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
                        <float>1423480905.87</float>
                        <string>UTC</string>
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
                <value> <string>xiaowu</string> </value>
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
                <value> <string>944.12751.13272.54476</string> </value>
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
                        <float>1436170826.41</float>
                        <string>GMT+2</string>
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
                <value>
                  <none/>
                </value>
            </item>
            <item>
                <key> <string>actor</string> </key>
                <value> <string>xiaowu</string> </value>
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
                <value> <string>empty</string> </value>
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
                        <float>1423480866.38</float>
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
</ZopeData>
