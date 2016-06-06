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
            <value> <string>gadget_officejs_drive_jio.js</string> </value>
        </item>
        <item>
            <key> <string>description</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>gadget_drive_officejs_jio_js</string> </value>
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

/*global window, rJS, jIO, alert, XMLHttpRequestProgressEvent, UriTemplate */\n
/*jslint indent: 2, maxerr: 3 */\n
(function (window, rJS, jIO, alert, XMLHttpRequestProgressEvent, UriTemplate) {\n
  "use strict";\n
\n
  // jIO call wrapper for redirection to authentication page if needed\n
  function wrapJioCall(gadget, method_name, argument_list) {\n
    var storage = gadget.state_parameter_dict.jio_storage;\n
    return storage[method_name].apply(storage, argument_list)\n
      .push(undefined, function (error) {\n
        if (error instanceof XMLHttpRequestProgressEvent &&\n
            error.target.status === 401) {\n
          if (gadget.state_parameter_dict.jio_storage_name === "erp5") {\n
            return gadget.redirect({ page: "login" });\n
          }\n
          if (gadget.state_parameter_dict.jio_storage_name === "dav") {\n
            var regexp = /^Nayookie login_url=(http[s]?:\\/\\/[\\/\\-\\[\\]{}()*+=:?&.,\\\\\\^$|#\\s\\w%]+)$/,\n
              auth_page = error.target.getResponseHeader(\'WWW-Authenticate\'),\n
              site;\n
            if (regexp.test(auth_page)) {\n
              site = UriTemplate.parse(\n
                regexp.exec(auth_page)[1]\n
              ).expand({back_url: window.location.href,\n
                        origin: window.location.protocol + \'//\' +\n
                                window.location.host});\n
              return gadget.redirect({ toExternal: true, url: site });\n
            }\n
          }\n
        } else if (gadget.state_parameter_dict.jio_storage_name === "dav" &&\n
                 error instanceof XMLHttpRequestProgressEvent &&\n
                 error.target.status === 0) {\n
          // XXX: need more precision, not all errors with 0 status should be redirected...\n
          alert("Unable to access the WebDAV server. It may have an invalid" +\n
                " SSL certificate, or is just not running.\\n" +\n
                "You will be redirected to this server...");\n
          return gadget.redirect({ toExternal: true,\n
                                   url: gadget.state_parameter_dict.jio_storage_url +\n
                                        \'/../redirect?back_url=\' + window.location.href\n
                                 });\n
        }\n
        throw error;\n
      });\n
  }\n
\n
  rJS(window)\n
\n
    .ready(function (gadget) {\n
      // Initialize the gadget local parameters\n
      // XXX Hardcoded\n
      gadget.state_parameter_dict = {jio_storage_name: "dav", // "erp5"\n
                                     jio_storage_url: "https://localhost:5000/webdav"}; // for ERP5: <instance>/web_site_module/hateoas/\n
    })\n
\n
    .declareAcquiredMethod("redirect", "redirect")\n
    .declareAcquiredMethod("getSetting", "getSetting")\n
\n
    .declareMethod(\'createJio\', function (jio_options) {\n
      jio_options = {\n
        type: \'daverp5mapping\',\n
        sub_storage: {\n
          type: this.state_parameter_dict.jio_storage_name,\n
          url: this.state_parameter_dict.jio_storage_url,\n
          with_credentials: true, // webdav\n
          default_view_reference: \'view\' // erp5\n
        }\n
      };\n
      this.state_parameter_dict.jio_storage = jIO.createJIO(jio_options);\n
    })\n
    .declareMethod(\'allDocs\', function () {\n
      return wrapJioCall(this, \'allDocs\', arguments);\n
    })\n
    .declareMethod(\'allAttachments\', function () {\n
      return wrapJioCall(this, \'allAttachments\', arguments);\n
    })\n
    .declareMethod(\'get\', function () {\n
      return wrapJioCall(this, \'get\', arguments);\n
    })\n
    .declareMethod(\'put\', function () {\n
      return wrapJioCall(this, \'put\', arguments);\n
    })\n
    .declareMethod(\'post\', function () {\n
      return wrapJioCall(this, \'post\', arguments);\n
    })\n
    .declareMethod(\'remove\', function () {\n
      return wrapJioCall(this, \'remove\', arguments);\n
    })\n
    .declareMethod(\'getAttachment\', function () {\n
      return wrapJioCall(this, \'getAttachment\', arguments);\n
    })\n
    .declareMethod(\'putAttachment\', function () {\n
      return wrapJioCall(this, \'putAttachment\', arguments);\n
    })\n
    .declareMethod(\'removeAttachment\', function () {\n
      return wrapJioCall(this, \'removeAttachment\', arguments);\n
    })\n
    .declareMethod(\'repair\', function () {\n
      return wrapJioCall(this, \'repair\', arguments);\n
    });\n
\n
}(window, rJS, jIO, alert, XMLHttpRequestProgressEvent, UriTemplate));

]]></string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>OfficeJS Drive Jio Gadget JS</string> </value>
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
                <value> <string>zope</string> </value>
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
                        <float>1451481239.72</float>
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
                <value> <string>949.20746.21257.48042</string> </value>
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
                        <float>1456138293.9</float>
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
                <value> <string>zope</string> </value>
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
                        <float>1451481208.9</float>
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
