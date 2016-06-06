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
            <value> <string>gadget_webrtc.js</string> </value>
        </item>
        <item>
            <key> <string>description</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>rjs_gadget_webrtc_js</string> </value>
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
            <value> <string>/*jslint indent: 2*/\n
/*global rJS, RSVP, window*/\n
(function (rJS, RSVP, window) {\n
  "use strict";\n
\n
  var RTCPeerConnection = window.RTCPeerConnection || window.mozRTCPeerConnection ||\n
                         window.webkitRTCPeerConnection || window.msRTCPeerConnection,\n
    RTCSessionDescription = window.RTCSessionDescription || window.mozRTCSessionDescription ||\n
                           window.webkitRTCSessionDescription || window.msRTCSessionDescription;\n
\n
  function enqueueDefer(gadget, callback) {\n
    var deferred = gadget.props.current_deferred;\n
\n
    // Unblock queue\n
    if (deferred !== undefined) {\n
      deferred.resolve("Another event added");\n
    }\n
\n
    // Add next callback\n
    try {\n
      gadget.props.service_queue.push(callback);\n
    } catch (error) {\n
      throw new Error("Connection gadget already crashed... " +\n
                      gadget.props.service_queue.rejectedReason.toString());\n
    }\n
\n
    // Block the queue\n
    deferred = RSVP.defer();\n
    gadget.props.current_deferred = deferred;\n
    gadget.props.service_queue.push(function () {\n
      return deferred.promise;\n
    });\n
\n
  }\n
\n
  function deferOnIceCandidate(candidate) {\n
    var gadget = this;\n
    enqueueDefer(gadget, function () {\n
      // Firing this callback with a null candidate indicates that\n
      // trickle ICE gathering has finished, and all the candidates\n
      // are now present in pc.localDescription.  Waiting until now\n
      // to create the answer saves us from having to send offer +\n
      // answer + iceCandidates separately.\n
      if (candidate.candidate === null) {\n
        return gadget.notifyDescriptionCalculated(JSON.stringify(gadget.props.connection.localDescription));\n
      }\n
    });\n
  }\n
\n
  function deferDataChannelOnOpen() {\n
    var gadget = this;\n
    enqueueDefer(gadget, function () {\n
      return gadget.notifyDataChannelOpened();\n
    });\n
  }\n
\n
  function deferDataChannelOnClose() {\n
    var gadget = this;\n
    enqueueDefer(gadget, function () {\n
      return gadget.notifyDataChannelClosed();\n
    });\n
  }\n
\n
  function deferDataChannelOnMessage(evt) {\n
    var gadget = this;\n
    enqueueDefer(gadget, function () {\n
      return gadget.notifyDataChannelMessage(evt.data);\n
//         var data = JSON.parse(evt.data);\n
//         console.log(data.message);\n
    });\n
  }\n
\n
  function deferServerDisconnection(gadget) {\n
    enqueueDefer(gadget, function () {\n
      // Try to auto connection\n
      if (gadget.props.connection !== undefined) {\n
        gadget.props.connection.disconnect();\n
        delete gadget.props.connection;\n
      }\n
    });\n
  }\n
\n
//   function deferOfferSuccessCallback(description) {\n
//     var gadget = this;\n
//     enqueueDefer(gadget, function () {\n
//       gadget.props.connection.setLocalDescription(description);\n
//     });\n
//   }\n
\n
  function deferErrorHandler(error) {\n
    enqueueDefer(this, function () {\n
      throw error;\n
    });\n
  }\n
\n
  function deferServerConnection(gadget) {\n
    deferServerDisconnection(gadget);\n
\n
  }\n
\n
  function listenToChannelEvents(gadget) {\n
    gadget.props.channel.onopen = deferDataChannelOnOpen.bind(gadget);\n
    gadget.props.channel.onclose = deferDataChannelOnClose.bind(gadget);\n
    gadget.props.channel.onmessage = deferDataChannelOnMessage.bind(gadget);\n
    gadget.props.channel.onerror = deferErrorHandler.bind(gadget);\n
  }\n
\n
  rJS(window)\n
    .ready(function (g) {\n
      g.props = {};\n
    })\n
\n
    .declareAcquiredMethod(\'notifyDescriptionCalculated\',\n
                           \'notifyDescriptionCalculated\')\n
    .declareAcquiredMethod(\'notifyDataChannelOpened\',\n
                           \'notifyDataChannelOpened\')\n
    .declareAcquiredMethod(\'notifyDataChannelMessage\',\n
                           \'notifyDataChannelMessage\')\n
    .declareAcquiredMethod(\'notifyDataChannelClosed\',\n
                           \'notifyDataChannelClosed\')\n
\n
    .declareService(function () {\n
      /////////////////////////\n
      // Handle WebRTC connection\n
      /////////////////////////\n
      var context = this;\n
\n
      context.props.service_queue = new RSVP.Queue();\n
      deferServerConnection(context);\n
\n
      return new RSVP.Queue()\n
        .push(function () {\n
          return context.props.service_queue;\n
        })\n
        .push(function () {\n
          // XXX Handle cancellation\n
          throw new Error("Service should not have been stopped!");\n
        })\n
        .push(undefined, function (error) {\n
          // Always disconnect in case of error\n
          if (context.props.connection !== undefined) {\n
            context.props.connection.close();\n
          }\n
          throw error;\n
        });\n
    })\n
\n
\n
    .declareMethod(\'createConnection\', function (configuration, constraints) {\n
      this.props.connection = new RTCPeerConnection(configuration, constraints);\n
      this.props.connection.onicecandidate = deferOnIceCandidate.bind(this);\n
      var context = this;\n
      this.props.connection.ondatachannel = function (evt) {\n
        context.props.channel = evt.channel;\n
        listenToChannelEvents(context);\n
      };\n
    })\n
\n
    .declareMethod(\'createDataChannel\', function (title, options) {\n
      // XXX Improve to support multiple data channel\n
      this.props.channel = this.props.connection.createDataChannel(title, options);\n
      listenToChannelEvents(this);\n
      // console.log("Channel type: " + this.props.channel.binarytype);\n
    })\n
\n
    .declareMethod(\'createOffer\', function (constraints) {\n
      var gadget = this;\n
      return new RSVP.Promise(function (resolve, reject) {\n
        gadget.props.connection.createOffer(\n
          resolve,\n
          reject,\n
          constraints\n
        );\n
      });\n
    })\n
\n
    .declareMethod(\'setRemoteDescription\', function (description) {\n
      var gadget = this;\n
      return new RSVP.Promise(function (resolve, reject) {\n
        gadget.props.connection.setRemoteDescription(\n
          new RTCSessionDescription(JSON.parse(description)),\n
          resolve,\n
          reject\n
        );\n
      });\n
    })\n
\n
    .declareMethod(\'setLocalDescription\', function (description) {\n
      var gadget = this;\n
      return new RSVP.Promise(function (resolve, reject) {\n
        gadget.props.connection.setLocalDescription(\n
          new RTCSessionDescription(description),\n
          resolve,\n
          reject\n
        );\n
      });\n
    })\n
\n
    .declareMethod(\'createAnswer\', function (constraints) {\n
      var gadget = this;\n
      return new RSVP.Promise(function (resolve, reject) {\n
        gadget.props.connection.createAnswer(\n
          resolve,\n
          reject,\n
          constraints\n
        );\n
      });\n
    })\n
\n
    .declareMethod(\'send\', function (message) {\n
      this.props.channel.send(message);\n
    })\n
\n
    .declareMethod(\'close\', function () {\n
      // XXX Of course, this will fail if connection is not open yet...\n
      this.props.channel.close();\n
      this.props.connection.close();\n
      delete this.props.channel;\n
      delete this.props.connection;\n
    });\n
\n
}(rJS, RSVP, window));\n
</string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>WebRTC Gadget JS</string> </value>
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
                        <float>1439905919.9</float>
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
                <value> <string>romain</string> </value>
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
                <value> <string>945.18239.14794.40840</string> </value>
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
                        <float>1440432050.86</float>
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
                        <float>1439905128.27</float>
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
