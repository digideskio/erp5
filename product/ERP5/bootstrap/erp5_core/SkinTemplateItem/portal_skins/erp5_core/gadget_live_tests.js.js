<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="File" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>_EtagSupport__etag</string> </key>
            <value> <string>ts52670931.35</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>gadget_live_tests.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*global window, rJS, jIO, RSVP, location, document, FormData, console */\n
/*jslint indent: 2, maxlen: 80, nomen: true */\n
(function (rJS, jIO, RSVP, window, document, FormData) {\n
  "use strict";\n
  var my_url_run_test = document.baseURI + \'runLiveTest\',\n
    my_url_read_test = document.baseURI + \'readTestOutput\',\n
    paused = false,\n
    data_textarea =\n
      document.querySelector("[name=\'field_your_text_output\']"),\n
    continue_loop = true,\n
    tests_still_running = true,\n
    last_call = false,\n
    data_size = 0,\n
    form_data = new FormData();\n
\n
  data_textarea.value = "";\n
\n
  form_data.append("test_list",\n
    document.querySelector("[name=\'field_your_test\']").value);\n
  form_data.append("run_only",\n
    document.querySelector("[name=\'field_your_run_only\']").value);\n
  form_data.append("debug",\n
    document.querySelector("[name=\'field_your_debug\']").checked ===\n
       true ? 1 : 0);\n
  form_data.append("verbose",\n
    document.querySelector("[name=\'field_your_verbose\']").checked ===\n
       true ? 1 : 0);\n
\n
  // if the user scrolls in the window we do not want it to be updated.\n
  // so set paused flag to false\n
  function scrollFunction() {\n
    paused = data_textarea.scrollHeight - data_textarea.scrollTop !==\n
      data_textarea.clientHeight;\n
    // if the service was paused when the tests are finished,\n
    // set continue_loop to false\n
    if (!paused && !tests_still_running) {\n
      continue_loop = false;\n
    }\n
  }\n
\n
  data_textarea.onscroll = scrollFunction;\n
\n
  rJS(window).declareService(function () {\n
    var queue = new RSVP.Queue();\n
\n
    function launchLiveTest() {\n
      queue.push(function () {\n
        return jIO.util.ajax({\n
          type: "POST",\n
          url: my_url_run_test,\n
          data: form_data\n
        });\n
      }).push(function () {\n
        tests_still_running = false;\n
        // set continue_loop to false ONLY IF the test is not paused.\n
        // Otherwise it will be set when user scrolls to the end\n
        if (!paused) {\n
          continue_loop = false;\n
        }\n
      }, function (error) {\n
        console.error("Error launching live tests", error);\n
      });\n
    }\n
    return queue.push(function () {\n
      return launchLiveTest();\n
    });\n
  }).declareService(function () {\n
    var queue = new RSVP.Queue();\n
\n
    function getLiveTestOutput() {\n
      queue.push(function () {\n
        return jIO.util.ajax({\n
          type: "GET",\n
          url: my_url_read_test\n
        });\n
      }).push(function (evt) {\n
        var data = evt.target.response;\n
        // cut the characters that are already presented\n
        data = data.substring(data_size);\n
        if ((!paused || last_call) && data.length !== undefined) {\n
          // to put the data in the correct place\n
          data_size = data_size + data.length;\n
          // add the new data\n
          data_textarea.value = data_textarea.value + data;\n
          data_textarea.scrollTop = data_textarea.scrollHeight;\n
        }\n
        return RSVP.delay(1000);\n
      }, function (error) {\n
        console.error("Error refreshing live test output", error);\n
      }).push(function () {\n
        if (continue_loop) {\n
          return getLiveTestOutput();\n
        }\n
        if (!continue_loop) {\n
          if (!last_call) {\n
            last_call = true;\n
            return getLiveTestOutput();\n
          }\n
        }\n
      });\n
    }\n
    return queue.push(function () {\n
      // a delay of 2 seconds so the test can be launched\n
      // before results are read\n
      return RSVP.delay(2000);\n
    }).push(getLiveTestOutput());\n
  });\n
}(rJS, jIO, RSVP, window, document, FormData));

]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>3561</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
