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
            <value> <string>gadget_interface.js</string> </value>
        </item>
        <item>
            <key> <string>description</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>gadget_interface_js</string> </value>
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
/*\n
 * DOMParser HTML extension\n
 * 2012-09-04\n
 *\n
 * By Eli Grey, http://eligrey.com\n
 * Public domain.\n
 * NO WARRANTY EXPRESSED OR IMPLIED. USE AT YOUR OWN RISK.\n
 */\n
/*! @source https://gist.github.com/1129031 */\n
(function (DOMParser) {\n
  "use strict";\n
  var DOMParser_proto = DOMParser.prototype,\n
    real_parseFromString = DOMParser_proto.parseFromString;\n
\n
  // Firefox/Opera/IE throw errors on unsupported types\n
  try {\n
    // WebKit returns null on unsupported types\n
    if ((new DOMParser()).parseFromString("", "text/html")) {\n
      // text/html parsing is natively supported\n
      return;\n
    }\n
  } catch (ignore) {}\n
\n
  DOMParser_proto.parseFromString = function (markup, type) {\n
    var result, doc, doc_elt, first_elt;\n
    if (/^\\s*text\\/html\\s*(?:;|$)/i.test(type)) {\n
      doc = document.implementation.createHTMLDocument("");\n
      doc_elt = doc.documentElement;\n
\n
      doc_elt.innerHTML = markup;\n
      first_elt = doc_elt.firstElementChild;\n
\n
      if (doc_elt.childElementCount === 1\n
          && first_elt.localName.toLowerCase() === "html") {\n
        doc.replaceChild(first_elt, doc_elt);\n
      }\n
\n
      result = doc;\n
    } else {\n
      result = real_parseFromString.apply(this, arguments);\n
    }\n
    return result;\n
  };\n
}(DOMParser));\n
\n
/*global window, rJS, RSVP */\n
/*jslint nomen: true, indent: 2, maxerr: 3 */\n
(function (window, rJS, RSVP, DOMParser) {\n
  "use strict";\n
  function ajax(url) {\n
    var xhr;\n
    function resolver(resolve, reject) {\n
      function handler() {\n
        try {\n
          if (xhr.readyState === 0) {\n
            // UNSENT\n
            reject(xhr);\n
          } else if (xhr.readyState === 4) {\n
            // DONE\n
            if ((xhr.status < 200) || (xhr.status >= 300)) {\n
              reject(xhr);\n
            } else {\n
              resolve(xhr);\n
            }\n
          }\n
        } catch (e) {\n
          reject(e);\n
        }\n
      }\n
\n
      xhr = new XMLHttpRequest();\n
      xhr.open("GET", url);\n
      xhr.onreadystatechange = handler;\n
      xhr.setRequestHeader(\'Accept\', \'text/html\');\n
      xhr.withCredentials = true;\n
      xhr.send();\n
    }\n
\n
    function canceller() {\n
      if ((xhr !== undefined) && (xhr.readyState !== xhr.DONE)) {\n
        xhr.abort();\n
      }\n
    }\n
    return new RSVP.Promise(resolver, canceller);\n
  }\n
\n
  function fetchAppcacheData(appcache_url) {\n
    var defer = RSVP.defer();\n
    return new RSVP.Queue()\n
      .push(function() {\n
        return ajax(appcache_url);\n
      })\n
      .push(function(xhr) {\n
        var filename_list = xhr.responseText.split(\'\\n\');\n
        return filename_list;\n
      }, function(error) {\n
        defer.reject(error);\n
        return defer.promise;\n
      });\n
  }\n
\n
  function filterGadgetList(filename_list) {\n
    var html_list = [],\n
      js_list = [],\n
      gadget_list = [],\n
      ext,\n
      file_name,\n
      last_index,\n
      item;\n
    for(item in filename_list) {\n
      last_index = filename_list[item].lastIndexOf(\'.\');\n
      file_name = filename_list[item].substr(0,last_index);\n
      ext = filename_list[item].substr(last_index+1);\n
      if(ext === "html") {\n
        html_list.push(file_name);\n
      } else if(ext === "js") {\n
        js_list.push(file_name);\n
      }\n
    }\n
    for(item in html_list) {\n
      if (js_list.indexOf(html_list[item]) > -1) {\n
        gadget_list.push(html_list[item] + ".html");\n
      }\n
    }\n
    return gadget_list;\n
  }\n
\n
  function generateErrorMessage(error) {\n
    var error_message = \'\';\n
    error_message = error_message\n
                  + error.toString()\n
                  + (error.message !== undefined ? error.message : \'\')\n
                  + (error.status ? error.status.toString() + \' \' : \'\')\n
                  + (error.statusText !== undefined ? error.statusText : \'\');\n
    return error_message;\n
  }\n
\n
  function getInterfaceListFromURL(gadget_url) {\n
    var defer = RSVP.defer();\n
    return new RSVP.Queue()\n
      .push(function() {\n
        return ajax(gadget_url);\n
      })\n
      .push(function(xhr) {\n
        var document_element = (new DOMParser()).parseFromString(xhr.responseText, \'text/html\'),\n
          interface_list = [],\n
          element,\n
          i;\n
        if (document_element.nodeType === 9 && document_element.head !== null) {\n
          for (i = 0; i < document_element.head.children.length; i += 1) {\n
            element = document_element.head.children[i];\n
            if (element.href !== null && element.rel === "http://www.renderjs.org/rel/interface") {\n
              interface_list.push(\n
                renderJS.getAbsoluteURL(element.getAttribute("href"), window.location.href)\n
              );\n
            }\n
          }\n
        }\n
      return interface_list;\n
    }, function(error) {\n
      var message = "Error with loading the gadget data.\\n";\n
      error.message = message + generateErrorMessage(error);\n
      defer.reject(error);\n
      return defer.promise;\n
    });\n
  }\n
\n
  function verifyInterfaceDefinition(interface_url) {\n
    //to verify if interface definition follows the correct template.\n
    var error_message = "Interface definition is incorrect: One or more required tags are missing.",\n
      defer = RSVP.defer();\n
    return new RSVP.Queue()\n
      .push(function () {\n
        return ajax(interface_url);\n
      })\n
      .push(function(xhr) {\n
        var doc = (new DOMParser()).parseFromString(xhr.responseText, \'text/html\').body,\n
          dl_list = doc.getElementsByTagName(\'dl\'),\n
          next_element = dl_list[0].firstElementChild,\n
          method_len = dl_list.length - 1,\n
          i;\n
        if (dl_list[0].childElementCount !== 3*method_len) {\n
          throw new Error(error_message);\n
        }\n
        try {\n
          for (i = 0; i < method_len; i += 1) {\n
            if ((!next_element || next_element.localName.toLowerCase() !== \'dt\') ||\n
              (!(next_element = next_element.nextElementSibling) || next_element.localName.toLowerCase() !== \'dd\') ||\n
              (!(next_element = next_element.nextElementSibling)  || next_element.localName.toLowerCase() !== \'dl\')) {\n
              throw new Error(error_message);\n
            }\n
            if(next_element.getElementsByTagName(\'dt\').length !== next_element.getElementsByTagName(\'dd\').length) {\n
              throw new Error(error_message);\n
            }\n
            var argument_len = next_element.getElementsByTagName(\'dt\').length,\n
              next_child_element = next_element.firstElementChild,\n
              j;\n
            for (j = 0; j < argument_len; j += 1) {\n
              if ((!next_child_element || next_child_element.localName.toLowerCase() !== \'dt\') ||\n
                (!(next_child_element = next_child_element.nextElementSibling) || next_child_element.localName.toLowerCase() !== \'dd\')) {\n
                throw new Error(error_message);\n
              }\n
              next_child_element = next_child_element.nextElementSibling;\n
            }\n
            next_element = next_element.nextElementSibling;\n
          }\n
          defer.resolve("Success");\n
        } catch(error) {\n
          defer.reject(error);\n
        }\n
        return defer.promise;\n
      }, function(error) {\n
        var message = "Error with loading the interface data.\\n";\n
        error.message = message + generateErrorMessage(error);\n
        defer.reject(error);\n
        return defer.promise;\n
      });\n
  }\n
\n
  function verifyInterfaceDeclaration(interface_url, declared_interface_list) {\n
    //to verify if gadget declares the interface.\n
    var defer = RSVP.defer();\n
    try {\n
      if (declared_interface_list.indexOf(interface_url) > -1) {\n
        defer.resolve("Success");\n
      } else {\n
        throw new Error("Interface is not declared.");\n
      }\n
    } catch(error) {\n
      defer.reject(error);\n
    }\n
    return defer.promise;\n
  }\n
\n
  function verifyAllMethod(interface_method_list, gadget_method_list) {\n
    //to verify all methods of gadget and interface.\n
    var defer = RSVP.defer();\n
    return new RSVP.Queue()\n
      .push(function() {\n
        return verifyAllMethodDeclared(interface_method_list, gadget_method_list[0]);\n
      })\n
/*    Commented till figure out the way to fetch the argument length of a defined function.\n
      .push(function() {\n
        return verifyAllMethodSignature(interface_method_list, gadget_method_list[1]);\n
      })\n
*/\n
      .push (function() {\n
        defer.resolve("Success");\n
        return defer.promise;\n
      }, function(error) {\n
        defer.reject(error);\n
        return defer.promise;\n
      });\n
  }\n
\n
  function verifyAllMethodDeclared(interface_method_list, gadget_method_list) {\n
    //to verify if all the interface methods are declared by the gadget.\n
    var defer = RSVP.defer(),\n
      gadget_method_name_list = gadget_method_list,\n
      interface_method_name_list = [],\n
      i, j,\n
      failed = false,\n
      failed_methods = [];\n
    for (i = 0; i < interface_method_list.length; i += 1) {\n
      interface_method_name_list.push(interface_method_list[i].name);\n
    }\n
    try {\n
      for (j = 0; j < interface_method_name_list.length; j += 1) {\n
        if(gadget_method_name_list.indexOf(interface_method_name_list[j]) < 0) {\n
          failed = true;\n
          failed_methods.push(interface_method_name_list[j]);\n
        }\n
      }\n
      if(failed) {\n
        var error_message = "Following required methods are not declared in the gadget: ",\n
          method;\n
        for(method in failed_methods) {\n
          error_message += ("\\n" + failed_methods[method]);\n
        }\n
        throw new Error(error_message);\n
      }\n
      defer.resolve("Success");\n
    } catch(error) {\n
      defer.reject(error);\n
    }\n
    return defer.promise;\n
  }\n
\n
  function verifyAllMethodSignature(interface_method_list, gadget_method_list) {\n
    //to verify if all the declared methods match the signature of the interface methods.\n
    var defer = RSVP.defer(),\n
      interface_method_dict = {},\n
      gadget_method_name_list = [],\n
      index,\n
      item,\n
      i, j,\n
      failed = false,\n
      failed_methods = [];\n
    for(i = 0; i < interface_method_list.length; i += 1) {\n
      interface_method_dict[interface_method_list[i].name] = interface_method_list[i];\n
    }\n
    for(j = 0; j < gadget_method_list.length; j += 1) {\n
      gadget_method_name_list.push(gadget_method_list[j].name);\n
    }\n
    try {\n
      for(item in interface_method_dict) {\n
        index = gadget_method_name_list.lastIndexOf(item);\n
        if(!verifyMethodSignature(interface_method_dict[item], gadget_method_list[index])) {\n
          failed = true;\n
          failed_methods.push(item);\n
        }\n
      }\n
      if(failed) {\n
        var error_message = "Following methods have missing/mismatched arguments: ",\n
          method;\n
        for(method in failed_methods) {\n
          error_message += ("\\n" + failed_methods[method]);\n
        }\n
        throw new Error(error_message);\n
      }\n
      defer.resolve("Success");\n
    } catch(error) {\n
      defer.reject(error);\n
    }\n
    return defer.promise;\n
  }\n
\n
  function verifyMethodSignature(interface_method, gadget_method) {\n
    //to verify if two methods have the same signature\n
    var max_arg_len = interface_method.argument_list.length,\n
      min_arg_len = 0,\n
      i;\n
    if (max_arg_len) {\n
      var argument_list = interface_method.argument_list;\n
      for (i = 0; i < argument_list.length; i += 1) {\n
        if (argument_list[i].required) {\n
          min_arg_len += 1;\n
        }\n
      }\n
    }\n
    return (gadget_method.arg_len >= min_arg_len && gadget_method.arg_len <= max_arg_len);\n
  }\n
\n
  rJS(window)\n
    .ready(function (g) {\n
      g.props = {};\n
    })\n
\n
    .declareMethod("getVerifyGadget", function (gadget_url) {\n
      var interface_gadget = this,\n
        defer = RSVP.defer();\n
      return new RSVP.Queue()\n
        .push(function () {\n
          return interface_gadget.declareGadget(gadget_url, {\n
            scope: gadget_url\n
          });\n
        })\n
        .push(function () {\n
          return interface_gadget.getDeclaredGadget(gadget_url);\n
        }, function(error) {\n
          var message = "Error with loading the gadget.\\n";\n
          error.message = message + error.message;\n
          defer.reject(error);\n
          return defer.promise;\n
        });\n
    })\n
\n
    .declareMethod("getDeclaredGadgetInterfaceList", function (gadget_data) {\n
      var interface_gadget = this,\n
        defer = RSVP.defer();\n
      return new RSVP.Queue()\n
        .push(function() {\n
          if(gadget_data.constructor === String) {\n
            return getInterfaceListFromURL(gadget_data);\n
          } else {\n
            return gadget_data.getInterfaceList();\n
          }\n
        })\n
        .push(function(interface_list) {\n
          return interface_list;\n
        }, function(error) {\n
          defer.reject(error);\n
          return defer.promise;\n
        });\n
    })\n
\n
    .declareMethod("getDeclaredGadgetMethodList", function (gadget) {\n
      var declared_method_dict = {},\n
        declared_method_list = [],\n
        item;\n
      for (item in gadget) {\n
        if (!(/__/).test(item)) {\n
          declared_method_dict[item] = gadget[item];\n
        }\n
      }\n
      for(item in declared_method_dict) {\n
        declared_method_list.push(item);\n
      }  \n
      return RSVP.all([\n
        declared_method_list //,\n
        // gadget.getDeclaredMethodList()\n
      ]); \n
    })\n
\n
    .declareMethod("getGadgetListFromAppcache", function (appcache_url) {\n
      var defer = RSVP.defer();\n
      return new RSVP.Queue()\n
        .push(function() {\n
          return fetchAppcacheData(appcache_url);\n
        })\n
        .push(function(filename_list) {\n
          return filterGadgetList(filename_list);\n
        })\n
        .push(function(filtered_gadget_list) {\n
          return filtered_gadget_list;\n
        }, function(error) {\n
          defer.reject(error);\n
          return defer.promise;\n
        });\n
    })\n
\n
    .declareMethod("getAbsoluteURL", function (gadget, url) {\n
      return new RSVP.Queue()\n
        .push(function() {\n
          return gadget.getPath(); \n
        })\n
        .push(function(base_url) {\n
          return rJS.getAbsoluteURL(url, base_url);\n
        });\n
    })\n
\n
    .declareMethod("getInterfaceData", function (interface_url) {\n
      var interface_data = {\n
          name: "",\n
          description: "",\n
          method_list: []\n
        },\n
        defer = RSVP.defer();\n
      return new RSVP.Queue()\n
        .push(function() {\n
          return ajax(interface_url);\n
        })\n
        .push(function(xhr) {\n
          var doc = (new DOMParser()).parseFromString(xhr.responseText, \'text/html\').body,\n
            dl_list = doc.getElementsByTagName(\'dl\'),\n
            dt_list = doc.getElementsByTagName(\'dt\'),\n
            dd_list = doc.getElementsByTagName(\'dd\'),\n
            method_len = dl_list.length - 1,\n
            dt_count = 0,\n
            dl_count = 1,\n
            i;\n
          interface_data.name = doc.getElementsByTagName(\'h1\')[0].innerHTML;\n
          interface_data.description = doc.getElementsByTagName(\'h3\')[0].innerHTML;\n
          for (i = 0; i < method_len; i += 1) {\n
            var method = {\n
                name: dt_list[dt_count].innerHTML,\n
                description: dd_list[dt_count].innerHTML,\n
                argument_list: []\n
              },\n
              argument_len = dl_list[dl_count].getElementsByTagName(\'dt\').length,\n
              j;\n
            dt_count += 1;\n
            dl_count += 1;\n
            for (j = 0; j < argument_len; j += 1) {\n
              var argument_item = {\n
                  name: dt_list[dt_count].innerHTML,\n
                  description: dd_list[dt_count].innerHTML,\n
                  required: dt_list[dt_count].getAttribute("data-parameter-required") === "optional" ? false:true,\n
                  type: dt_list[dt_count].getAttribute("data-parameter-type")\n
                };\n
              dt_count += 1;\n
              method.argument_list.push(argument_item);\n
            }\n
            interface_data.method_list.push(method);\n
          }\n
          return interface_data;\n
        }, function(error) {\n
          var message = "Error with loading the interface data.\\n";\n
          error.message = message + generateErrorMessage(error);\n
          defer.reject(error);\n
          return defer.promise;\n
      });\n
    })\n
\n
    .declareMethod("getDefinedInterfaceMethodList", function (interface_url) {\n
      var defer = RSVP.defer();\n
      return this.getInterfaceData(interface_url)\n
        .push(function(interface_data) {\n
          return interface_data.method_list;\n
        }, function(error) {\n
          defer.reject(error);\n
          return defer.promise;\n
        });\n
    })\n
\n
    .declareMethod("getGadgetListImplementingInterface", function (interface_data, gadget_source_data) {\n
      var interface_gadget = this,\n
        interface_list,\n
        gadget_list;\n
      return new RSVP.Queue()\n
        .push(function () {\n
          var required_interface_list = [];\n
          if(!interface_data) {\n
            throw new Error("Invalid input: No interface data is provided.");\n
          } else if(interface_data.constructor === Array) {\n
            required_interface_list = interface_data;\n
          } else if(interface_data.constructor === String) {\n
            required_interface_list.push(interface_data);\n
          } else {\n
            throw new Error("Invalid input: Invalid interface data is provided.");\n
          }\n
          return required_interface_list;\n
        })\n
        .push(function (i_list) {\n
          var source_gadget_list = [];\n
          interface_list = i_list;\n
          if(!gadget_source_data) {\n
            throw new Error("Invalid input: No gadget source information is provided.");\n
          } else if(gadget_source_data.constructor === Array) {\n
            source_gadget_list = gadget_source_data;\n
          } else if(gadget_source_data.constructor === String) {\n
            source_gadget_list = interface_gadget.getGadgetListFromAppcache(gadget_source_data);\n
          } else {\n
            throw new Error("Invalid input: Invalid gadget source information is provided.");\n
          }\n
          return source_gadget_list;\n
        })\n
        .push(function (g_list) {\n
          var item,\n
            result_list = [];\n
          gadget_list = g_list;\n
          for (item in gadget_list) {\n
            result_list.push(interface_gadget.verifyGadgetInterfaceImplementation(gadget_list[item], interface_list));\n
          }\n
          return RSVP.all(result_list);\n
        })\n
        .push(function(result_list) {\n
          var item,\n
            result_gadget_list = [];\n
          for(item in result_list) {\n
            if (result_list[item].result === true) {\n
              result_gadget_list.push(gadget_list[item]);\n
            }\n
          }\n
          return result_gadget_list;\n
        });\n
    })\n
\n
    .declareMethod("verifyGadgetSingleInterfaceImplementation", function (verify_gadget, interface_url) {\n
      var interface_gadget = this,\n
        absolute_interface_url,\n
        verify_result = {};\n
      return new RSVP.Queue()\n
        .push(function () {\n
          return RSVP.all([ \n
            interface_gadget.getDeclaredGadgetInterfaceList(verify_gadget),\n
            interface_gadget.getAbsoluteURL(verify_gadget, interface_url)\n
          ]);\n
        })\n
        .push(function (interface_detail) {\n
          var declared_interface_list = interface_detail[0];\n
          absolute_interface_url = interface_detail[1];\n
          return verifyInterfaceDeclaration(absolute_interface_url, declared_interface_list);\n
        })\n
        .push(function () {\n
          return verifyInterfaceDefinition(absolute_interface_url);\n
        })\n
        .push(function () {\n
          return RSVP.all([\n
            interface_gadget.getDefinedInterfaceMethodList(absolute_interface_url),\n
            interface_gadget.getDeclaredGadgetMethodList(verify_gadget)\n
          ]);\n
        })\n
        .push(function(method_list) {\n
          return verifyAllMethod(method_list[0], method_list[1]);\n
        })\n
        .push(function() {\n
          verify_result.result = true;\n
          return verify_result;\n
        }, function(error) {\n
          var interface_name = absolute_interface_url.substr(absolute_interface_url.lastIndexOf(\'/\')+1),\n
            error_message;\n
          error_message = "Interface Name: " + interface_name + "\\n"\n
                        + "Error Details : \\n" + error.message + "\\n"; \n
          verify_result.result = false;\n
          verify_result.details = error_message;\n
          return verify_result;\n
        });\n
    })\n
\n
    .declareMethod("verifyGadgetInterfaceImplementation", function (gadget_data, interface_data) {\n
      var interface_gadget = this,\n
        verify_gadget,\n
        interface_list,\n
        verify_result = {},\n
        declared_gadget = false;\n
      return new RSVP.Queue()\n
        .push(function () {\n
          var required_gadget;\n
          if(!gadget_data) {\n
            throw new Error("Invalid input: No gadget data is provided.");\n
          } else if(gadget_data.constructor === String) {\n
            verify_result.gadget_url = gadget_data;\n
            declared_gadget = true;\n
            required_gadget = interface_gadget.getVerifyGadget(gadget_data);\n
          } else {\n
            required_gadget = gadget_data;\n
          }\n
          return required_gadget;\n
        })\n
        .push(function (required_gadget) {\n
          var required_interface_list = [];\n
          verify_gadget = required_gadget;\n
          if(!interface_data) {\n
            required_interface_list = interface_gadget.getDeclaredGadgetInterfaceList(verify_gadget);\n
          } else if(interface_data.constructor === Array) {\n
            required_interface_list = interface_data;\n
          } else if(interface_data.constructor === String) {\n
            required_interface_list.push(interface_data);\n
          }\n
          return required_interface_list;\n
        })\n
        .push(function (required_interface_list) {\n
          var interface_url,\n
            result_list = [],\n
            item;\n
          interface_list = required_interface_list;\n
          for (item in interface_list) {\n
            interface_url = interface_list[item];\n
            result_list.push(interface_gadget.verifyGadgetSingleInterfaceImplementation(verify_gadget, interface_url));\n
          }\n
          return RSVP.all(result_list);\n
        })\n
        .push(function(result_list) {\n
          var item,\n
            failed = false,\n
            error_message = \'\';\n
          for(item in result_list) {\n
            if (!result_list[item].result) {\n
              failed = true;\n
              error_message += (result_list[item].details + \'\\n\');\n
            }\n
          }\n
          if(failed) {\n
            throw new Error(error_message);\n
          }\n
        })\n
        .push (function() {\n
          verify_result.result = true;\n
          return verify_result;\n
        }, function(error) {\n
          verify_result.result = false;\n
          verify_result.details = error.message;\n
          return verify_result;\n
        });\n
    });\n
\n
}(window, rJS, RSVP, DOMParser));

]]></string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>Gadget Interface JS</string> </value>
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
                        <float>1444121210.22</float>
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
                <value> <string>946.46289.58152.58624</string> </value>
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
                        <float>1446475754.4</float>
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
                <value>
                  <none/>
                </value>
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
                        <float>1444121103.94</float>
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
