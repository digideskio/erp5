<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="File" module="OFS.Image"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>_Cacheable__manager_id</string> </key>
            <value> <string>anonymous_http_cache</string> </value>
        </item>
        <item>
            <key> <string>_EtagSupport__etag</string> </key>
            <value> <string>ts52852209.74</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>filesaver.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/* FileSaver.js\n
 * A saveAs() FileSaver implementation.\n
 * 1.1.20151003\n
 *\n
 * By Eli Grey, http://eligrey.com\n
 * License: MIT\n
 *   See https://github.com/eligrey/FileSaver.js/blob/master/LICENSE.md\n
 */\n
\n
/*global self */\n
/*jslint bitwise: true, indent: 4, laxbreak: true, laxcomma: true, smarttabs: true, plusplus: true */\n
\n
/*! @source http://purl.eligrey.com/github/FileSaver.js/blob/master/FileSaver.js */\n
\n
var saveAs = saveAs || (function(view) {\n
  "use strict";\n
  // IE <10 is explicitly unsupported\n
  if (typeof navigator !== "undefined" && /MSIE [1-9]\\./.test(navigator.userAgent)) {\n
    return;\n
  }\n
  var\n
      doc = view.document\n
      // only get URL when necessary in case Blob.js hasn\'t overridden it yet\n
    , get_URL = function() {\n
      return view.URL || view.webkitURL || view;\n
    }\n
    , save_link = doc.createElementNS("http://www.w3.org/1999/xhtml", "a")\n
    , can_use_save_link = "download" in save_link\n
    , click = function(node) {\n
      var event = new MouseEvent("click");\n
      node.dispatchEvent(event);\n
    }\n
    , is_safari = /Version\\/[\\d\\.]+.*Safari/.test(navigator.userAgent)\n
    , webkit_req_fs = view.webkitRequestFileSystem\n
    , req_fs = view.requestFileSystem || webkit_req_fs || view.mozRequestFileSystem\n
    , throw_outside = function(ex) {\n
      (view.setImmediate || view.setTimeout)(function() {\n
        throw ex;\n
      }, 0);\n
    }\n
    , force_saveable_type = "application/octet-stream"\n
    , fs_min_size = 0\n
    // See https://code.google.com/p/chromium/issues/detail?id=375297#c7 and\n
    // https://github.com/eligrey/FileSaver.js/commit/485930a#commitcomment-8768047\n
    // for the reasoning behind the timeout and revocation flow\n
    , arbitrary_revoke_timeout = 500 // in ms\n
    , revoke = function(file) {\n
      var revoker = function() {\n
        if (typeof file === "string") { // file is an object URL\n
          get_URL().revokeObjectURL(file);\n
        } else { // file is a File\n
          file.remove();\n
        }\n
      };\n
      if (view.chrome) {\n
        revoker();\n
      } else {\n
        setTimeout(revoker, arbitrary_revoke_timeout);\n
      }\n
    }\n
    , dispatch = function(filesaver, event_types, event) {\n
      event_types = [].concat(event_types);\n
      var i = event_types.length;\n
      while (i--) {\n
        var listener = filesaver["on" + event_types[i]];\n
        if (typeof listener === "function") {\n
          try {\n
            listener.call(filesaver, event || filesaver);\n
          } catch (ex) {\n
            throw_outside(ex);\n
          }\n
        }\n
      }\n
    }\n
    , auto_bom = function(blob) {\n
      // prepend BOM for UTF-8 XML and text/* types (including HTML)\n
      if (/^\\s*(?:text\\/\\S*|application\\/xml|\\S*\\/\\S*\\+xml)\\s*;.*charset\\s*=\\s*utf-8/i.test(blob.type)) {\n
        return new Blob(["\\ufeff", blob], {type: blob.type});\n
      }\n
      return blob;\n
    }\n
    , FileSaver = function(blob, name, no_auto_bom) {\n
      if (!no_auto_bom) {\n
        blob = auto_bom(blob);\n
      }\n
      // First try a.download, then web filesystem, then object URLs\n
      var\n
          filesaver = this\n
        , type = blob.type\n
        , blob_changed = false\n
        , object_url\n
        , target_view\n
        , dispatch_all = function() {\n
          dispatch(filesaver, "writestart progress write writeend".split(" "));\n
        }\n
        // on any filesys errors revert to saving with object URLs\n
        , fs_error = function() {\n
          if (target_view && is_safari && typeof FileReader !== "undefined") {\n
            // Safari doesn\'t allow downloading of blob urls\n
            var reader = new FileReader();\n
            reader.onloadend = function() {\n
              var base64Data = reader.result;\n
              target_view.location.href = "data:attachment/file" + base64Data.slice(base64Data.search(/[,;]/));\n
              filesaver.readyState = filesaver.DONE;\n
              dispatch_all();\n
            };\n
            reader.readAsDataURL(blob);\n
            filesaver.readyState = filesaver.INIT;\n
            return;\n
          }\n
          // don\'t create more object URLs than needed\n
          if (blob_changed || !object_url) {\n
            object_url = get_URL().createObjectURL(blob);\n
          }\n
          if (target_view) {\n
            target_view.location.href = object_url;\n
          } else {\n
            var new_tab = view.open(object_url, "_blank");\n
            if (new_tab == undefined && is_safari) {\n
              //Apple do not allow window.open, see http://bit.ly/1kZffRI\n
              view.location.href = object_url\n
            }\n
          }\n
          filesaver.readyState = filesaver.DONE;\n
          dispatch_all();\n
          revoke(object_url);\n
        }\n
        , abortable = function(func) {\n
          return function() {\n
            if (filesaver.readyState !== filesaver.DONE) {\n
              return func.apply(this, arguments);\n
            }\n
          };\n
        }\n
        , create_if_not_found = {create: true, exclusive: false}\n
        , slice\n
      ;\n
      filesaver.readyState = filesaver.INIT;\n
      if (!name) {\n
        name = "download";\n
      }\n
      if (can_use_save_link) {\n
        object_url = get_URL().createObjectURL(blob);\n
        setTimeout(function() {\n
          save_link.href = object_url;\n
          save_link.download = name;\n
          click(save_link);\n
          dispatch_all();\n
          revoke(object_url);\n
          filesaver.readyState = filesaver.DONE;\n
        });\n
        return;\n
      }\n
      // Object and web filesystem URLs have a problem saving in Google Chrome when\n
      // viewed in a tab, so I force save with application/octet-stream\n
      // http://code.google.com/p/chromium/issues/detail?id=91158\n
      // Update: Google errantly closed 91158, I submitted it again:\n
      // https://code.google.com/p/chromium/issues/detail?id=389642\n
      if (view.chrome && type && type !== force_saveable_type) {\n
        slice = blob.slice || blob.webkitSlice;\n
        blob = slice.call(blob, 0, blob.size, force_saveable_type);\n
        blob_changed = true;\n
      }\n
      // Since I can\'t be sure that the guessed media type will trigger a download\n
      // in WebKit, I append .download to the filename.\n
      // https://bugs.webkit.org/show_bug.cgi?id=65440\n
      if (webkit_req_fs && name !== "download") {\n
        name += ".download";\n
      }\n
      if (type === force_saveable_type || webkit_req_fs) {\n
        target_view = view;\n
      }\n
      if (!req_fs) {\n
        fs_error();\n
        return;\n
      }\n
      fs_min_size += blob.size;\n
      req_fs(view.TEMPORARY, fs_min_size, abortable(function(fs) {\n
        fs.root.getDirectory("saved", create_if_not_found, abortable(function(dir) {\n
          var save = function() {\n
            dir.getFile(name, create_if_not_found, abortable(function(file) {\n
              file.createWriter(abortable(function(writer) {\n
                writer.onwriteend = function(event) {\n
                  target_view.location.href = file.toURL();\n
                  filesaver.readyState = filesaver.DONE;\n
                  dispatch(filesaver, "writeend", event);\n
                  revoke(file);\n
                };\n
                writer.onerror = function() {\n
                  var error = writer.error;\n
                  if (error.code !== error.ABORT_ERR) {\n
                    fs_error();\n
                  }\n
                };\n
                "writestart progress write abort".split(" ").forEach(function(event) {\n
                  writer["on" + event] = filesaver["on" + event];\n
                });\n
                writer.write(blob);\n
                filesaver.abort = function() {\n
                  writer.abort();\n
                  filesaver.readyState = filesaver.DONE;\n
                };\n
                filesaver.readyState = filesaver.WRITING;\n
              }), fs_error);\n
            }), fs_error);\n
          };\n
          dir.getFile(name, {create: false}, abortable(function(file) {\n
            // delete file if it already exists\n
            file.remove();\n
            save();\n
          }), abortable(function(ex) {\n
            if (ex.code === ex.NOT_FOUND_ERR) {\n
              save();\n
            } else {\n
              fs_error();\n
            }\n
          }));\n
        }), fs_error);\n
      }), fs_error);\n
    }\n
    , FS_proto = FileSaver.prototype\n
    , saveAs = function(blob, name, no_auto_bom) {\n
      return new FileSaver(blob, name, no_auto_bom);\n
    }\n
  ;\n
  // IE 10+ (native saveAs)\n
  if (typeof navigator !== "undefined" && navigator.msSaveOrOpenBlob) {\n
    return function(blob, name, no_auto_bom) {\n
      if (!no_auto_bom) {\n
        blob = auto_bom(blob);\n
      }\n
      return navigator.msSaveOrOpenBlob(blob, name || "download");\n
    };\n
  }\n
\n
  FS_proto.abort = function() {\n
    var filesaver = this;\n
    filesaver.readyState = filesaver.DONE;\n
    dispatch(filesaver, "abort");\n
  };\n
  FS_proto.readyState = FS_proto.INIT = 0;\n
  FS_proto.WRITING = 1;\n
  FS_proto.DONE = 2;\n
\n
  FS_proto.error =\n
  FS_proto.onwritestart =\n
  FS_proto.onprogress =\n
  FS_proto.onwrite =\n
  FS_proto.onabort =\n
  FS_proto.onerror =\n
  FS_proto.onwriteend =\n
    null;\n
\n
  return saveAs;\n
}(\n
     typeof self !== "undefined" && self\n
  || typeof window !== "undefined" && window\n
  || this.content\n
));\n
// `self` is undefined in Firefox for Android content script context\n
// while `this` is nsIContentFrameMessageManager\n
// with an attribute `content` that corresponds to the window\n
\n
if (typeof module !== "undefined" && module.exports) {\n
  module.exports.saveAs = saveAs;\n
} else if ((typeof define !== "undefined" && define !== null) && (define.amd != null)) {\n
  define([], function() {\n
    return saveAs;\n
  });\n
}

]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>9546</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
