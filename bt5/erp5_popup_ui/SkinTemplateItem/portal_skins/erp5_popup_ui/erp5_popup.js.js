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
            <value> <string>http_cache</string> </value>
        </item>
        <item>
            <key> <string>_EtagSupport__etag</string> </key>
            <value> <string>ts01396443.57</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>erp5_popup.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*\n
Copyright (c) 2010 Nexedi SA and Contributors. All Rights Reserved.\n
                   Yoshinori Okuji <yo@nexedi.com>\n
\n
This program is Free Software; you can redistribute it and/or\n
modify it under the terms of the GNU General Public License\n
as published by the Free Software Foundation; either version 2\n
of the License, or (at your option) any later version.\n
\n
This program is distributed in the hope that it will be useful,\n
but WITHOUT ANY WARRANTY; without even the implied warranty of\n
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n
GNU General Public License for more details.\n
\n
You should have received a copy of the GNU General Public License\n
along with this program; if not, write to the Free Software\n
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.\n
*/\n
\n
/*\n
Note: this JavaScript is used to pop up dialogs inside the same pages, instead of transiting into different pages.\n
It would not be difficult to extend this script to support more types of dialogs, but it is enabled only for\n
relation update dialogs at the moment. This is tested with erp5_xhtml_style.\n
\n
If you want to use this feature, you need to load additional files in global_definitions:\n
\n
           dummy                python:js_list.extend((\'%s/jquery-ui-1.7.2/js/jquery-1.3.2.min.js\' % portal_path, \'%s/jquery-ui-1.7.2/js/jquery-ui-1.7.2.custom.min.js\' % portal_path));\n
           dummy                python:css_list.append(\'%s/jquery-ui-1.7.2/css/erp5-theme/jquery-ui-1.7.2.custom.css\' % portal_path);\n
           dummy                python:js_list.append(\'%s/erp5_popup.js\' % portal_path);\n
\n
The first two lines are required for loading jQuery and jQuery UI. The last line is for this file.\n
*/\n
\n
$(function() {\n
  /*\n
   * generic dialog to display another ERP5 page on top of the page.\n
   *\n
   * Parameters:\n
   * \'dialog\': object to pass as argument to $.ui.dialog on creation.\n
   *           erp5_dialog has generic defaults, and everything you will\n
   *           pass will override those defaults.\n
   * \'load\'  :\n
   *        - url: url to load in the popup\n
   *        - params: parameters to give to the ajax call. can be omitted\n
   *        - method: default $.post, you can change it to $.get\n
   *\n
   * Example:\n
   *   $(\'<div id="jquery_erp5_dialog" />\').appendTo(\'body\').erp5_popup({\n
   *        dialog: {title: \'It works\', },\n
   *        load: {url: \'/erp5/some_module/someobject\'},\n
   *   )};\n
   */\n
  $.fn.erp5_popup = function(params) {\n
    dialog = $(this);\n
\n
    var default_dialog_parameters = {\n
       modal: true,\n
       width: $(window).width() * 0.8,\n
       height: $(window).height() * 0.8,\n
       title: \'ERP5 dialog\',\n
       close: function() {\n
         dialog.dialog(\'destroy\');\n
         dialog.empty();\n
      },\n
    }\n
    // initalize jQuery dialog\n
    dialog.dialog($.extend({}, default_dialog_parameters, params.dialog));\n
\n
    var load = function(url, query, ajax_method) {\n
      if (!query) query = {};\n
      if (!ajax_method) ajax_method = $.post;\n
      //dialog.empty();\n
      // scroll up to begin of "window"\n
      window.scrollTo(0,0);\n
      // Some bogus animations for having the user to feel easier.\n
      var animate = function() {\n
        var element = $(\'p.loading\', dialog);\n
        if (element.length != 0) {\n
          //element.animate({opacity: 1}, 2000, \'linear\');\n
          //element.animate({opacity: 0}, 2000, \'linear\', animate);\n
          element.animate({color: \'white\'}, 2000, \'linear\');\n
          element.animate({color: \'black\'}, 2000, \'linear\', animate);\n
        }\n
      };\n
      $(\'<div class="loading" style="background-color: #AAAAAA; opacity: 0.5; position: absolute; left: 0%; width: 100%; top: 0%; height: 100%; transparent;"><p class="loading" style="position: absolute; left: 0%; width: 100%; top: 30%; height: 40%; text-align: center; color: black; font-size: 32pt;">Loading...</p></div>\').appendTo(dialog);\n
      animate();\n
\n
      ajax_method(url, query, function(data, textStatus, XMLHttpRequest) {\n
        if (textStatus == \'success\' || textStatus == \'notmodified\') {\n
          // Stop the animations above.\n
          dialog.empty();\n
          //$(\'div.loading\', dialog).remove();\n
\n
          dialog.html($(\'<div />\').append(data.replace(/<script(.|\\s)*?\\/script>/g, \'\')).find(\'form\'));\n
\n
          // XXX Get rid of unneeded stuff in JavaScript for now.\n
          $(\'.bars, .breadcrumb, .logged_in_as\', dialog).remove();\n
          $(\'[id]\', dialog).removeAttr(\'id\');\n
          // XXX Get rid of unneeded KM stuff in JavaScript for now.\n
          $(\'.wrapper\', dialog).remove();\n
\n
          // Insert the same buttons as at the bottom into near the top.\n
          //$(\'div.bottom_actions\', dialog).clone().insertAfter($(\'div.dialog_box\', dialog)).css(\'margin-bottom\', \'1em\');\n
\n
          $(\'input[type="image"], button.sort_button, .dialog_selector > button, button.save\', dialog).click(function(event) {\n
            event.preventDefault();\n
            var self = $(this);\n
            var form = $(\'form.main_form\', dialog);\n
            var params = {};\n
            params[self.attr(\'name\')] = self.attr(\'value\');\n
            load(form.attr(\'action\'), $.param(params) + \'&\' + form.serialize());\n
          });\n
\n
          // XXX Remove the hardcoded handler.\n
          $(\'.dialog_selector > select[onchange]\', dialog).removeAttr(\'onchange\');\n
          $(\'.dialog_selector > select\', dialog).change(function(event) {\n
            //event.preventDefault();\n
            var button = $(\'button\', this.parentNode);\n
            var form = $(\'form.main_form\', dialog);\n
            var params = {};\n
            params[button.attr(\'name\')] = button.attr(\'value\');\n
            load(form.attr(\'action\'), $.param(params) + \'&\' + form.serialize());\n
          });\n
\n
          // listbox type in page number\n
          $(\'input[name="listbox_page_start"][onkeypress]\', dialog).removeAttr(\'onkeypress\');\n
          $(\'input[name="listbox_page_start"]\', dialog).keypress(function(event) {\n
            if (event.keyCode == \'13\') {\n
              event.preventDefault();\n
              var self = $(this);\n
              self.value = self.attr(\'defaultValue\');\n
              var form = $(\'form.main_form\', dialog);\n
              // XXX no other way but hardcoding the method name.\n
              load(\'listbox_setPage\', form.serialize());\n
            }\n
          });\n
          \n
          // Listbox next & previous, last & first buttons\n
          $.each([\'listbox_nextPage\', \'listbox_previousPage\', \'listbox_firstPage\', \'listbox_lastPage\'], \n
                 function(index, value) {\n
                   var button = $(\'button[type="submit"][name="\' + value + \':method"]\', dialog).first();\n
                   button.click(function(event) {\n
                                  var form = $(\'form.main_form\', dialog);\n
                                  event.preventDefault();\n
                                  load(value, form.serialize());            \n
                   });\n
          });\n
         \n
          $(\'th.listbox-table-filter-cell input[type="text"]\', dialog).removeAttr(\'onkeypress\').keypress(function(event) {\n
            if (event.keyCode == \'13\') {\n
              event.preventDefault();\n
              //var self = $(this);\n
              //self.value = self.attr(\'defaultValue\');\n
              var form = $(\'form.main_form\', dialog);\n
              var first_submit_button = $($(\'input[type="submit"]\', form)[0]);\n
              var params = {};\n
              params[first_submit_button.attr(\'name\')] = first_submit_button.attr(\'value\');\n
              load(form.attr(\'action\'), $.param(params) + \'&\' + form.serialize());\n
            }\n
          });\n
\n
          $(\'button.dialog_cancel_button\', dialog).click(function(event) {\n
            event.preventDefault();\n
            dialog.dialog(\'close\');\n
          });\n
\n
          $(\'button.dialog_update_button\', dialog).click(function(event) {\n
            event.preventDefault();\n
            var self = $(this);\n
            var form = $(\'form.main_form\', dialog);\n
            var params = {};\n
            params[self.attr(\'name\')] = self.attr(\'value\');\n
            load(form.attr(\'action\'), $.param(params) + \'&\' + form.serialize());\n
          });\n
        }\n
      });\n
    };\n
    load(params.load.url, params.load.params, params.load.method);\n
  };\n
});\n
\n
$(function() {\n
  // XXX It is necessary to keep a reference to a dialog, because jQuery / jQuery UI does not keep information\n
  // in elements of DOM unfortunately. This is not a big problem at the moment, because this implementation assumes\n
  // that a dialog is modal.\n
  // XXX Nicolas: see $.data() for storage in DOM. I dont think that it matters however. $("#jquery_erp5_dialog") should be enough\n
  var dialog = $(\'<div id="jquery_erp5_dialog" />\').appendTo(\'body\');\n
\n
\n
  // Those two definitions could be kept in a different file. The jQuery plugin providing an implementation is different than\n
  // the places where we use this plugin\n
\n
  // Make the relation update dialogs as pop-ups.\n
  $(\'input[value="update..."]\').click(function(event) {\n
    event.preventDefault();\n
\n
    var self = $(this);\n
    var form = $(\'form#main_form\');\n
    var params = {};\n
    params[self.attr(\'name\')] = self.attr(\'value\');\n
\n
    dialog.erp5_popup({\n
        dialog: { title: $(\'label\', this.parentNode.parentNode).text() },\n
        load: {\n
            url: form.attr(\'action\'),\n
            params: $.param(params) + \'&\' + form.serialize(),\n
        }\n
    });\n
  });\n
  \n
  // login logout links for KM\n
  $(\'a[id="login-logout-link"]\').click(function(event) {\n
    if($(\'a[id="login-logout-link"]\').attr(\'href\').indexOf(\'login_form\')==-1){\n
      // we show popup only for login_form\n
      return\n
    }\n
    event.preventDefault();\n
\n
    dialog.erp5_popup({\n
        dialog: { title: $(\'label\', this.parentNode.parentNode).text() },\n
        load: {\n
            url: this.href,\n
            method: $.get,\n
        }\n
    });\n
  });\n
  \n
  \n
  // Make the Add gadget dialog work as pop-ups.\n
  $(\'a[id="add-gadgets"]\').click(function(event) {\n
    event.preventDefault();\n
\n
    dialog.erp5_popup({\n
        dialog: { title: $(\'label\', this.parentNode.parentNode).text() },\n
        load: {\n
            url: this.href,\n
            method: $.get,\n
        }\n
    });\n
  });\n
\n
});\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>10183</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
