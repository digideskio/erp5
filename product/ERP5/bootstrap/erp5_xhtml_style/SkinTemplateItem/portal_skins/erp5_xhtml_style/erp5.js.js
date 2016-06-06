<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="DTMLMethod" module="OFS.DTMLMethod"/>
    </pickle>
    <pickle>
      <dictionary>
        <item>
            <key> <string>_Cacheable__manager_id</string> </key>
            <value> <string>http_cache</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>erp5.js</string> </value>
        </item>
        <item>
            <key> <string>_vars</string> </key>
            <value>
              <dictionary/>
            </value>
        </item>
        <item>
            <key> <string>globals</string> </key>
            <value>
              <dictionary/>
            </value>
        </item>
        <item>
            <key> <string>raw</string> </key>
            <value> <string encoding="cdata"><![CDATA[

/*\n
Copyright (c) 20xx-2006 Nexedi SARL and Contributors. All Rights Reserved.\n
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
function submitAction(form, act) {\n
  form.action = act;\n
  form.submit();\n
}\n
\n
// This function will be called when the user click the save button. As \n
// submitAction function may have changed the action before, it\'s better to\n
// reset the form action to it\'s original behaviour. This is actually\n
// usefull when the user click the back button.\n
function clickSaveButton(act) {\n
  changed = false;\n
  document.forms[0].action = act;\n
}\n
\n
// The first input element with an "autofocus" class will get the focus,\n
// else if no element have autofocus class, the first element which is not the\n
// search field will get the focus. This is generally the title input text of\n
// a view\n
function autoFocus() {\n
  var first_autofocus_expr = ".//input[@class=\'autofocus\']";\n
  var FIRST_RESULT = XPathResult.FIRST_ORDERED_NODE_TYPE;\n
\n
  var input = document.evaluate(first_autofocus_expr, document, null, FIRST_RESULT, null).singleNodeValue;\n
  if (input) {\n
    input.focus();\n
  }else{\n
    // The following is disabled, because it is too annoying to have an auto focus at everywhere.\n
    //var first_text_input_expr = ".//input[@type=\'text\'][@name != \'field_your_search_text\']"\n
    //var first_text_input = document.evaluate(first_text_input_expr, document, null, FIRST_RESULT, null).singleNodeValue;\n
    //if (first_text_input){\n
    //  first_text_input.focus();\n
    //}\n
   true;\n
  }\n
}\n
\n
function buildTables(element_list, rowPredicate, columnPredicate,\n
                    tableClassName) {\n
  /* Generic code to build a table from elements in element_list.\n
   * XXX: not used anymore ?\n
   * rowPredicate(element) -> bool\n
   *   When it returns a true value, a new line is started with element.\n
   *   When is returns a false value, element is skipped.\n
   * columnPredicate(element, initial_element) -> bitfield\n
   *   bit 3: end_table (if true, imlies end_row)\n
   *     End current table.\n
   *   bit 2: end_row\n
   *     End current row.\n
   *   bit 1: use_element\n
   *     Element passed to columnPredicate will be put in current row.\n
   * Hardcoded:\n
   *  - items in a table line must be siblings in existing DOM\n
   *  - table is put in place of first element of the first row\n
   */\n
  var element_index = 0;\n
  while (element_index < element_list.length) {\n
    var row_list = [];\n
    var end_table = false;\n
    while ((!end_table) && element_index < element_list.length) {\n
      var row_begin = element_list[element_index];\n
      if (rowPredicate(row_begin)) {\n
        var item_list = [row_begin];\n
        var row_item = row_begin;\n
        var end_line = false;\n
        while ((!end_line) && (row_item = row_item.nextSibling) !== null) {\n
          var predicate_result = columnPredicate(row_item, row_begin);\n
          if ((predicate_result & 1) !== 0)\n
            item_list.push(row_item);\n
          end_table = ((predicate_result & 4) !== 0);\n
          end_line = ((predicate_result & 6) !== 0);\n
        }\n
        row_list.push(item_list);\n
      }\n
      element_index++;\n
    }\n
    /* Do not create a table with just one cell. */\n
    if ((row_list.length > 1) ||\n
        (row_list.length == 1 && row_list[0].length > 1)) {\n
      var first_element = row_list[0][0];\n
      var fake_table = $("<table>");\n
      fake_table.addClass(tableClassName);\n
      fake_table.insertBefore(first_element);\n
      $.each(row_list, function() {\n
        var fake_row = $("<tr>");\n
        $.each(this, function() {\n
          var fake_cell = $("<td>");\n
          fake_cell.append(this);\n
          fake_row.append(fake_cell[0]);\n
        });\n
        fake_table.append(fake_row[0]);\n
      });\n
    }\n
  }\n
}\n
\n
function matchLeftFieldset(element) {\n
// XXX: not used anymore ?\n
  return (element.tagName == "FIELDSET" &&\n
       element.className.toLowerCase().indexOf(\'left\') != -1);\n
}\n
\n
function matchRightFieldset(element, ignored) {\n
// XXX: not used anymore ?\n
  if (element.tagName == "FIELDSET" &&\n
       element.className.toLowerCase().indexOf(\'right\') != -1)\n
    return 7; /* End row, table and use element */\n
  return 0;\n
}\n
\n
function fixLeftRightHeightAndFocus(fix_height) {\n
  if (fix_height == 1) {\n
    var right_xpath = "following-sibling::fieldset[contains(@class, \'right\')]";\n
    var matched_left_element_list = document.evaluate("//fieldset[contains(@class, \'left\') and " + right_xpath + "]", document, null, XPathResult.UNORDERED_NODE_SNAPSHOT_TYPE, null);\n
    var element_index;\n
    for (element_index = 0; element_index < matched_left_element_list.snapshotLength; element_index++) {\n
      var element = matched_left_element_list.snapshotItem(element_index);\n
      var right = document.evaluate(right_xpath, element, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;\n
      var table = $(\'<table class="fake">\').insertBefore(element);\n
      table.append($("<tr>").append($("<td>").append(element)).append($("<td>").append(right)));\n
    }\n
  }\n
  autoFocus();\n
}\n
\n
// This function can be used to catch ENTER pressed in an input\n
// and modify respective main form action\n
// if clear_changed_flag is set to true, changed will be set to false, so no\n
// warning message about unsaved changes will be displayed\n
function submitFormOnEnter(event, form, method_name, clear_changed_flag, element){\n
  if (clear_changed_flag === null){ clear_changed_flag = false; }\n
  if(event.keyCode == 13){\n
    if (form == "main_form") {\n
      form = document.forms[form]; // backward compatibility\n
    }\n
    form.action = method_name;\n
    if (clear_changed_flag === true) {\n
      changed = false;\n
    }\n
    form.submit();\n
    event.preventDefault();\n
    return false;\n
  }\n
}\n
\n
var old_index = 0;\n
function shiftCheck(evt) {\n
  /*Uncheck all checkboxes from last unchecked one in \n
    business template Install / Update / Reinstall dialog.\n
  */\n
  evt = (evt)?evt:event;\n
  var target=(evt.target)?evt.target:evt.srcElement;\n
  // remove "checkbox" part from ID\n
  // This part can be reused easilly by usual left column\n
  var target_index= target.id.substr(8);\n
  if(!evt.shiftKey) {\n
    old_index = target_index;\n
    check_option = target.checked;\n
    return false;\n
    }\n
  target.checked=1;\n
  var low=Math.min(target_index , old_index);\n
  var high=Math.max(target_index , old_index);\n
  for(var i=low;i<=high;i++) {\n
    $("#checkbox" + i).attr("checked", false);\n
   }\n
  return true;\n
  }\n
\n
var indexAllCheckBoxesAtBTInstallationOnLoad = function() {\n
    // This Part is used basically for Business Template Installation.\n
    $("input.shift_check_support").each(\n
      function(index){$(this).attr("id",  "checkbox"+index);});\n
    //var inputs = window.getElementsByTagAndClassName("input", "shift_check_support");\n
    //for(i=0;i<=inputs.length-1;i++) {inputs[i].id = "checkbox" + i; }\n
};\n
\n
var resizeIFrameOnLoad = function() {\n
  /* Resize all frames in document in order to remove sliders  */\n
  $("object.auto_height").each(function(){\n
    var inner_frame = this.contentDocument;\n
    if (inner_frame){\n
      $(this).css("height", inner_frame.documentElement.offsetHeight + \'px\');\n
    }\n
  });\n
};\n
\n
var changed = false;\n
function installUnsavedChangesWarning(warning_message) {\n
  window.onbeforeunload = function() {\n
    if ((changed)&&($("button.save")))\n
      // show an warning box only if save button do exists\n
      return warning_message;\n
  };\n
}\n
\n
var addOnChangeEventHandler = function() {\n
  /* Add a onchange event handler for all fields inputs.\n
  This event handler set a dirty flag which cause a warning\n
  while leaving the page, unless leaving by:\n
      - saving (see clickSaveButton function from this file)\n
      - clicking a relation field wheel\n
      - clicking on a input with type submit\n
  */\n
  $("#master div").each(function(i) {\n
    if ($(this).attr("class") == "input") {\n
        $(this).children().each(function() {\n
          if ($(this).prop("tagName") == "INPUT" ||\n
              $(this).prop("tagName") == "SELECT" ||\n
              $(this).prop("tagName") == "TEXTAREA") {\n
              if ($(this).val() == "update..." ||\n
                  ($(this).prop("tagName") == "INPUT" &&\n
                  $(this).attr("type") == \'submit\')) {\n
               // this is a relation field wheel or a submit form button\n
             this.onclick = function() { changed = false;};\n
            } else {\n
              if (!this.onchange) {\n
                this.onchange = function() { changed = true; };\n
              }\n
            }\n
          } \n
          /* Listbox or MatrixBox */\n
          if ($(this).prop("tagName") == "DIV" && (\n
              $(this).attr("class") == "listbox-container" ||\n
              $(this).attr("class") == "MatrixContent")) {\n
            $(this).find(\'td\').each(function(){\n
              if ($(this).attr("class") == "listbox-search-line") {\n
                return non-false;\n
              }\n
              $(this).find(\'input\').each(function(){\n
                if ($(this).attr("type") != "hidden" &&\n
                    !this.onchange) {\n
                  this.onchange = function() { changed = true; };\n
                }\n
              });\n
              return true;\n
            });\n
          }\n
        });\n
    }\n
  });\n
};\n
\n
var rewriteIndentedSelect = function() {\n
  /*\n
   Under firefox, rewrite indented title categories using style definition.\n
   This way we can select items by pressing the first letter of their name. */\n
\n
    $("#master select").each(function() {\n
      $(this).children().each(function() {\n
        if ($(this).prop("tagName") != "OPTION") {\n
          return non-false;\n
        }\n
        text = $(this).html();\n
        if (text.substring(0, 1) == \'\\n\') {\n
          text = text.substring(1, text.length);\n
        }\n
        level = 0;\n
        if (text.substring(0, 6) == \'&nbsp;\') {\n
          for (idx=0; idx <= text.length; idx+=6) {\n
            if (text.substring(idx, idx+6) == \'&nbsp;\') {\n
              level += 1;\n
            } else {\n
              break;\n
            }\n
          }\n
        }\n
        if (level >= 1) {\n
          level = level / 4.0;\n
          $(this).html(text.replace(/^(&nbsp;)+/, ""));\n
          $(this).css("paddingLeft", level+"em");\n
        }\n
        return true;\n
      });\n
    });\n
};\n
\n
function queryStringToArray(query_string){\n
  /*\n
    Turn a query string into a "dictionary"\n
  */\n
  var final_dict = {};\n
  var b = query_string.split(\'&\');\n
  $.each(b, function(x, y){\n
    var temp = y.split(\'=\');\n
    final_dict[temp[0]] = temp[1];});\n
  return final_dict;\n
}\n
\n
function submitLinkAsHtmlForm(event){\n
  /*\n
  Parse link into form arguments and pass everything as a \n
  form (together with rest of page\'s input elements).\n
  */\n
  var url = $(this).attr("href");\n
  var form = $("form");\n
  var method = url.substring(0, url.indexOf(\'?\'));\n
  var query_string = url.substring(url.indexOf(\'?\')+1);\n
  var params = queryStringToArray(query_string);\n
  $.each(params, function(key, value) {\n
    if (!$(\'*[name="\' + key + \'"]\').length){\n
      // key not part of HTML namespace\n
      form.append(\'<input type="hidden" name="\' + key+ \'" value="\' + value + \'">\');\n
    }});\n
  // submit form  \n
  form.attr("action", method);\n
  form.submit();\n
  event.stopPropagation();\n
  return false;\n
}\n
\n
function redirectPDFPage(event, element){\n
  /*\n
    Used in PDF thumbnail preview mode\n
  */\n
  if(event.keyCode == 13){\n
    selection_index = parseInt($(element).val(), 10) - 1;\n
    window.location.href = "PDF_viewHTMLPreviewAsImage?selection_index=" + selection_index;\n
    return false;    \n
  }\n
}\n
\n
if (navigator.userAgent.toLowerCase().indexOf(\'firefox\') != -1)\n
  $(document).ready(rewriteIndentedSelect);\n
$(document).ready(resizeIFrameOnLoad);\n
$(document).ready(addOnChangeEventHandler);\n
$(document).ready(indexAllCheckBoxesAtBTInstallationOnLoad);\n
\n
\n
\n
function installDoubleSubmitDialogPrevention(confirmation_message) {\n
  /* Install an handler to prevent submitting a dialog twice. */\n
  $(document).ready( function() {\n
    $(".dialog_submit_button").on("click", function(e){\n
      $(this).on("click.confirm", function(event) {\n
        $(this).off(".confirm");\n
        if (! confirm(confirmation_message) ) {\n
          event.preventDefault();\n
        }\n
      });\n
    });\n
  });\n
}

]]></string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
