<?xml version="1.0"?>
<ZopeData>
  <record id="1" aka="AAAAAAAAAAE=">
    <pickle>
      <global name="DTMLMethod" module="OFS.DTMLMethod"/>
    </pickle>
    <pickle>
      <dictionary>
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
  document.forms[0].action = act;\n
}\n
\n
\n
// The first input element with an "autofocus" class will get the focus,\n
// else if no element have autofocus class, the first element which is not the\n
// search field will get the focus. This is generally the title input text of\n
// a view\n
function autoFocus() {\n
  var first_autofocus_expr = ".//input[@class=\'autofocus\']"\n
  var FIRST_RESULT = XPathResult.FIRST_ORDERED_NODE_TYPE\n
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
  }\n
}\n
\n
function buildTables(element_list, rowPredicate, columnPredicate,\n
                    tableClassName) {\n
  /* Generic code to build a table from elements in element_list.\n
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
        while ((!end_line) && (row_item = row_item.nextSibling) != null) {\n
          var predicate_result = columnPredicate(row_item, row_begin)\n
          if ((predicate_result & 1) != 0)\n
            item_list.push(row_item);\n
          end_table = ((predicate_result & 4) != 0);\n
          end_line = ((predicate_result & 6) != 0);\n
        }\n
        row_list.push(item_list);\n
      }\n
      element_index++;\n
    }\n
    /* Do not create a table with just one cell. */\n
    if ((row_list.length > 1) ||\n
        (row_list.length == 1 && row_list[0].length > 1)) {\n
      var first_element = row_list[0][0];\n
      var container = first_element.parentNode;\n
      var fake_table = document.createElement("table");\n
      var i;\n
      var j;\n
      fake_table.className = tableClassName;\n
      container.insertBefore(fake_table, first_element);\n
      for (i = 0; i < row_list.length; i++) {\n
        var fake_row = document.createElement("tr");\n
        var row_element_list = row_list[i];\n
        for (j = 0; j < row_element_list.length; j++) {\n
          var fake_cell = document.createElement("td");\n
          fake_cell.appendChild(row_element_list[j]);\n
          fake_row.appendChild(fake_cell);\n
        }\n
        fake_table.appendChild(fake_row);\n
      }\n
    }\n
  }\n
}\n
\n
function matchChunk(string, separator, chunk_value) {\n
  if (string != null) {\n
    var id_chunks = string.split(separator);\n
    var i;\n
    for (i = 0; i < id_chunks.length; i++) {\n
      if (id_chunks[i] == chunk_value)\n
        return true;\n
    }\n
  }\n
  return false;\n
}\n
\n
function matchLeftFieldset(element) {\n
  return (element.tagName == "FIELDSET") &&\n
          matchChunk(element.id, \'_\', "left");\n
}\n
\n
function matchRightFieldset(element, ignored) {\n
  if ((element.tagName == "FIELDSET") &&\n
       matchChunk(element.id, \'_\', "right"))\n
    return 7; /* End row, table and use element */\n
  return 0;\n
}\n
\n
function fixLeftRightHeightAndFocus(fix_height) {\n
  if (fix_height == 1) {\n
    buildTables(document.getElementsByTagName(\'fieldset\'),\n
                matchLeftFieldset, matchRightFieldset,\n
                "fake");\n
  }\n
  autoFocus();\n
}\n
\n
// This function can be used to catch ENTER pressed in an input \n
// and modify respective main form action\n
function submitFormOnEnter(event, main_form_id, method_name){\n
  var key_code = event.keyCode;\n
  if(key_code == 13){\n
    var main_form = getElement(main_form_id)\n
    main_form.action=method_name;};\n
}\n
\n
var old_index=0;\n
function shiftCheck(evt) {\n
  evt=(evt)?evt:event;\n
  var target=(evt.target)?evt.target:evt.srcElement;\n
  // remove "checkbox" part from ID\n
  // This part can be reused easilly by usual left column\n
  var target_index= target.id.substr(8);\n
  if(!evt.shiftKey) {\n
    old_index= target_index\n
    check_option = target.checked;\n
    return false;\n
    }\n
  target.checked=1;\n
  var low=Math.min(target_index , old_index);\n
  var high=Math.max(target_index , old_index);\n
  for(var i=low;i<=high;i++) {\n
    document.getElementById("checkbox" + i ).checked = check_option;\n
   }\n
  return true;\n
  }\n
\n
var indexAllCheckBoxesAtBTInstallationOnLoad = function() {\n
    // This Part is used basically for Business Template Installation.\n
    var inputs = window.getElementsByTagAndClassName("input", "shift_check_support");\n
    for(i=0;i<=inputs.length-1;i++) { inputs[i].id = "checkbox" + i; }\n
}\n
\n
addLoadEvent(indexAllCheckBoxesAtBTInstallationOnLoad)

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
