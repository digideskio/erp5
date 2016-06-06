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
            <value> <string>ts01809029.9</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>erp5_knowledge_box.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

// global layout is saved here\n
var last_layout = \'\';\n
\n
// current active pad relative url\n
var active_knowledge_pad_relative_url = \'\';\n
var active_knowledge_pad_title_dom_id = \'\';\n
\n
// enable or disable integration with server\n
var is_knowledge_template_used = 0;\n
\n
// dictionary of invisible gadgets\n
var invisible_gadgets={};\n
\n
var create_default_knowledge_pad_script_id = "ERP5Site_createDefaultKnowledgePadListForUser";\n
var knowledge_box_edit_script_id = "KnowledgeBox_baseEdit";\n
var knowledge_pad_save_layout_script_id = "KnowledgePad_saveBoxColumnLayout";\n
var knowledge_pad_delete_box_script_id = "KnowledgePad_deleteBox";\n
var knowledge_box_toggle_script_id = "KnowledgeBox_toggleVisibility";\n
var knowledge_pad_rename_script_id = "ERP5Site_renameKnowledgePad";\n
var knowledge_pad_delete_script_id = "ERP5Site_deleteKnowledgePad";\n
var add_new_knowledge_pad_script_id = "ERP5Site_addNewKnowledgePad";\n
var knowledge_pad_as_json_script_id = "KnowledgePad_getPadAsJSON";\n
var add_new_gadget_form_id = "Base_viewGadgetListDialog";\n
\n
function createCustomKnowledgePadOnServer(){\n
  $.ajax({url:create_default_knowledge_pad_script_id, \n
          data:{mode: mode,\n
                default_pad_group: default_pad_group},\n
          success:function(data){window.location=cancel_url;}});\n
}\n
\n
function showCreateDefaultKnowledgePadWarningMessage(){\n
  user_choice = confirm("In order to complete operation you must have your own tab on server instead of the default one which you are currently using and which you can not change.Is it OK to create new one for you now?");\n
  if (user_choice===true){\n
    createCustomKnowledgePadOnServer();}\n
}\n
\n
function createCookie(name, value, days, path) {\n
  var expires = "";\n
  if (days){\n
    var date = new Date();\n
    date.setTime(date.getTime()+(days*24*60*60*1000));\n
    expires = "; expires="+date.toGMTString();}\n
  if (!path){path=\'/\';}\n
  document.cookie = name+"="+value+expires+"; path="+path;\n
}\n
\n
function updater(url, box_relative_url, dom_id, \n
                 editable_mode, additionnal_request_params, field_prefix){\n
  /* Get content from server */\n
  request_params = {};\n
  additionnal_request_params = typeof(additionnal_request_params) != \'undefined\' ? additionnal_request_params : [];\n
\n
  // getting parameters for the request in the form\'s hidden inputs\n
  input_list = $("#" + dom_id).find("input");\n
\n
  function extractHiddenInputs(index){\n
    element = $(this);\n
    type = element.attr("type");\n
    name = element.attr("name");\n
    value = element.val();\n
    is_list = name.substring(name.length, name.length - 5) == ":list";\n
    if(type == "hidden"){\n
      if(name == "gadget_form_id"){\n
        // turn \'gadget_form_id\' into \'form_id\'\n
        request_params["form_id"] = value;}\n
      else if(is_list){\n
        if(typeof(request_params[name]) == "undefined"){\n
          request_params[name] = new Array();}\n
        request_params[name].push(value);}\n
      else{\n
        // not list input\n
        request_params[name] = value;}\n
    }}\n
  \n
  input_list.each(extractHiddenInputs);\n
\n
  // we can have a field_prefix which allows multiple gadgets within same HTML form\n
  if (field_prefix){\n
    $.each(request_params,  \n
         function (key, value){\n
           if (key.match("^"+field_prefix)){\n
             delete request_params[key];\n
             request_params[key.replace(field_prefix,\'\')] = value;\n
           }});\n
  }\n
  \n
  // getting parameters for request from the parameter additionnal_request_params\n
  $.each(additionnal_request_params,  \n
         function (key, value){request_params[key] = additionnal_request_params[key];});\n
         \n
  request_params["box_relative_url"] = box_relative_url;\n
  request_params["is_gadget_mode:int"] = 1; \n
  request_params["editable_mode:int"] = editable_mode; \n
\n
  // set transperancy to show an activity is going on\n
  $("#" + dom_id).css("opacity", 0.5);\n
  $.ajax({url:url,\n
          data: request_params,\n
          success: handleServerSuccess,\n
          error: handleServerError,\n
          // it\'s important for Zope to have traditional way of encoding an URL\n
          traditional: 1});\n
      \n
  function handleServerSuccess(data, text_status, xhr){\n
    content_type = xhr.getResponseHeader(\'Content-Type\');\n
    if(content_type.search("application/json")!=-1){\n
      // server returned JSON which may contain HTML & JavaScript\n
      html = data[\'body\'];\n
      eval(data[\'javascript\']);}\n
    else{\n
      /* server returned HTML */\n
      html = data;}\n
    $("#" + dom_id).html(html);\n
    $("#" + dom_id).css("opacity", 1.0);\n
  }\n
      \n
  function handleServerError(res){\n
    $("#" + dom_id).html("Server side error.");\n
    $("#" + dom_id).css("opacity", 1.0);\n
  }\n
}\n
\n
function submitGadgetPreferenceFormOnEnter(event, \n
                                           form_fields_main_prefix, \n
                                           box_relative_url, \n
                                           edit_form_id){\n
  /* This function can be used to submit gadget preferences form whenever\n
  an enter is pressed in form */\n
  if(event.keyCode == 13){submitSynchronousGadgetPreferenceForm(form_fields_main_prefix, \n
                                                                box_relative_url, \n
                                                                edit_form_id);}\n
}\n
\n
function addHiddenInput(name, value){\n
  $("form").find(\'input[name="\' + name + \'"]\').remove();\n
  $("form").append(\'<input type="hidden" name="\' + name + \'" value="\' + value + \'">\');\n
}\n
\n
function submitSynchronousGadgetPreferenceForm(\n
                                form_fields_main_prefix, \n
                                box_relative_url,\n
                                edit_form_id){\n
  /* this will add respective gadget knowledge box relative url and\n
     gadget ERP5 preference form field_prefix (so multiple gadgets can \n
     safely coexist in one HTML page with one HTML form */\n
  redirect_url = window.location.protocol + "//" + window.location.host + window.location.pathname;\n
  addHiddenInput("box_relative_url", box_relative_url);\n
  addHiddenInput("form_fields_main_prefix", form_fields_main_prefix);\n
  addHiddenInput("gadget_redirect_url", redirect_url);\n
  addHiddenInput("form_id", edit_form_id);\n
  clickSaveButton(knowledge_box_edit_script_id);\n
}\n
\n
function submitAsynchronousGadgetPreferenceForm(\n
                                 form_dom_id, \n
                                 view_form_url, \n
                                 box_relative_url, \n
                                 visual_block_dom_id, \n
                                 form_fields_main_prefix,\n
                                 edit_form_id){\n
  /* Iterate over all possible form elements within edit form,\n
    collect them and send to server*/\n
  var request_str = "synchronous_mode:int=0&" + "box_relative_url=" + box_relative_url+ "&form_fields_main_prefix=" + form_fields_main_prefix + "&form_id="+edit_form_id + "&";\n
  \n
  //input tags\n
  $("#" + form_dom_id).find("input").each(\n
    function (index) {\n
      element = $(this);\n
      type = element.attr("type");\n
      name = element.attr("name");\n
      is_checked = element.attr("checked");\n
      value = element.val();\n
      if (type == "checkbox"){\n
        if (is_checked){request_str+=name + ":boolean=True&";}\n
        else {request_str+=name + ":boolean=False&";}}\n
      if (type == "radio" && is_checked){request_str+=name + "="+value+"&";}\n
      if (type == "text" || type == "password"){request_str+=name + "=" + value + "&";}\n
    } );\n
  \n
  // select tags\n
  $("#" + form_dom_id).find("select").each(\n
    function (index) {\n
      element = $(this);\n
      name = element.attr("name");\n
      is_multiple = element.attr("multiple");\n
      value = element.val();\n
      if (is_multiple){\n
        //support multifield selects in gadget edit form\n
        element.children("option").each(\n
          function (index) {\n
            option = $(this);\n
            if(option.attr("selected")){request_str+=element.attr("name") + \'=\' + option.val() + \'&\';}\n
          }); }\n
       else{request_str+=name + \'=\' + value + \'&\';} });\n
  \n
  // save form preferences to remote server\n
  $.ajax({url: knowledge_box_edit_script_id + "?" + request_str,\n
          dataType: "json",\n
          success: function (data){\n
                     if (data.validation_status){\n
                       // server side validation passed\n
                       updater(view_form_url, box_relative_url, visual_block_dom_id);\n
                       $("#" + form_dom_id).toggle();\n
                       // clean error messages\n
                       $("#" + form_dom_id + " span.error").remove();\n
                     }\n
                     else{\n
                       // server side validation failed show error message\n
                       $("#" + form_dom_id + " div.edit-form-content").html(data.content);\n
                     }\n
          } });\n
}\n
\n
function updateServerBoxColumnLayout(event, ui){\n
  /* read columns structure from DOM  and save it to server */\n
  var columns_arr = new Array;\n
  var columns = $("div.portal-column");\n
  // sort alphabetically as it\'s required to get proper layout from DOM\n
  columns.sort(function(a, b) {\n
                 var compA = $(a).attr("id").toUpperCase();\n
                 var compB = $(b).attr("id").toUpperCase();\n
                return (compA < compB) ? -1 : (compA > compB) ? 1 : 0;});\n
\n
  columns.each(function(column_index, column){\n
    column = $(this);\n
    var items_arr = new Array;\n
    column_items = column.find("div.block");\n
    column_items.each(function(box_index, box){\n
      items_arr[box_index] = column_items[box_index].id;});           \n
    columns_arr[column_index] = items_arr.join(\'|\');});\n
  \n
  var layout = columns_arr.join("##");\n
  // .. and send it to server only if it\'s different\n
  if (layout!=last_layout){\n
    last_layout = layout;\n
    $.ajax({url: knowledge_pad_save_layout_script_id, \n
            data: {user_layout: layout}});}\n
}\n
\n
function showAddNewPadPopup(){\n
  $("#add_new_tab_dialog").toggle();\n
  // set focus on new Pad title after toggle effect is over \n
  setTimeout("$(\'#new_pad_title\').focus()", 500 );\n
}\n
\n
function showRenamePadPopup(knowledge_pad_relative_url, knowledge_pad_title_dom_id){\n
  // set current active pad\' url & title dom element id\n
  active_knowledge_pad_relative_url = knowledge_pad_relative_url;\n
  active_knowledge_pad_title_dom_id = knowledge_pad_title_dom_id;\n
  // init rename dialog input field to current active pad\n
  $("#new_knowledge_pad_title")[0].value = $("#"+knowledge_pad_title_dom_id)[0].innerHTML;\n
  // show rename dialog\n
  $("#rename_tab_dialog").toggle();\n
  // set focus on new Pad title after toggle effect is over \n
  setTimeout("$(\'#new_knowledge_pad_title\').focus()", 500);\n
}\n
\n
function loadPadFromServer(pad_relative_url, selected_pad_dom_id, mode){\n
  /* Load Pad from server */\n
  //  show some animation\n
  $("#loading-wrapper").first().show();\n
  $.ajax({url: knowledge_pad_as_json_script_id, \n
          data: {pad_relative_url: pad_relative_url,\n
                 mode: mode},\n
          dataType: "json",\n
          success: handleServerSuccess});\n
  // set old pad to not selected\n
  old_selected_pad = $("#tabs ul").children("li.tab_selected").first();\n
  old_selected_pad.removeClass("tab_selected");\n
  old_selected_pad.addClass("tab");\n
  \n
  pad_actions = old_selected_pad.children("div.pad-actions").first();\n
  pad_actions.hide();\n
   \n
  // set new selected pad class \n
  new_selected_pad = $("#" + selected_pad_dom_id).first();\n
  new_selected_pad.addClass("tab_selected");\n
  \n
  // enable "settings" for this pad and hide instant switch\n
  pad_actions = new_selected_pad.children("div.pad-actions").first();\n
  pad_actions.show();\n
  \n
  // set new active pad\n
  active_knowledge_pad_relative_url = pad_relative_url;\n
  \n
  // update "Add Gadget" link\n
  current_url = $("#add-gadgets").attr("href");\n
  new_url = current_url.substring(0, current_url.indexOf("active_pad_relative_url=")+24)+active_knowledge_pad_relative_url;\n
  $("#add-gadgets").attr("href", new_url);\n
  \n
  //function metadataFetchFailed(meta){}\n
  function handleServerSuccess(data){\n
    body = data.body;\n
    javascript = data.javascript;\n
    body_element = $("#pad-body-wrapper")[0];\n
    body_element.innerHTML = body;\n
    // init new Pad\n
    initialize();\n
    // execute JS code provided by server\n
    eval(javascript);\n
    // give some timeout as we can be sometimes two fast loading a tab\n
    setTimeout("$(\'#loading-wrapper\').first().hide();", 250 );}\n
}\n
\n
function addPadOnServerOnEnter(event, mode, cancel_url){\n
  /* Catch and submit form when ENTER is pressed */\n
  if(event.keyCode == 13){\n
    addPadOnServer(mode, cancel_url);\n
    return false;}\n
}\n
\n
function addPadOnServer(mode,\n
                        cancel_url){\n
  /* add pad on server */\n
  pad_title_value = $("#new_pad_title").first().val();\n
  window.location = add_new_knowledge_pad_script_id + "?redirect_url=" + cancel_url + "&mode=" + mode + "&pad_title=" + pad_title_value;\n
}\n
\n
function removeKnowledgePadFromServer(knowledge_pad_relative_url, mode){\n
  /* remove pad from server*/\n
  if (is_knowledge_template_used){\n
    showCreateDefaultKnowledgePadWarningMessage();}\n
  else{\n
    var user_choice = true;\n
    user_choice = confirm("Are you sure you want to remove this pad from your home?");\n
    if (user_choice===true){\n
      location.href=knowledge_pad_delete_script_id + "?knowledge_pad_relative_url=" + knowledge_pad_relative_url+"&mode="+mode;} }\n
}\n
\n
function renameKnowledgePadToServerOnEnter(event){\n
  if(event.keyCode == 13){\n
    renameKnowledgePadToServer();\n
    return false;}\n
  return true;\n
}\n
\n
function renameKnowledgePadToServer(){\n
  if (is_knowledge_template_used){\n
    showCreateDefaultKnowledgePadWarningMessage();}\n
  else{\n
    // rename it locally and update server asynchonously\n
    title_element = $("#"+active_knowledge_pad_title_dom_id).first();\n
    input_element = $("#new_knowledge_pad_title");\n
    var knowledge_pad_title = input_element.val();\n
    title_element.html(knowledge_pad_title);\n
    $.ajax({url: knowledge_pad_rename_script_id, \n
            data: {knowledge_pad_relative_url: active_knowledge_pad_relative_url,\n
                   knowledge_pad_title: knowledge_pad_title}});                                           \n
  }\n
  $("#rename_tab_dialog").toggle();\n
}\n
\n
function initialize(){\n
  // initialize sortable columns\n
  if (is_knowledge_template_used===0){\n
    // allow drag and drop only if we are dealing with a pad we can modify\n
    sortable_list = $("div.portal-column");\n
    function makeSortables(index){\n
      element = $(this);\n
      if (element.attr("class") == "portal-column"){\n
        // eliminate undraggable columns by checking exact match\n
        element.sortable({handle: "h3.handle",\n
                          connectWith: sortable_list,\n
                          placeholder: "block-hover",\n
                          forcePlaceholderSize: 1,\n
                          opacity: 0.8,\n
                          containment: "document",\n
                          delay: 100,\n
                          stop: updateServerBoxColumnLayout});} }\n
    if (sortable_list!==null) sortable_list.each(makeSortables);\n
  }\n
\n
  // enable show/hide tabs\n
  gadgets_tabs = $("#tabs");\n
  gadgets_tabs_switcher = $("#tabs_switcher");  \n
  add_gadget = $("#add_new_gadget_link");\n
  \n
  function toggleTabNavigation(){\n
    /* Toggle tabs navigation */\n
    var is_tabs_visible=0;\n
    if($("#tabs").css("display")!="block"){\n
      is_tabs_visible=1;\n
      $("#tab_switcher_visible").show();\n
      $("#tab_switcher_hidden").hide();}\n
    else{\n
      $("#tab_switcher_visible").hide();\n
      $("#tab_switcher_hidden").show();}\n
    $("#tabs").toggle();\n
    createCookie("is_tabs_visible", is_tabs_visible, 365); }\n
 \n
  function bindGadgetHandlers(index, box){\n
    /* Bind all gadgets handlers */\n
    box = $(this);\n
    var edit = box.find("a.block-edit-form").first();\n
    var edit_form = box.find("div.edit-form").first();\n
    var remove = box.find("a.block-remove").first();   \n
    var minimize = box.find("a.block-minimize").first(); \n
    var minimize_wrapper = box.find("div.minimize_wrapper").first(); \n
    if(minimize){\n
      minimize.unbind("click");\n
      minimize.bind("click", function (){\n
        if (is_knowledge_template_used){showCreateDefaultKnowledgePadWarningMessage();}\n
        else{\n
          minimize_wrapper.toggle();\n
          box_id = box.attr("id");\n
          js_dom_id = box_id + "_content";\n
          js_code = invisible_gadgets[js_dom_id];\n
          if (js_code!=undefined){\n
            eval(js_code);\n
            // gadget is now visible, i.e. no need to query server just toggle locally dom\n
            delete invisible_gadgets[js_dom_id];}\n
           $.ajax({url: knowledge_box_toggle_script_id, \n
                   data: {box_relative_url: box_id}});\n
           }\n
        });}\n
\n
    if(edit){\n
      edit.unbind("click");\n
      edit.bind("click", function (){\n
        if (is_knowledge_template_used){showCreateDefaultKnowledgePadWarningMessage();}\n
        else{edit_form.toggle();}});}\n
        \n
    if(remove){\n
      remove.unbind("click");\n
      remove.bind("click", function (){\n
        if (is_knowledge_template_used){showCreateDefaultKnowledgePadWarningMessage();}\n
        else{\n
          user_choice = confirm("Are you sure you want to remove this gadget from your personalized page?");\n
          if (user_choice===true){\n
            box_id = box.attr("id");\n
            box.toggle();\n
            $.ajax({url: knowledge_pad_delete_box_script_id, \n
                    data: {box_relative_url: box_id}});}\n
        }});}\n
  }\n
  \n
  // tabs navigation\n
  if(gadgets_tabs_switcher){\n
    gadgets_tabs_switcher.unbind("click");\n
    gadgets_tabs_switcher.bind("click", toggleTabNavigation);}\n
  \n
  // for each box (gadget) add respective event handlers\n
  gadget_list = $("div.block");\n
  if (gadget_list!==null){\n
    gadget_list.each(bindGadgetHandlers);\n
    // when dom is loaded we need to remove all gadget\'s scripts otherwise currently when a gadget is moved\n
    // its HTML is getting executed again, thus making unecessary calls to server, etc ...\n
    gadget_list.each(\n
      function (index, box){  $(this).find("script").remove();});\n
  }\n
}\n
\n
// call function after load of document\n
$(document).ready(initialize);

]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>18140</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
