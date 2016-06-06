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
            <value> <string>ung.js</string> </value>
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

$.fn.outerHTML = function() {\n
    $t = $(this);\n
    if( "outerHTML" in $t[0] )\n
    { return $t[0].outerHTML; }\n
    else\n
    {\n
        var content = $t.wrap(\'<div></div>\').parent().html();\n
        $t.unwrap();\n
        return content;\n
    }\n
};\n
\n
function getCurrentObjectUrl(){\n
  return window.location.href.split("?")[0];\n
}\n
\n
function toogleLoading(is_toogle, _message) {\n
  var loading_wrapper;\n
  if (is_toogle) {\n
    loading_wrapper = $("#loading-wrapper").first();\n
    toogleLoading.prototype.old_loading_message = loading_wrapper.find(\'p\')[0].textContent;\n
    loading_wrapper.find(\'p\')[0].textContent = _message;\n
    loading_wrapper.show();\n
  }\n
  else {\n
    loading_wrapper = $("#loading-wrapper").first();\n
    loading_wrapper.hide();\n
    loading_wrapper.find(\'p\')[0].textContent = toogleLoading.prototype.old_loading_message;\n
  }\n
}\n
\n
function changeLanguage(language){\n
  $.ajax({\n
     url: "WebSite_changeLanguage?language=" + language,\n
     async: false,\n
     success: function(){\n
       window.location.reload();\n
     }\n
  });\n
}\n
\n
function getPortalTypeFromContext(){\n
  var response = $.ajax({\n
                    url: "getPortalType",\n
                    method: "GET",\n
                    async: false\n
                }).responseText;\n
  return response;\n
}\n
\n
function getUrlParameterList(){\n
  var argumentList = {};\n
  var resultList = window.location.href.split("?");\n
  if (resultList.length > 1) {\n
    var parameterList = resultList[1].split("&");\n
    for (var i=0;i<parameterList.length;i++){\n
      parameter = (parameterList[i].replace(":int","")).split("=");\n
      argumentList[parameter[0]] = parameter[1];\n
    }\n
  }\n
  return argumentList;\n
}\n
\n
function getObjectPropertyValue(method_name){\n
  return $.ajax({\n
            url: method_name,\n
            async: false\n
         }).responseText;\n
}\n
\n
function showNotImplementedMessage(tag){\n
  $(tag).fadeIn(500).delay(1000).fadeOut(800);\n
}\n
\n
function updateWebPage(){\n
  var parameterList = getUrlParameterList();\n
  url = "WebPage_updateWebDocument?document_path=" +\n
         parameterList.document_path;\n
  $.get(url, {}, function(data, textStatus, XMLHttpRequest){\n
    response = jQuery.parseJSON(data);\n
    if (response.status != 200){\n
      setTimeout(updateWebPage(), 1500);\n
    }\n
    else {\n
      clearTimeout();\n
      window.location = getCurrentObjectUrl() + "?editable_mode:int=1";\n
    }\n
  });\n
}\n
\n
function checkConversion(){\n
  $.get("Base_getDocumentConversionState?path=" + parameterList.document_path, {},\n
                                               function(data, textStatus, XMLHttpRequest){\n
     status = jQuery.parseJSON(data);\n
     switch (status) {\n
      case "converted":\n
        $("a#loading_message").text("Opening your Document...");\n
        clearTimeout();\n
        setTimeout(updateWebPage(), 1000);\n
        break;\n
      case "conversion_failed":\n
        clearTimeout();\n
        $("a#loading_message").text("Problems to convert your document...");\n
        setTimeout(window.location.href = window.location.href.match("^http.*\\/ung")[0], 3000);\n
        break;\n
      default:\n
        setTimeout(checkConversion(), 1500);\n
        break;\n
     }\n
  });\n
}\n
\n
function setObjectPropertyValue(method_name, value, parameter){\n
  $.ajax({\n
        type: "POST",\n
        url: method_name,\n
        data: parameter + "=" + value,\n
        async: false\n
  });\n
  return true;\n
}\n
\n
function changeCheckBoxValue(value){\n
  $("table.listbox tbody tr td.listbox-table-select-cell input").each(function(){\n
    this.checked = value;\n
  });\n
}\n
\n
function waitCreateUNGUser(paramStr){\n
  $.get("ERP5Site_checkIfUserExist?" + paramStr, {}, function(data, textStatus, xhr){\n
     data = jQuery.parseJSON(data);\n
     if (data.response === true){\n
       clearTimeout();\n
       window.location.reload();\n
     }\n
     else {\n
       setTimeout(waitCreateUNGUser(paramStr), 3500);\n
     }\n
  });\n
}\n
\n
function displayFormMessage(message, delay){\n
  $("td#form-message").text(message);\n
  $("td#form-message").fadeIn(300).delay(delay).fadeOut(1000);\n
}\n
\n
function displayLoginForm(){\n
  var tagToHide = "a.ung_docs, img[alt=\'calendar_logo_box\']," +\n
                  "table#create-new-user, img[alt=\'mail_logo_box\']" +\n
                  ", div.navigation";\n
  $(tagToHide).hide();\n
  $("div.header-left div.field input, div.main-right, div.main-left").hide();\n
  $.get("WebSection_loginDialog", function(data){\n
    // set body\n
    $("div.header-left fieldset.widget").append("<p>" + data + "</p>");\n
    // fix \'ENTER\' key to form submit on firefox browser\n
    $("//input[id=\'name\'], //input[id=\'password\']").bind(\'keyup\', function(e) {\n
      if (e.which == 13) {\n
          $(\'form#main_form\').submit();\n
          e.preventDefault();\n
      }\n
    });\n
    // set "new account form" behaviour\n
    $("td#new-account-form").click(function(event){\n
      $("table#field_table, table#new-account-table").hide();\n
      $("table#create-new-user input[type=\'text\'], table#create-new-user input[type=\'password\']").each(function(){\n
        $(this).attr("value", "");\n
      });\n
      $("table#field_table, table#new-account-table, table#create-new-user").css("width", "100%");\n
      $("table#create-new-user").show();\n
      $("td#back-login").click(function(event){\n
        reloadLoginPage(event);\n
      });\n
      $("form#create-user").submit(function(event){\n
        event.preventDefault();\n
        var formHash = {};\n
        var paramList = $("form#create-user").serializeArray();\n
        for (var i=0; i < paramList.length; i++){\n
          formHash[paramList[i].name] = paramList[i].value;\n
        }\n
        if (formHash.password != formHash.confirm){\n
          displayFormMessage("Please confirm your password correctly..", 3500);\n
          return false;\n
        }\n
        $.getJSON(\'ERPSite_createUNGUser?\' + $("form#create-user").serialize(), function(response){\n
          if (response === null){\n
            displayFormMessage(formHash.login_name + " is not available, please try another...", 3500);\n
            return false;\n
          }\n
          else {\n
            displayFormMessage("The user " + formHash.login_name + " will be created in few seconds...", 8000);\n
            var paramStr = "reference=" + formHash.login_name;\n
            setTimeout(waitCreateUNGUser(paramStr), 2000);\n
          }\n
          return true;\n
        });\n
        return true;\n
      });\n
    });\n
  });\n
}\n
\n
function reloadLoginPage(event){\n
  event.preventDefault();\n
  if ($("div#main-content").html() === null){\n
    displayLoginForm();\n
  }\n
  if ($("table#create-new-user").css("display") != "none"){\n
    $("table#field_table, table#new-account-table, table#create-new-user").css("width", "78%");\n
    $("table#create-new-user").hide();\n
    $("table#field_table, table#new-account-table").show();\n
  }\n
}\n
\n
function displayDocumentTitle(title){\n
  var document_title = title;\n
  document_title === null ? document_title = getObjectPropertyValue("getTitle"): null;\n
  if (document_title.length > 30){\n
    $("a[name=\'document_title\']").html(document_title.substring(0,30) + "...");\n
  }\n
  else{\n
    $("a[name=\'document_title\']").html(document_title);\n
  }\n
}\n
\n
// XXX: refactor to upgrade performance of \'updateListboxSelection\' function\n
function updateListboxSelection() {\n
  var data_params = $(\'form#main_form\').serializeArray();\n
  $(\'input[name="knowledge_pad_module_ung_knowledge_pad_ung_docs_listbox_content_listbox_uid:list"]\').each(function() {\n
      data_params.push({\n
        \'name\': \'listbox_uid:list\',\n
        \'value\': this.value\n
      });\n
    });\n
  $.ajax({\n
        async: false,\n
        type: \'POST\',\n
        url: \'Base_updateListboxSelection\',\n
        data: $.param(data_params)\n
  });\n
}\n
\n
$().ready(function(){\n
  $("p.clear").remove();\n
  if ($("a#login").html() !== null){\n
    displayLoginForm();\n
    return 0;\n
  }\n
  if ($("div.gadget-column").length === 0) {\n
    parameterList = getUrlParameterList();\n
    if (parameterList.hasOwnProperty("upload_document") === true){\n
      $("a[name=\'document_title\'], a[name=\'document_state\'], div.header-right, div.content").hide();\n
      $("a#loading_message").show();\n
      setTimeout(checkConversion(), 1000);\n
    }\n
    else {\n
      switch (getPortalTypeFromContext()) {\n
        case "Web Page":\n
          $("div.content").css({"position":"fixed", "bottom": "0px",\n
                                "left": "0px", "right": "0px"});\n
          $("div.content").css({"top": "5em"});\n
          break;\n
        case "Web Table":\n
          $("div.content").css({"position":"fixed", "bottom": "0px",\n
                                "left": "0px", "right": "0px"});\n
          $("div.content").css({"top": "6em"});\n
          $.getJSON("Base_getPreferencePathList", function(data){\n
            var ungPreferencePath = data.preference;\n
            $.get(ungPreferencePath + \'/getPreferredThemeSheetEditor\', function(data){\n
              link = $("<link>");\n
              link.attr("id", "dynamic_css");\n
              link.attr({type: \'text/css\', rel:\'stylesheet\', href:data});\n
              $("head").append(link);\n
            });\n
          });\n
          break;\n
        default: break;\n
      }\n
      displayDocumentTitle(null);\n
    }\n
  }\n
  $("input#upload").click(function(event){\n
    event.preventDefault();\n
    $("#upload_document").dialog("open");\n
  });\n
  $("tbody tr td.listbox-table-domain-tree-cell a").each(function(){\n
    if ($(this).text().length == 16){\n
      $(this).css("padding-right", "82px");\n
    }\n
    if ($(this).text().length > 16){\n
      $(this).css("padding-right", "24px");\n
    }\n
  });\n
\n
  if ($("div.listbox-domain-tree-container").length < 1) {\n
    $("div.action_menu ul li a").click(function(event){\n
      event.preventDefault();\n
      herfList = this.getAttribute("href").split("?");\n
      action_name = herfList[herfList.length-1].split("=")[1];\n
      $.ajax({\n
             url: "Base_changeWorkflowState",\n
             data: "action_name=" + action_name,\n
             success: function(){\n
               window.location.reload();\n
             }\n
      });\n
    });\n
    if ($("a[name=\'document_state\']").text() == "Draft") {\n
      $("div.action_menu li ul").append("<li><a id=\'share_document\' href=\'#\'>" +\n
                                        "<h6>Share this Document</h6></a></li>");\n
      $("div.action_menu ul li a#share_document").click(function(event){\n
        event.preventDefault();\n
        $.ajax({\n
               url: \'WebPage_shareDocument\',\n
               async: false\n
        });\n
        location.reload();\n
      });\n
    }\n
    $("div.action_menu li ul").css("height", $("div.action_menu li ul li").length * 25.3 + "px");\n
  }\n
\n
  $("#edit_document").dialog({\n
    autoOpen: false,\n
    height: 131,\n
    width: 389,\n
    modal: true,\n
    buttons: {\n
      "Save": function(){\n
        var save_button = $("button.save");\n
        save_button.html() == "Save" ? save_button.html("Saving...") : null;\n
        var new_title = $("input#name.title").attr("value");\n
        var new_short_title = $("input#short_title.short_title").attr("value");\n
        var new_language = $("input#language.language").attr("value");\n
        var new_version = $("input#version.version").attr("value");\n
        var new_int_index = $("input#sort_index.sort_index").attr("value");\n
        var new_subject_list = $("textarea#keyword_list").attr("value").replace(/\\n+/g, ",");\n
        displayDocumentTitle(new_title);\n
        setObjectPropertyValue("setTitle", new_title, "value");\n
        setObjectPropertyValue("setShortTitle", new_short_title, "value");\n
        setObjectPropertyValue("setLanguage", new_language, "language");\n
        setObjectPropertyValue("setVersion", new_version, "value");\n
        setObjectPropertyValue("setIntIndex", new_int_index, "value");\n
        setObjectPropertyValue("WebPage_setSubjectList", new_subject_list, "value");\n
        $("#edit_document").dialog("close");\n
        save_button.click();\n
      },\n
      Cancel: function() {\n
        $(this).dialog("close");\n
      }\n
    }\n
  });\n
  $("#upload_document").dialog({\n
    autoOpen: false,\n
    height: 116,\n
    width: 346,\n
    modal: true\n
  });\n
  $("div.gadget-listbox").dialog({\n
    autoOpen: false,\n
    height: 416,\n
    width: 600,\n
    modal: true,\n
    buttons: {\n
      "Add": function(){\n
         var gadgetIdList = Array();\n
         $("table#gadget-table tbody tr td input").each(function(){\n
           if (this.checked){\n
             gadgetIdList.push($(this).attr("id"));\n
           }\n
         });\n
         if (gadgetIdList.length === 0){\n
           $(this).dialog("close");\n
         }\n
         var tabTitle = $("div#tabs ul li.tab_selected span").html();\n
         $.ajax({\n
           type: "post",\n
           url:"WebSection_addGadgetList",\n
           data: [{name:"gadget_id_list", value: gadgetIdList}],\n
           success: function(data) {\n
             window.location.reload();\n
           }\n
         });\n
      }\n
    }\n
  });\n
  $("div#preference_dialog").dialog({\n
    autoOpen: false,\n
    height: \'auto\',\n
    width: \'auto\',\n
    modal:true,\n
    show: \'drop\',\n
    buttons: {\n
      "Save": function(){\n
        var erp5PreferenceArgument = $("form#erp5_preference").serialize();\n
        $.ajax({\n
          async: false,\n
          url: ungPreferencePath + "/Base_edit",\n
          data: erp5PreferenceArgument + "&form_id=Preference_viewHtmlStyle"\n
        });\n
        var ungPreferenceArgument = $("form#ung_preference").serialize();\n
        $.ajax({\n
          async: false,\n
          url: ungPreferencePath + "/Base_edit",\n
          data: ungPreferenceArgument + "&form_id=UNGPreference_view"\n
        });\n
        location.reload();\n
      },\n
      Cancel: function() {\n
        $(this).dialog("close");\n
      }\n
    }\n
  });\n
  $("p#more_properties").click(function(){\n
      $("div#more_property").show();\n
      $("p#hide_properties").show();\n
      $("div#edit_document fieldset").animate({"height": "186px"}, "slow");\n
      $("div.ui-dialog").animate({"top": "50px"}, "slow").animate({"height": "255px"}, "slow");\n
      $("div#edit_document").animate({"height": "183px"}, "slow");\n
      $("div#edit_document fieldset input").css("margin", "0").css("width", "60%");\n
      $("div#edit_document fieldset label").css("float", "left").css("width", "35%");\n
      $("div#more_property input").css("width", "47%");\n
      $("p#more_properties").hide();\n
    });\n
  $("p#hide_properties").click(function(){\n
      $("div#more_property").hide();\n
      $("p#more_properties").show();\n
      $("p#hide_properties").hide();\n
      $("div#edit_document fieldset input").css("width", "95%").css("margin-top", "14px");\n
      $("div#edit_document fieldset").animate({"height": "69px"}, "slow");\n
      $("div.ui-dialog").animate({"height": "148px"}, "slow");\n
      $("div#edit_document").animate({"height": "78px"}, "slow");\n
  });\n
  $("a#settings").click(function(event){\n
      event.preventDefault();\n
      if ($("div#preference_dialog").html() === ""){\n
        $.ajax({\n
          url: "Base_getPreferencePathList",\n
          async: false,\n
          dataType: \'json\',\n
          success: function(data){\n
            ungPreferencePath = data.preference;\n
            $.ajax({\n
              url: ungPreferencePath + \'/Preference_viewHtmlStyle?editable_mode:int=1\',\n
              async: false,\n
              method: \'get\',\n
              success: function(data){\n
                $("div#preference_dialog").append("<form id=\'erp5_preference\'>" +\n
                                                  "<fieldset class=\'center editable\'>" +\n
                                                  $(data).find(\'fieldset.center.editable\').html() +\n
                                                  "</fieldset></form>");\n
                }\n
            });\n
            $.ajax({\n
              url: ungPreferencePath + \'/UNGPreference_view?editable_mode:int=1\',\n
              async: false,\n
              method: \'get\',\n
              success: function(data){\n
                $("div#preference_dialog").append("<form id=\'ung_preference\'>" +\n
                                                  "<fieldset class=\'center editable\'>" +\n
                                                  $(data).find(\'fieldset.center.editable\').html() +\n
                                                  "</fieldset></form>");\n
                }\n
            });\n
          }\n
        });\n
      }\n
      $("div#preference_dialog").dialog("open");\n
    });\n
\n
  $("button#change_state").click(function(event){\n
      event.preventDefault();\n
      $("div#change_state_dialog").html(\'\');\n
      // update portal selections\n
      updateListboxSelection();\n
      $.ajax({\n
        async: false,\n
        url: \'erp5/Folder_viewWorkflowActionDialog\',\n
        data: {selection_name: $(\'input[name=list_selection_name]\').val(),\n
               form_id: $(\'input[name=gadget_form_id]\').val(),\n
               editable_mode: 1\n
              },\n
        success: function(data2) {\n
          folder_workflow_action_dialog_data = data2;\n
          $("div#change_state_dialog").append("<form id=\'change_state_form\'>" +\n
                                              "<div class=\'change_state_dialog\'>" +\n
                                              "<table class=\'listbox listbox-table\'>" +\n
                                              "  <thead>" +\n
                                              "    <tr class=\'listbox-label-line\'>" +\n
                                              "            <th class=\'listbox-table-header-cell\'>Count</th>" +\n
                                              "            <th class=\'listbox-table-header-cell\'>Type</th>" +\n
                                              "            <th class=\'listbox-table-header-cell\'>State</th>" +\n
                                              "            <th class=\'listbox-table-header-cell\'>Workflow</th>" +\n
                                              "            <th class=\'listbox-table-header-cell\'>Action</th>" +\n
                                              "    </tr>" +\n
                                              "  </thead>" +\n
                                              "  <tbody>" +\n
                                              $(data2).find(\'div.listbox-body > table > tbody\').html() +\n
                                              "  </tbody></table>" +\n
                                              "  </div>" +\n
                                              $(data2).find(\'textarea[name*="comment"]\').parent().parent().html() +\n
                                              "</form>");\n
          $("div#change_state_dialog").dialog("open");\n
        }\n
      });\n
    });\n
  $("div#change_state_dialog").dialog({\n
    autoOpen: false,\n
    height: \'auto\',\n
    width: 680,\n
    modal:true,\n
    buttons: {\n
      \'Change State\': function() {\n
        var folder_workflow_data = $(folder_workflow_action_dialog_data).find(\'input[type="hidden"]\').serializeArray();\n
        var change_state_data = $(\'form#change_state_form\').serializeArray();\n
        var merge = {};\n
        $.map(folder_workflow_data, function(n,i){merge[n.name] = n.value;});\n
        $.map(change_state_data, function(n,i){merge[n.name] = n.value;});\n
        merge[\'form_id\'] = \'WebSection_viewUNGDocumentList\';\n
        $.ajax({\n
          async: false,\n
          url: \'web_site_module\' + "/Base_callDialogMethod",\n
          data: merge,\n
          success: function(result){\n
            var form_data = $(result).find(\'input[type="hidden"]\').serializeArray();\n
            var merge2 = {};\n
            $.map(form_data, function(n,i){merge2[n.name] = n.value;});\n
            $.ajax({\n
              async: false,\n
              url: \'web_site_module\' + "/Base_callDialogMethod",\n
              data: merge2,\n
              success: function(result2){\n
                $("div#change_state_dialog").dialog("close");\n
                setPortalStatusMessage("Workflow in progress. Please refresh your page to take changes.");\n
              }\n
            });\n
          }\n
        });\n
      },\n
      Cancel: function() {\n
        $( this ).dialog("close");\n
      }\n
    }\n
  });\n
\n
  $("button.ui-button, span.ui-icon").click(function(){$("p#hide_properties").click();});\n
  $("input#submit_document").click(function(event){\n
    if (document.getElementById("upload-file").value === ""){\n
      event.preventDefault();\n
      $("span#no-input-file").show();\n
    }\n
  });\n
  $("a[name=\'document_title\']").click(function(){\n
      $("div#more_property").hide();\n
      $("p#hide_properties").hide();\n
      var document_title = getObjectPropertyValue("getTitle");\n
      if ($("input#name.title").attr("value") != document_title) {\n
        displayDocumentTitle();\n
      }\n
      $("input#name.title").attr("value", document_title);\n
      $("input#short_title.short_title").attr("value", getObjectPropertyValue("getShortTitle"));\n
      $("input#reference.reference").attr("value", getObjectPropertyValue("getReference"));\n
      $("input#version.version").attr("value", getObjectPropertyValue("getVersion"));\n
      $("input#language.language").attr("value", getObjectPropertyValue("getLanguage"));\n
      $("input#sort_index.sort_index").attr("value", getObjectPropertyValue("getIntIndex"));\n
      var subjectList = jQuery.parseJSON(getObjectPropertyValue(\'getSubjectList\').replace(/\'/g,\'"\'));\n
      if (subjectList !== null) {\n
        $("textarea#keyword_list").attr("value", subjectList.join("\\n"));\n
      } else {\n
        $("textarea#keyword_list").attr("value", "");\n
      }\n
      $("#edit_document").dialog("open");\n
    });\n
  $("a#help").click(function(event){\n
    event.preventDefault();\n
    showNotImplementedMessage("a#right_message");\n
  });\n
  $("span#knowledge_pad_module_8_titlean").text("1");\n
  if ($("#tab-list-container #tabs ul li").length > 2) {\n
    $("li#add_new_tab_dialog_link.tab").hide();\n
  }\n
  $("div#add_new_gadget_link a#add-gadgets").removeAttr("onclick");\n
  $("div#add_new_gadget_link a#add-gadgets").click(function(event){\n
    event.preventDefault();\n
    // fill gadget list\n
    $.getJSON("WebSection_getGadgetPathList", function(to_parse_data){\n
      gadgetList = jQuery(to_parse_data);\n
      gadgetList.each(function(){\n
        $("div.gadget-listbox table#gadget-table").append($(\'<tr>\').append($(\'<td>\').append($(\'<input>\').attr(\'type\', \'checkbox\').attr(\'id\', this.id))).append($(\'<td>\').append($(\'<a>\').text(this.title))).append($(\'<td>\').append($(\'<img>\').attr(\'src\', this.image_url).text(this.title))));\n
        });\n
    });\n
    $("div.gadget-listbox").dialog("open");\n
  });\n
  $("div#page_wrapper div#portal-column-1.portal-column, div#page_wrapper div#portal-column-2.portal-column").remove();\n
  var jScreen = jQuery(this);\n
  if (jScreen.width() < 1280){\n
    $("div.listbox-tree, div.gadget-action div.front_pad").css("width", "79%");\n
    $("td.listbox-table-domain-tree-cell a").css("padding-right", "25px");\n
    $("div.header-right").css("width", "52.3%");\n
  }\n
  $("a.tree-open").parent().parent().css("background-color", "#BBCCFF");\n
  if (window.location.href.match("^http.*\\/unfoldDomain") !== null){\n
    $("a.document").css("text-decoration", "none").css("color", "#000");\n
  }\n
  var h3Tag = $("div#page_wrapper div h3");\n
  if (h3Tag.text().replace(/^\\s+/,\'\').replace(/\\s+$/,\'\') == "Your tab is empty."){\n
    h3Tag.hide();\n
  }\n
\n
  if (!$("div.gadget-column").length === 0) {\n
    // render main document listbox\n
    $.ajax({\n
      async: false,\n
      url: \'WebSection_getUNGDocumentListPadAsJSON\',\n
      data: {pad_relative_url: \'knowledge_pad_module/ung_knowledge_pad\', mode: \'web_front\'},\n
      dataType: \'json\',\n
      success: function(data){\n
        external_data = data;\n
        var data_html = $(data.body)[0];\n
        //var data_script = $(data.body)[1].text\n
        var data_script = data.javascript;\n
\n
        ung_listbox_container = $(\'div#main_listbox-container\');\n
        // fill body\n
        ung_listbox_container.html(data_html);\n
        // attach listener\n
        ung_listbox_container.live(\'DOMSubtreeModified\', checkUNGListbox);\n
        // eval script to update listbox\n
        eval(data_script);\n
        // remove class \'portal-column\' from main listbox\n
        // (as it should not interfere in user\'s box layout)\n
        // updateServerBoxColumnLayout method uses \'div.portal-column\' as selector\n
        ung_listbox_container.find(\'div.portal-column\')[0].className = \'\';\n
\n
        configureUNGSearch(data_script);\n
\n
        wrapUpdater();\n
      }\n
    });\n
  }\n
  return false;\n
});\n
\n
function configureUNGSearch(data_script) {\n
  ung_listbox_updater_call = data_script;\n
  $(\'input#search_button\').click(function(event){\n
    event.preventDefault();\n
    var searched_text = $(\'input[name="field_your_search_text"]\').val();\n
\n
    // keep old function to call\n
    var originalUpdater = updater;\n
    // overwrite (shadowing) to change \'params\' param on the fly\n
    updater = function() {\n
      // \'params\' is the fifth param, so treat it\n
      params = arguments[4];\n
      params[\'SearchableText\'] = searched_text;\n
      originalUpdater.apply(this, arguments);\n
    };\n
    // eval script\n
    eval(data_script);\n
\n
    // restore old function\n
    updater = originalUpdater;\n
  });\n
}\n
\n
function wrapUpdater() {\n
  originalUpdater = updater;\n
  updater = wrappedUpdater;\n
}\n
\n
function wrappedUpdater() {\n
  dom_id = arguments[2];\n
  additional_request_params = arguments[4];\n
\n
  // let UNG save checked itens of main listbox under portal_selections\n
  enabled_checkboxes = $(\'#\'+dom_id).find(\'input[type="checkbox"]:checked\');\n
  enabled_checkboxes.each(function(key, value){\n
    element = $(value);\n
    element_name = element.attr("name");\n
    element_value = element.val();\n
    if (typeof(additional_request_params[element_name]) == "undefined") {\n
      additional_request_params[element_name] = new Array();\n
    }\n
    additional_request_params[element_name].push(element_value);\n
  });\n
  originalUpdater.apply(this, arguments);\n
}\n
\n
function checkUNGListbox() {\n
  gadget_listbox_container = $(\'div#main_listbox-container div.listbox-container\');\n
  if (gadget_listbox_container.length >= 1) {\n
    // XXX: the .die and .live calls are because of the call to .find function\n
    // that is triggered recursively without stop if parent has the .live\n
    // listener, like in this case\n
    ung_listbox_container.die(\'DOMSubtreeModified\');\n
\n
    // look if there\'s a listbox-tree (listbox-domain navigation) inside\n
    // main content of listbox. If it finds someone, then call\n
    // separate_script to detach fields of main content of listbox [again]\n
    if (gadget_listbox_container.find("div.listbox-tree").length >= 1) {\n
      separateUNGListboxGadgetFields();\n
    }\n
\n
    // re-attach listener\n
    ung_listbox_container.live(\'DOMSubtreeModified\', checkUNGListbox);\n
  }\n
}\n
\n
function separateUNGListboxGadgetFields() {\n
  // get gadget listbox container\n
  var data = gadget_listbox_container;\n
\n
  // remove menu of listbox container gadget\n
  ung_listbox_container.find(\'h3.handle\').remove();\n
\n
  // detach domain_selected\n
  $("a.domain_selected").text(data.find("button.tree-open:last").text());\n
\n
  // XXX: temporaly commented while developing\n
  // TODO: analyze if this css is breaking layout of \'global scope\'\n
//  $("body").css("overflow", "hidden");\n
\n
  // configure Refresh button\n
  configureRefreshButton();\n
\n
  // detach listbox-page-navigation\n
  var gadget_navigation = data.find("div.listbox-page-navigation");\n
  if (gadget_navigation) {\n
    ung_toolbar_navigation = $(\'div.toolbar\').find(\'div.listbox-navigation\');\n
    ung_toolbar_navigation.html(gadget_navigation.html());\n
    gadget_navigation.remove();\n
  }\n
\n
  // remove \'listbox-title\' from header\n
  $(\'div.listbox-title\').remove();\n
\n
  // detach css of listbox-tree\n
  var listboxTreeHeight = data.find("div.listbox-tree").css("height").replace("px", "");\n
  try {\n
    var domainTreeHeight = data.find("div.listbox-domain-tree-container").css("height").replace("px", "");\n
  } catch(e) {\n
    // this maybe categorize first access of user, needing\n
    // to reload page in time to create \'selection\' in portal_selections\n
    window.location.reload();\n
    return false;\n
  }\n
  if (parseInt(listboxTreeHeight,10) > parseInt(domainTreeHeight,10)){\n
    data.find("div.listbox-tree").css("height", data.find("div.listbox-domain-tree-container").css("height"));\n
  }\n
  if (parseInt(domainTreeHeight,10) > 233) {\n
    data.find("div.listbox-tree").css("overflow-y", "scroll");\n
  }\n
\n
  // detach listbox-tree\n
  var listbox_tree_div = data.find("div.listbox-tree").outerHTML();\n
  data.find("div.listbox-tree").remove();\n
  // XXX: improve this behaviour of replacing\n
  file_listbox_tree = $(\'div.file-quick-search\').find(\'div.listbox-tree\');\n
  if (file_listbox_tree.length >= 1) {\n
    file_listbox_tree.replaceWith(listbox_tree_div);\n
  } else {\n
    $("div.file-quick-search").append(listbox_tree_div);\n
  }\n
\n
  // detach css of listbox-body\n
  var tr_length = data.find("div.listbox-body tbody tr").length;\n
  if (tr_length < 16){\n
    var height = tr_length * 1.5;\n
    data.find("div.listbox-body tbody").css("height", height + "em");\n
  }\n
\n
  // hide listbox-page-navigation if doesn\'t need it\n
  if (data.find("div.listbox-page-navigation").text() == "null")\n
    data.find("div.listbox-page-navigation").hide();\n
\n
  // update checkAll and uncheckAll buttons under listbox\n
  $("input.listbox-check-all").click(function(event){\n
    event.preventDefault();\n
    changeCheckBoxValue(true);\n
  });\n
  $("input.listbox-uncheck-all").click(function(event){\n
    event.preventDefault();\n
    changeCheckBoxValue(false);\n
  });\n
  return true;\n
}\n
\n
function configureRefreshButton() {\n
  $(\'a#refresh_button\').click(function(event){\n
    event.preventDefault();\n
    // keep old function to call\n
    var originalUpdater = updater;\n
    // overwrite (shadowing) to change \'params\' param on the fly\n
    updater = function() {\n
      // \'params\' is the fifth param, so treat it\n
      params = arguments[4];\n
      params[\'reset:int\'] = 1;\n
      originalUpdater.apply(this, arguments);\n
    };\n
    // eval script\n
    eval(ung_listbox_updater_call);\n
\n
    // restore old function\n
    updater = originalUpdater;\n
  });\n
}\n
\n
function setPortalStatusMessage(status_message) {\n
    //display warning\n
    status_message_tag = $(\'div.portal_status_message\');\n
    status_message_tag.css("font-weight", "bold");\n
    status_message_tag.text(status_message);\n
}\n


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
