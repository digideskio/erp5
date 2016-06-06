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
            <value> <string>ung_calendar.js</string> </value>
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

function callBeforeRequest(type){\n
  switch(type){\n
    case 1:\n
      message = "Loading Events...";\n
      break;\n
    case 2:\n
      message = "Adding Event...";\n
      break;\n
    case 3:\n
      message = "Removing Event...";\n
      break;\n
    case 4:\n
      message = "The request is being processed ...";\n
      break;\n
    default: break;\n
  }\n
  $("#errorpannel").hide();\n
  $("#loadingpannel").html(message).show();\n
}\n
\n
function callAfterRequest(type){\n
  switch(type){\n
    default:\n
      $("#loadingpannel").hide();\n
      break;\n
  }\n
}\n
\n
function callOnError(type, data){\n
  $("#errorpannel").show();\n
}\n
\n
function Edit(data){\n
  var url ="WebSection_newEvent";\n
  $("div#new_event_dialog").dialog({\n
    title: "Update Event",\n
    buttons: {\n
      "Save": function(){\n
        var data = $("form#create_new_event").serializeArray();\n
        var dataHash = {};\n
        for (var i=0; i<data.length; i++)\n
          dataHash[data[i].name] = data[i].value;\n
        start_date = dataHash.start_date_month + "/" + \n
                    dataHash.start_date_day + "/" + \n
                    dataHash.start_date_year + " " + \n
                    dataHash.start_date_hour + ":" + \n
                    dataHash.start_date_minute;\n
  \n
        stop_date = dataHash.stop_date_month + "/" + \n
                    dataHash.stop_date_day + "/" + \n
                    dataHash.stop_date_year + " " + \n
                    dataHash.stop_date_hour + ":" + \n
                    dataHash.stop_date_minute;\n
\n
        var paramList = [{name : \'CalendarEndTime\', \'value\': stop_date},\n
                         {name : \'event_portal_type\', \'value\': dataHash.portal_type},\n
                         {name : \'CalendarStartTime\', \'value\': start_date},\n
                         {name : \'title\', \'value\': dataHash.title},\n
                         {name : \'request_type\', \'value\': \'update\'},\n
                         {name : \'event_id\', \'value\': $("input#event_id").attr("value")},\n
                         {name : \'event_text_content\', \'value\': dataHash.event_text_content}];\n
\n
        $.post("Base_updateCalendarEventList", paramList, function(){\n
                $("div#new_event_dialog").dialog("close");\n
                $("div#showreflashbtn.fbutton").click();\n
        });\n
      }\n
    }\n
  });\n
  $("div#new_event_dialog").load(url, {}, function(){\n
    $("form#create_new_event").append("<input type=\'hidden\' id=\'event_id\'/>");\n
    $("input#event_id").attr("value", data[9]);\n
    $("form#create_new_event select").val(data[10]);\n
    $("textarea[name=\'event_text_content\']").val(data[11]);\n
    $("input[name=\'title\']").attr("value", data[1]);\n
    $("input.start_date_field[name=\'start_date_year\']").attr("value", data[2].getFullYear());\n
    $("input.start_date_field[name=\'start_date_month\']").attr("value", (parseInt(data[2].getMonth(),10) + 1));\n
    $("input.start_date_field[name=\'start_date_day\']").attr("value", data[2].getDate());\n
    $("input.start_date_field[name=\'start_date_hour\']").attr("value", data[2].getHours());\n
    $("input.start_date_field[name=\'start_date_minute\']").attr("value", data[2].getMinutes());\n
\n
    $("input.stop_date_field[name=\'stop_date_year\']").attr("value", data[3].getFullYear());\n
    $("input.stop_date_field[name=\'stop_date_month\']").attr("value", (parseInt(data[3].getMonth(),10) + 1));\n
    $("input.stop_date_field[name=\'stop_date_day\']").attr("value", data[3].getDate());\n
    $("input.stop_date_field[name=\'stop_date_hour\']").attr("value", data[3].getHours());\n
    $("input.stop_date_field[name=\'stop_date_minute\']").attr("value", data[3].getMinutes());\n
  });\n
  $("div#new_event_dialog").dialog(\'open\');\n
}\n
\n
function View(data){\n
  var str = "";\n
  $.each(data, function(i, item){\n
    str += "[" + i + "]: " + item + "\\n";\n
  });\n
  alert(str);\n
}\n
\n
function Delete(data, callback){\n
  hiConfirm("Are You Sure to Delete this Event", \'Confirm\', function(r){ r && callback(0);});\n
}\n
\n
function submitEventOnEvent(event){\n
  var keynum;\n
  if(window.event){\n
    keynum = event.keyCode;\n
  }\n
  else if(event.which){\n
    keynum = event.which;\n
  }\n
  if (keynum == 13){\n
    createNewEvent();\n
  }  \n
}\n
\n
function createNewEvent(){\n
  $.post("EventModule_createNewEvent",\n
    $("form#create_new_event").serialize(), function(){\n
      $("div#new_event_dialog").dialog("close");\n
      $("div#showreflashbtn.fbutton").click();\n
  });\n
}\n
\n
function createFieldToInsertOnDialog(){\n
  return "<th class=\'cb-key\'>Event Type</th>" + \n
         "<td class=\'cb-value\'><select name=\'portal_type\'>" +\n
         "<option>Acknowledgement</option>" +\n
         "<option>Fax Message</option>" + \n
         "<option>Letter</option>" +\n
         "<option>Mail Message</option>" +\n
         "<option>Note</option>" + \n
         "<option>Phone Call</option>" +\n
         "<option>Short Message</option>" +\n
         "<option>Site Message</option>" + \n
         "<option>Visit</option>" +\n
         "<option>Web Message</option>" +\n
         "</select></td>";\n
}\n
\n
i18n.xgcalendar.content = "Title";\n
i18n.xgcalendar.location = "Event Id";\n
i18n.xgcalendar.participant = "Event Type";\n
i18n.xgcalendar.repeat_event = "Description";\n
i18n.xgcalendar.event = "Title";\n
\n
$(document).ready(function() {     \n
  var DATA_FEED_URL = "Base_updateCalendarEventList";\n
  var op = {\n
    view: "week",\n
    showday: new Date(),\n
    EditCmdhandler:Edit,\n
    DeleteCmdhandler:Delete,\n
    weekstartday: 0,\n
    ViewCmdhandler:View,\n
    onBeforeRequestData: callBeforeRequest,\n
    onAfterRequestData: callAfterRequest,\n
    onRequestDataError: callOnError,\n
    autoload:true,\n
    url: DATA_FEED_URL + "?request_type=list",\n
    quickAddUrl: DATA_FEED_URL + "?request_type=add",\n
    quickUpdateUrl: DATA_FEED_URL + "?request_type=update",\n
    quickDeleteUrl: DATA_FEED_URL + "?request_type=remove",\n
    loadFieldOnDialog: createFieldToInsertOnDialog \n
  };\n
  var $dv = $("#calhead");\n
  var _MH = document.documentElement.clientHeight;\n
  var dvH = $dv.height() + 2;\n
  op.height = _MH - dvH;\n
  op.eventItems = [];\n
  $("#gridcontainer").bcalendar(op).BcalGetOp();\n
  $("#caltoolbar").noSelect();\n
  //to show day view\n
  $("#showdaybtn").click(function(e) {\n
    $("div.toolbar-listview, div.event-listview").remove();\n
    $("#caltoolbar div.fcurrent").each(function() {\n
      $(this).removeClass("fcurrent");\n
    });\n
    $(this).addClass("fcurrent");\n
    var optionList = $("#gridcontainer").swtichView("day").BcalGetOp();\n
    $("div#display-datetime span#text-datetime").text(optionList.datestrshow);\n
  });\n
  //to show week view\n
  $("#showweekbtn").click(function(e) {\n
    $("div.toolbar-listview, div.event-listview").remove();\n
    $("#caltoolbar div.fcurrent").each(function() {\n
      $(this).removeClass("fcurrent");\n
    });\n
    $(this).addClass("fcurrent");\n
    var optionList = $("#gridcontainer").swtichView("week").BcalGetOp();\n
    $("div#display-datetime span#text-datetime").text(optionList.datestrshow);\n
  });\n
  //to show month view\n
  $("#showmonthbtn").click(function(e) {\n
    $("div.toolbar-listview, div.event-listview").remove();\n
    $("#caltoolbar div.fcurrent").each(function() {\n
      $(this).removeClass("fcurrent");\n
    });\n
    $(this).addClass("fcurrent");\n
    var optionList = $("#gridcontainer").swtichView("month").BcalGetOp();\n
    $("div#display-datetime span#text-datetime").text(optionList.datestrshow);\n
  });\n
  $("#showreflashbtn").click(function(e){\n
    $("#gridcontainer").reload();\n
  });          \n
  //Add a new event\n
  $("span.addcal").click(function() {\n
    var url ="WebSection_newEvent";\n
    var date = new Date();\n
    $("div#new_event_dialog").load(url, {}, function(){\n
      $("input.start_date_field[name=\'start_date_month\'], input.stop_date_field[name=\'stop_date_month\']").attr("value", date.getMonth()+1);\n
      $("input.start_date_field[name=\'start_date_day\'], input.stop_date_field[name=\'stop_date_day\']").attr("value", date.getDate());\n
      $("input.start_date_field[name=\'start_date_hour\'], input.stop_date_field[name=\'stop_date_hour\']").attr("value", date.getHours());\n
      $("input.start_date_field[name=\'start_date_minute\'], input.stop_date_field[name=\'stop_date_minute\']").attr("value", date.getMinutes());\n
    });\n
    $("div#new_event_dialog").dialog("open");\n
  });\n
  //go to today\n
  $("#showtodaybtn").click(function() {\n
    var optionList = $("#gridcontainer").gotoDate().BcalGetOp();\n
    $("div#display-datetime span#text-datetime").text(optionList.datestrshow);\n
  });\n
  //previous date range\n
  $("#sfprevbtn").click(function() {\n
    var optionList = $("#gridcontainer").previousRange().BcalGetOp();\n
    $("div#display-datetime span#text-datetime").text(optionList.datestrshow);\n
  });\n
  //next date range\n
  $("#sfnextbtn").click(function() {\n
    var optionList = $("#gridcontainer").nextRange().BcalGetOp();\n
    $("div#display-datetime span#text-datetime").text(optionList.datestrshow);\n
  });\n
  $("div#new_event_dialog").dialog({\n
    autoOpen: false,\n
    height: 248,\n
    width: 410,\n
    modal: true\n
  });\n
  $("#datepicker").datepicker({\n
    onSelect: function(dateText, inst){\n
      var dateList = dateText.split("/");\n
      var month = dateList[0] - 1;\n
      var day = dateList[1];\n
      var year = dateList[2];\n
      var optionList = $("#gridcontainer").gotoDate(new Date(year, month, day)).BcalGetOp();\n
      $("div#display-datetime span#text-datetime").text(optionList.datestrshow);\n
     }\n
  });\n
  $("input#submit-search").click(function(event){\n
    event.preventDefault();\n
    if ($("input[name=\'searchable-text\']").val() === "")\n
      return false;\n
    $("div#dvCalMain.calmain div#gridcontainer").css("background", "none repeat scroll 0 0 #FFFFFF");\n
    $("div#dvwkcontaienr.wktopcontainer").remove();\n
    $("div#gridcontainer div#dvtec.scolltimeevent").remove();\n
    if (document.getElementById("blank-result") !== null){\n
      $("div#blank-result").remove();\n
    }\n
    $("div#gridcontainer div.event-listview,div#gridcontainer div.toolbar-listview").remove();\n
    var tableList = Array();\n
    tableList.push("<div class=\'toolbar-listview\'>",\n
                   "<table width=\'100%\' cellspacing=\'0\' cellpadding=\'2\'>",\n
                   "<tbody>",\n
                   "<tr><td>",\n
                   "<a id=\'back-calendar\' href=\'#\'> « Back to Calendar</a>",\n
                   "</td><td id=\'resultview\'>Results:</td>",\n
                   "</tbody></table></div>");\n
    tableList.push("<div class=\'event-listview\'>");\n
    tableList.push("<table width=\'100%\' cellspacing=\'0\' cellpadding=\'2\'><tbody>");\n
    text = $("input[name=\'searchable-text\']").val();\n
    paramList = [{name: "request_type", value: "list"}];\n
    if (text !== "")\n
      paramList.push({name: "SearchableText", value: text});\n
    $.ajax({\n
           url:"Base_updateCalendarEventList",\n
           dataType: "json",\n
           data : paramList,\n
           success: function(data){\n
             var eventTableList = Array();\n
             var eventList = data.events;\n
             var currentDate = new Date();\n
             for (var i = 0; i < eventList.length; i++){\n
               var eventDate = new Date(eventList[i][2]);\n
               var hourSymbol = "am";\n
               if (eventDate.getMonth() == currentDate.getMonth() && eventDate.getDate() == currentDate.getDate()){\n
                 eventTableList.push("<tr id=\'today-event\'>");\n
               }\n
               else {\n
                 eventTableList.push("<tr>");\n
               }\n
               var dateSplitted = eventList[i][2].split(" ");\n
               if (eventDate.getHours() >= 12)\n
                 hourSymbol = "pm";\n
               eventTableList.push("<td id=\'event-date\'>",\n
                                   dateSplitted[0],\n
                                   "</td>");\n
               eventTableList.push("<td id=\'time-range\'>", \n
                                   dateSplitted[1] + hourSymbol,\n
                                   "</td>");\n
               eventTableList.push("<td>", eventList[i][1]);\n
               eventTableList.push("</td></tr>");\n
             }\n
             $("div.event-listview tbody").append(eventTableList.join(""));\n
             $("td#resultview").append("<b>" + " " +\n
                                       $("div.event-listview tbody tr").length + \n
                                       "</b>" + " to " + \n
                                       "<b>" + text + "</b>");\n
             $("div.event-listview tbody td#event-date").click(function(){\n
               op.showday = new Date($(this).text());\n
               op.view = "day";\n
               $("#gridcontainer").bcalendar(op).BcalGetOp();\n
             });\n
             if ($("div.event-listview tr").height() > 0){\n
               $("div#gridcontainer").css("height",\n
                 $("div#gridcontainer table tbody tr").length*$("div.event-listview tr").height() + "px");\n
             } else {\n
                $("div#gridcontainer").css("height", "54px").append("<div id=\'blank-result\'>No Results</div>");\n
             }\n
           }\n
    });\n
    tableList.push("</tbody></table></div>");\n
    $("div#gridcontainer").append(tableList.join(""));\n
    return true;\n
  });\n
  $("img[alt=\'calendar_logo_box\']").click(function(){\n
    window.location.reload();\n
  });\n
});\n
\n
$("div#new_event_dialog").ready(function(){\n
  $("div#new_event_dialog").dialog({\n
    title: "Create New Event",\n
    autoOpen: false,\n
    buttons: {\n
      "Create": createNewEvent\n
      }\n
  });\n
});\n
\n
window.onload = function(){\n
  $("div#dvCalMain.calmain").parent().css("padding", "0 0 0 1px");\n
};

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
