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
            <value> <string>ts68192545.48</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>ERP5VCS_movableMenu.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/x-javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string>//*****************************************************************************\n
// Do not remove this notice.\n
//\n
// Copyright 2001 by Mike Hall.\n
// See http://www.brainjar.com for terms of use.\n
//*****************************************************************************\n
\n
// Determine browser and version.\n
\n
function Browser() {\n
\n
  var ua, s, i;\n
\n
  this.isIE    = false;  // Internet Explorer\n
  this.isNS    = false;  // Netscape\n
  this.version = null;\n
\n
  ua = navigator.userAgent;\n
\n
  s = "MSIE";\n
  if ((i = ua.indexOf(s)) \076= 0) {\n
    this.isIE = true;\n
    this.version = parseFloat(ua.substr(i + s.length));\n
    return;\n
  }\n
\n
  s = "Netscape6/";\n
  if ((i = ua.indexOf(s)) \076= 0) {\n
    this.isNS = true;\n
    this.version = parseFloat(ua.substr(i + s.length));\n
    return;\n
  }\n
\n
  // Treat any other "Gecko" browser as NS 6.1.\n
\n
  s = "Gecko";\n
  if ((i = ua.indexOf(s)) \076= 0) {\n
    this.isNS = true;\n
    this.version = 6.1;\n
    return;\n
  }\n
}\n
\n
var browser = new Browser();\n
\n
//=============================================================================\n
// Window Object\n
//=============================================================================\n
\n
function Window(el) {\n
\n
  var i, mapList, mapName;\n
\n
  // Get window components.\n
\n
  this.frame           = el;\n
  this.titleBar        = winFindByClassName(el, "titleBar");\n
  this.titleBarText    = winFindByClassName(el, "titleBarText");\n
  this.titleBarButtons = winFindByClassName(el, "titleBarButtons");\n
  this.clientArea      = winFindByClassName(el, "clientArea");\n
\n
  // Find matching button image map.\n
\n
  mapName = this.titleBarButtons.useMap.substr(1);\n
  mapList = document.getElementsByTagName("MAP");\n
  for (i = 0; i \074 mapList.length; i++){\n
    if (mapList[i].name == mapName)\n
      this.titleBarMap = mapList[i];\n
  }\n
\n
  // Save colors.\n
\n
  this.activeFrameBackgroundColor  = this.frame.style.backgroundColor;\n
  this.activeFrameBorderColor      = this.frame.style.borderColor;\n
  this.activeTitleBarColor         = this.titleBar.style.backgroundColor;\n
  this.activeTitleTextColor        = this.titleBar.style.color;\n
  this.activeClientAreaBorderColor = this.clientArea.style.borderColor;\n
  if (browser.isIE)\n
    this.activeClientAreaScrollbarColor = this.clientArea.style.scrollbarBaseColor;\n
\n
  // Save images.\n
\n
  this.activeButtonsImage   = this.titleBarButtons.src;\n
  this.inactiveButtonsImage = this.titleBarButtons.longDesc;\n
\n
  // Set flags.\n
\n
  this.isOpen      = false;\n
  this.isMinimized = false;\n
\n
  // Set methods.\n
\n
  this.open       = winOpen;\n
  this.close      = winClose;\n
  this.minimize   = winMinimize;\n
  this.restore    = winRestore;\n
  this.makeActive = winMakeActive;\n
\n
  // Set up event handling.\n
\n
  this.frame.parentWindow = this;\n
  this.frame.onmousemove  = winResizeCursorSet;\n
  this.frame.onmouseout   = winResizeCursorRestore;\n
  this.frame.onmousedown  = winResizeDragStart;\n
\n
  this.titleBar.parentWindow = this;\n
  this.titleBar.onmousedown  = winMoveDragStart;\n
\n
  this.clientArea.parentWindow = this;\n
  this.clientArea.onclick      = winClientAreaClick;\n
\n
  for (i = 0; i \074 this.titleBarMap.childNodes.length; i++){\n
    if (this.titleBarMap.childNodes[i].tagName == "AREA")\n
      this.titleBarMap.childNodes[i].parentWindow = this;\n
  }\n
\n
  // Calculate the minimum width and height values for resizing\n
  // and fix any initial display problems.\n
\n
  var initLt, initWd, w, dw;\n
\n
  // Save the inital frame width and position, then reposition\n
  // the window.\n
\n
  initLt = this.frame.style.left;\n
  initWd = parseInt(this.frame.style.width,10);\n
  this.frame.style.right = -this.titleBarText.offsetWidth + "px";\n
\n
  // For IE, start calculating the value to use when setting\n
  // the client area width based on the frame width.\n
\n
  if (browser.isIE) {\n
    this.titleBarText.style.display = "none";\n
    w = this.clientArea.offsetWidth;\n
    this.widthDiff = this.frame.offsetWidth - w;\n
    this.clientArea.style.width = w + "px";\n
    dw = this.clientArea.offsetWidth - w;\n
    w -= dw;     \n
    this.widthDiff += dw;\n
    this.titleBarText.style.display = "";\n
  }\n
\n
  // Find the difference between the frame\'s style and offset\n
  // widths. For IE, adjust the client area/frame width\n
  // difference accordingly.\n
\n
  w = this.frame.offsetWidth;\n
  this.frame.style.width = "140px";\n
  dw = this.frame.offsetWidth - w;\n
  w -= dw;\n
  this.frame.style.width = "140px";\n
  if (browser.isIE)\n
    this.widthDiff -= dw;\n
\n
  // Find the minimum width for resize.\n
\n
  this.isOpen = true;  // Flag as open so minimize call will work.\n
  this.minimize();\n
  // Get the minimum width.\n
  if (browser.isNS \046\046 browser.version \076= 1.2)\n
    // For later versions of Gecko.\n
    this.minimumWidth = this.frame.offsetWidth;\n
  else\n
    // For all others.\n
    this.minimumWidth = this.frame.offsetWidth - dw;\n
\n
  // Find the frame width at which or below the title bar text will\n
  // need to be clipped.\n
\n
  this.titleBarText.style.width = "";\n
  this.clipTextMinimumWidth = this.frame.offsetWidth - dw;\n
\n
  // Set the minimum height.\n
\n
  this.minimumHeight = 1;\n
\n
  // Restore window. For IE, set client area width.\n
\n
  this.restore();\n
  this.isOpen = false;  // Reset flag.\n
  initWd = Math.max(initWd, this.minimumWidth);\n
  this.frame.style.width = "140px";\n
  if (browser.isIE)\n
    this.clientArea.style.width = (initWd - this.widthDiff) + "px";\n
\n
  // Clip the title bar text if needed.\n
\n
  if (this.clipTextMinimumWidth \076= this.minimumWidth)\n
    this.titleBarText.style.width = (winCtrl.minimizedTextWidth + initWd - this.minimumWidth) + "px";\n
\n
  // Restore the window to its original position.\n
\n
  this.frame.style.right = "20px";\n
}\n
\n
//=============================================================================\n
// Window Methods\n
//=============================================================================\n
\n
function winOpen() {\n
\n
  if (this.isOpen)\n
    return;\n
\n
  // Restore the window and make it visible.\n
\n
  this.makeActive();\n
  this.isOpen = true;\n
  if (this.isMinimized)\n
    this.restore();\n
  this.frame.style.visibility = "visible";\n
}\n
\n
function winClose() {\n
\n
  // Hide the window.\n
\n
  this.frame.style.visibility = "hidden";\n
  this.isOpen = false;\n
}\n
\n
function winMinimize() {\n
\n
  if (!this.isOpen || this.isMinimized)\n
    return;\n
\n
  this.makeActive();\n
\n
  // Save current frame and title bar text widths.\n
\n
  this.restoreFrameWidth = this.frame.style.width;\n
  this.restoreTextWidth = this.titleBarText.style.width;\n
\n
  // Disable client area display.\n
\n
  this.clientArea.style.display = "none";\n
\n
  // Minimize frame and title bar text widths.\n
\n
  if (this.minimumWidth)\n
    this.frame.style.width = this.minimumWidth + "px";\n
  else\n
    this.frame.style.width = "";\n
  this.titleBarText.style.width = winCtrl.minimizedTextWidth + "px";\n
\n
  this.isMinimized = true;\n
}\n
\n
function winRestore() {\n
\n
  if (!this.isOpen || !this.isMinimized)\n
    return;\n
\n
  this.makeActive();\n
\n
  // Enable client area display.\n
\n
  this.clientArea.style.display = "";\n
\n
  // Restore frame and title bar text widths.\n
\n
  this.frame.style.width = this.restoreFrameWidth;\n
  this.titleBarText.style.width = this.restoreTextWidth;\n
\n
  this.isMinimized = false;\n
}\n
\n
function winMakeActive() {\n
\n
  if (winCtrl.active == this)\n
    return;\n
\n
  // Inactivate the currently active window.\n
\n
  if (winCtrl.active) {\n
    winCtrl.active.frame.style.backgroundColor    = winCtrl.inactiveFrameBackgroundColor;\n
    winCtrl.active.frame.style.borderColor        = winCtrl.inactiveFrameBorderColor;\n
    winCtrl.active.titleBar.style.backgroundColor = winCtrl.inactiveTitleBarColor;\n
    winCtrl.active.titleBar.style.color           = winCtrl.inactiveTitleTextColor;\n
    winCtrl.active.clientArea.style.borderColor   = winCtrl.inactiveClientAreaBorderColor;\n
    if (browser.isIE)\n
      winCtrl.active.clientArea.style.scrollbarBaseColor = winCtrl.inactiveClientAreaScrollbarColor;\n
    if (browser.isNS \046\046 browser.version \074 6.1)\n
      winCtrl.active.clientArea.style.overflow = "hidden";\n
    if (winCtrl.active.inactiveButtonsImage)\n
      winCtrl.active.titleBarButtons.src = winCtrl.active.inactiveButtonsImage;\n
  }\n
\n
  // Activate this window.\n
\n
  this.frame.style.backgroundColor    = this.activeFrameBackgroundColor;\n
  this.frame.style.borderColor        = this.activeFrameBorderColor;\n
  this.titleBar.style.backgroundColor = this.activeTitleBarColor;\n
  this.titleBar.style.color           = this.activeTitleTextColor;\n
  this.clientArea.style.borderColor   = this.activeClientAreaBorderColor;\n
  if (browser.isIE)\n
    this.clientArea.style.scrollbarBaseColor = this.activeClientAreaScrollbarColor;\n
  if (browser.isNS \046\046 browser.version \074 6.1)\n
    this.clientArea.style.overflow = "auto";\n
  if (this.inactiveButtonsImage)\n
    this.titleBarButtons.src = this.activeButtonsImage;\n
  this.frame.style.zIndex = winCtrl.maxzIndex + 1;\n
  winCtrl.active = this;\n
}\n
\n
//=============================================================================\n
// Event handlers.\n
//=============================================================================\n
\n
function winClientAreaClick(event) {\n
\n
  // Make this window the active one.\n
\n
  this.parentWindow.makeActive();\n
}\n
\n
//-----------------------------------------------------------------------------\n
// Window dragging.\n
//-----------------------------------------------------------------------------\n
\n
function winMoveDragStart(event) {\n
\n
  var target;\n
  var x, y;\n
\n
  if (browser.isIE)\n
    target = window.event.srcElement.tagName;\n
  if (browser.isNS)\n
    target = event.target.tagName;\n
\n
  if (target == "AREA")\n
    return;\n
\n
  this.parentWindow.makeActive();\n
\n
  // Get cursor offset from window frame.\n
\n
  if (browser.isIE) {\n
    x = window.event.x;\n
    y = window.event.y;\n
  }\n
  if (browser.isNS) {\n
    x = event.pageX;\n
    y = event.pageY;\n
  }\n
  winCtrl.xOffset = winCtrl.active.frame.offsetLeft - x;\n
  winCtrl.yOffset = winCtrl.active.frame.offsetTop  - y;\n
\n
  // Set document to capture mousemove and mouseup events.\n
\n
  if (browser.isIE) {\n
    document.onmousemove = winMoveDragGo;\n
    document.onmouseup   = winMoveDragStop;\n
  }\n
  if (browser.isNS) {\n
    document.addEventListener("mousemove", winMoveDragGo,   true);\n
    document.addEventListener("mouseup",   winMoveDragStop, true);\n
    event.preventDefault();\n
  }\n
\n
  winCtrl.inMoveDrag = true;\n
}\n
\n
function winMoveDragGo(event) {\n
\n
  var x, y;\n
\n
  if (!winCtrl.inMoveDrag)\n
    return;\n
\n
  // Get cursor position.\n
\n
  if (browser.isIE) {\n
    x = window.event.x;\n
    y = window.event.y;\n
    window.event.cancelBubble = true;\n
    window.event.returnValue = false;\n
  }\n
  if (browser.isNS) {\n
    x = event.pageX;\n
    y = event.pageY;\n
    event.preventDefault();\n
  }\n
\n
  // Move window frame based on offset from cursor.\n
\n
  winCtrl.active.frame.style.left = (x + winCtrl.xOffset) + "px";\n
  winCtrl.active.frame.style.top  = (y + winCtrl.yOffset) + "px";\n
}\n
\n
function winMoveDragStop(event) {\n
\n
  winCtrl.inMoveDrag = false;\n
\n
  // Remove mousemove and mouseup event captures on document.\n
\n
  if (browser.isIE) {\n
    document.onmousemove = null;\n
    document.onmouseup   = null;\n
  }\n
  if (browser.isNS) {\n
    document.removeEventListener("mousemove", winMoveDragGo,   true);\n
    document.removeEventListener("mouseup",   winMoveDragStop, true);\n
  }\n
}\n
\n
//-----------------------------------------------------------------------------\n
// Window resizing.\n
//-----------------------------------------------------------------------------\n
\n
function winResizeCursorSet(event) {\n
\n
  var target;\n
  var xOff, yOff;\n
\n
  if (this.parentWindow.isMinimized || winCtrl.inResizeDrag)\n
    return;\n
\n
  // If not on window frame, restore cursor and exit.\n
\n
  if (browser.isIE)\n
    target = window.event.srcElement;\n
  if (browser.isNS)\n
    target = event.target;\n
  if (target != this.parentWindow.frame)\n
    return;\n
\n
  // Find resize direction.\n
\n
  if (browser.isIE) {\n
    xOff = window.event.offsetX;\n
    yOff = window.event.offsetY;\n
  }\n
  if (browser.isNS) {\n
    xOff = event.layerX;\n
    yOff = event.layerY;\n
  }\n
  winCtrl.resizeDirection = "";\n
  if (yOff \074= winCtrl.resizeCornerSize)\n
    winCtrl.resizeDirection += "n";\n
  else if (yOff \076= this.parentWindow.frame.offsetHeight - winCtrl.resizeCornerSize)\n
    winCtrl.resizeDirection += "s";\n
  if (xOff \074= winCtrl.resizeCornerSize)\n
    winCtrl.resizeDirection += "w";\n
  else if (xOff \076= this.parentWindow.frame.offsetWidth - winCtrl.resizeCornerSize)\n
    winCtrl.resizeDirection += "e";\n
\n
  // If not on window edge, restore cursor and exit.\n
\n
  if (winCtrl.resizeDirection === "") {\n
    this.onmouseout(event);\n
    return;\n
  }\n
\n
  // Change cursor.\n
\n
  if (browser.isIE)\n
    document.body.style.cursor = winCtrl.resizeDirection + "-resize";\n
  if (browser.isNS)\n
    this.parentWindow.frame.style.cursor = winCtrl.resizeDirection + "-resize";\n
}\n
\n
function winResizeCursorRestore(event) {\n
\n
  if (winCtrl.inResizeDrag)\n
    return;\n
\n
  // Restore cursor.\n
\n
  if (browser.isIE)\n
    document.body.style.cursor = "";\n
  if (browser.isNS)\n
    this.parentWindow.frame.style.cursor = "";\n
}\n
\n
function winResizeDragStart(event) {\n
\n
  var target;\n
\n
  // Make sure the event is on the window frame.\n
\n
  if (browser.isIE)\n
    target = window.event.srcElement;\n
  if (browser.isNS)\n
    target = event.target;\n
  if (target != this.parentWindow.frame)\n
    return;\n
\n
  this.parentWindow.makeActive();\n
\n
  if (this.parentWindow.isMinimized)\n
    return;\n
\n
  // Save cursor position.\n
\n
  if (browser.isIE) {\n
    winCtrl.xPosition = window.event.x;\n
    winCtrl.yPosition = window.event.y;\n
  }\n
  if (browser.isNS) {\n
    winCtrl.xPosition = event.pageX;\n
    winCtrl.yPosition = event.pageY;\n
  }\n
\n
  // Save window frame position and current window size.\n
\n
  winCtrl.oldLeft   = parseInt(this.parentWindow.frame.style.left,  10);\n
  winCtrl.oldTop    = parseInt(this.parentWindow.frame.style.top,   10);\n
  winCtrl.oldWidth  = parseInt(this.parentWindow.frame.style.width, 10);\n
  winCtrl.oldHeight = parseInt(this.parentWindow.clientArea.style.height, 10);\n
\n
  // Set document to capture mousemove and mouseup events.\n
\n
  if (browser.isIE) {\n
    document.onmousemove = winResizeDragGo;\n
    document.onmouseup   = winResizeDragStop;\n
  }\n
  if (browser.isNS) {\n
    document.addEventListener("mousemove", winResizeDragGo,   true);\n
    document.addEventListener("mouseup"  , winResizeDragStop, true);\n
    event.preventDefault();\n
  }\n
\n
  winCtrl.inResizeDrag = true;\n
}\n
\n
function winResizeDragGo(event) {\n
\n
 var north, south, east, west;\n
 var dx, dy;\n
 var w, h;\n
\n
  if (!winCtrl.inResizeDrag)\n
    return;\n
\n
  // Set direction flags based on original resize direction.\n
\n
  north = false;\n
  south = false;\n
  east  = false;\n
  west  = false;\n
  if (winCtrl.resizeDirection.charAt(0) == "n")\n
    north = true;\n
  if (winCtrl.resizeDirection.charAt(0) == "s")\n
    south = true;\n
  if (winCtrl.resizeDirection.charAt(0) == "e" || winCtrl.resizeDirection.charAt(1) == "e")\n
    east = true;\n
  if (winCtrl.resizeDirection.charAt(0) == "w" || winCtrl.resizeDirection.charAt(1) == "w")\n
    west = true;\n
\n
  // Find change in cursor position.\n
\n
  if (browser.isIE) {\n
    dx = window.event.x - winCtrl.xPosition;\n
    dy = window.event.y - winCtrl.yPosition;\n
  }\n
  if (browser.isNS) {\n
    dx = event.pageX - winCtrl.xPosition;\n
    dy = event.pageY - winCtrl.yPosition;\n
  }\n
\n
  // If resizing north or west, reverse corresponding amount.\n
\n
  if (west)\n
    dx = -dx;\n
  if (north)\n
    dy = -dy;\n
\n
  // Check new size.\n
\n
  w = winCtrl.oldWidth  + dx;\n
  h = winCtrl.oldHeight + dy;\n
  if (w \074= winCtrl.active.minimumWidth) {\n
    w = winCtrl.active.minimumWidth;\n
    dx = w - winCtrl.oldWidth;\n
  }\n
  if (h \074= winCtrl.active.minimumHeight) {\n
    h = winCtrl.active.minimumHeight;\n
    dy = h - winCtrl.oldHeight;\n
  }\n
\n
  // Resize the window. For IE, keep client area and frame widths in synch.\n
\n
  if (east || west) {\n
    winCtrl.active.frame.style.width = w + "px";\n
    if (browser.isIE)\n
      winCtrl.active.clientArea.style.width = (w - winCtrl.active.widthDiff) + "px";\n
  }\n
  if (north || south)\n
    winCtrl.active.clientArea.style.height = h + "px";\n
\n
  // Clip the title bar text, if necessary.\n
\n
  if (east || west) {\n
    if (w \074 winCtrl.active.clipTextMinimumWidth)\n
      winCtrl.active.titleBarText.style.width = (winCtrl.minimizedTextWidth + w - winCtrl.active.minimumWidth) + "px";\n
    else\n
      winCtrl.active.titleBarText.style.width = "";\n
  }\n
\n
  // For a north or west resize, move the window.\n
\n
  if (west)\n
    winCtrl.active.frame.style.left = (winCtrl.oldLeft - dx) + "px";\n
  if (north)\n
    winCtrl.active.frame.style.top  = (winCtrl.oldTop  - dy) + "px";\n
\n
  if (browser.isIE) {\n
    window.event.cancelBubble = true;\n
    window.event.returnValue = false;\n
  }\n
  if (browser.isNS)\n
    event.preventDefault();\n
}\n
\n
function winResizeDragStop(event) {\n
\n
  winCtrl.inResizeDrag = false;\n
\n
  // Remove mousemove and mouseup event captures on document.\n
\n
  if (browser.isIE) {\n
    document.onmousemove = null;\n
    document.onmouseup   = null;\n
  }\n
  if (browser.isNS) {\n
    document.removeEventListener("mousemove", winResizeDragGo,   true);\n
    document.removeEventListener("mouseup"  , winResizeDragStop, true);\n
  }\n
}\n
\n
//=============================================================================\n
// Utility functions.\n
//=============================================================================\n
\n
function winFindByClassName(el, className) {\n
\n
  var i, tmp;\n
\n
  if (el.className == className)\n
    return el;\n
\n
  // Search for a descendant element assigned the given class.\n
\n
  for (i = 0; i \074 el.childNodes.length; i++) {\n
    tmp = winFindByClassName(el.childNodes[i], className);\n
    if (tmp !== null)\n
      return tmp;\n
  }\n
\n
  return null;\n
}\n
\n
//=============================================================================\n
// Initialization code.\n
//=============================================================================\n
\n
var winList = new Array();\n
var winCtrl = new Object();\n
\n
function winInit() {\n
\n
  var elList;\n
\n
  // Initialize window control object.\n
\n
  winCtrl.maxzIndex                        =   0;\n
  winCtrl.resizeCornerSize                 =  16;\n
  winCtrl.minimizedTextWidth               = 100;\n
  winCtrl.inactiveFrameBackgroundColor     = "#c0c0c0";\n
  winCtrl.inactiveFrameBorderColor         = "#f0f0f0 #505050 #404040 #e0e0e0";\n
  winCtrl.inactiveTitleBarColor            = "#808080";\n
  winCtrl.inactiveTitleTextColor           = "#c0c0c0";\n
  winCtrl.inactiveClientAreaBorderColor    = "#404040 #e0e0e0 #f0f0f0 #505050";\n
  winCtrl.inactiveClientAreaScrollbarColor = "";\n
  winCtrl.inMoveDrag                       = false;\n
  winCtrl.inResizeDrag                     = false;\n
\n
  // Initialize windows and build list.\n
\n
  elList = document.getElementsByTagName("DIV");\n
  for (var i = 0; i \074 elList.length; i++){\n
    if (elList[i].className == "window")\n
      winList[elList[i].id] = new Window(elList[i]);\n
  }\n
}\n
// run initialization code after page loads.\n
//window.onload = winInit;\n
\n
//]]\076</string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>18672</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
