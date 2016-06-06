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
            <value> <string>codemirror.js</string> </value>
        </item>
        <item>
            <key> <string>description</string> </key>
            <value>
              <none/>
            </value>
        </item>
        <item>
            <key> <string>id</string> </key>
            <value> <string>codemirror_rjs_js</string> </value>
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

// CodeMirror, copyright (c) by Marijn Haverbeke and others\n
// Distributed under an MIT license: http://codemirror.net/LICENSE\n
\n
// This is CodeMirror (http://codemirror.net), a code editor\n
// implemented in JavaScript on top of the browser\'s DOM.\n
//\n
// You can find some technical background for some of the code below\n
// at http://marijnhaverbeke.nl/blog/#cm-internals .\n
\n
(function(mod) {\n
  if (typeof exports == "object" && typeof module == "object") // CommonJS\n
    module.exports = mod();\n
  else if (typeof define == "function" && define.amd) // AMD\n
    return define([], mod);\n
  else // Plain browser env\n
    (this || window).CodeMirror = mod();\n
})(function() {\n
  "use strict";\n
\n
  // BROWSER SNIFFING\n
\n
  // Kludges for bugs and behavior differences that can\'t be feature\n
  // detected are enabled based on userAgent etc sniffing.\n
  var userAgent = navigator.userAgent;\n
  var platform = navigator.platform;\n
\n
  var gecko = /gecko\\/\\d/i.test(userAgent);\n
  var ie_upto10 = /MSIE \\d/.test(userAgent);\n
  var ie_11up = /Trident\\/(?:[7-9]|\\d{2,})\\..*rv:(\\d+)/.exec(userAgent);\n
  var ie = ie_upto10 || ie_11up;\n
  var ie_version = ie && (ie_upto10 ? document.documentMode || 6 : ie_11up[1]);\n
  var webkit = /WebKit\\//.test(userAgent);\n
  var qtwebkit = webkit && /Qt\\/\\d+\\.\\d+/.test(userAgent);\n
  var chrome = /Chrome\\//.test(userAgent);\n
  var presto = /Opera\\//.test(userAgent);\n
  var safari = /Apple Computer/.test(navigator.vendor);\n
  var mac_geMountainLion = /Mac OS X 1\\d\\D([8-9]|\\d\\d)\\D/.test(userAgent);\n
  var phantom = /PhantomJS/.test(userAgent);\n
\n
  var ios = /AppleWebKit/.test(userAgent) && /Mobile\\/\\w+/.test(userAgent);\n
  // This is woefully incomplete. Suggestions for alternative methods welcome.\n
  var mobile = ios || /Android|webOS|BlackBerry|Opera Mini|Opera Mobi|IEMobile/i.test(userAgent);\n
  var mac = ios || /Mac/.test(platform);\n
  var windows = /win/i.test(platform);\n
\n
  var presto_version = presto && userAgent.match(/Version\\/(\\d*\\.\\d*)/);\n
  if (presto_version) presto_version = Number(presto_version[1]);\n
  if (presto_version && presto_version >= 15) { presto = false; webkit = true; }\n
  // Some browsers use the wrong event properties to signal cmd/ctrl on OS X\n
  var flipCtrlCmd = mac && (qtwebkit || presto && (presto_version == null || presto_version < 12.11));\n
  var captureRightClick = gecko || (ie && ie_version >= 9);\n
\n
  // Optimize some code when these features are not used.\n
  var sawReadOnlySpans = false, sawCollapsedSpans = false;\n
\n
  // EDITOR CONSTRUCTOR\n
\n
  // A CodeMirror instance represents an editor. This is the object\n
  // that user code is usually dealing with.\n
\n
  function CodeMirror(place, options) {\n
    if (!(this instanceof CodeMirror)) return new CodeMirror(place, options);\n
\n
    this.options = options = options ? copyObj(options) : {};\n
    // Determine effective options based on given values and defaults.\n
    copyObj(defaults, options, false);\n
    setGuttersForLineNumbers(options);\n
\n
    var doc = options.value;\n
    if (typeof doc == "string") doc = new Doc(doc, options.mode, null, options.lineSeparator);\n
    this.doc = doc;\n
\n
    var input = new CodeMirror.inputStyles[options.inputStyle](this);\n
    var display = this.display = new Display(place, doc, input);\n
    display.wrapper.CodeMirror = this;\n
    updateGutters(this);\n
    themeChanged(this);\n
    if (options.lineWrapping)\n
      this.display.wrapper.className += " CodeMirror-wrap";\n
    if (options.autofocus && !mobile) display.input.focus();\n
    initScrollbars(this);\n
\n
    this.state = {\n
      keyMaps: [],  // stores maps added by addKeyMap\n
      overlays: [], // highlighting overlays, as added by addOverlay\n
      modeGen: 0,   // bumped when mode/overlay changes, used to invalidate highlighting info\n
      overwrite: false,\n
      delayingBlurEvent: false,\n
      focused: false,\n
      suppressEdits: false, // used to disable editing during key handlers when in readOnly mode\n
      pasteIncoming: false, cutIncoming: false, // help recognize paste/cut edits in input.poll\n
      selectingText: false,\n
      draggingText: false,\n
      highlight: new Delayed(), // stores highlight worker timeout\n
      keySeq: null,  // Unfinished key sequence\n
      specialChars: null\n
    };\n
\n
    var cm = this;\n
\n
    // Override magic textarea content restore that IE sometimes does\n
    // on our hidden textarea on reload\n
    if (ie && ie_version < 11) setTimeout(function() { cm.display.input.reset(true); }, 20);\n
\n
    registerEventHandlers(this);\n
    ensureGlobalHandlers();\n
\n
    startOperation(this);\n
    this.curOp.forceUpdate = true;\n
    attachDoc(this, doc);\n
\n
    if ((options.autofocus && !mobile) || cm.hasFocus())\n
      setTimeout(bind(onFocus, this), 20);\n
    else\n
      onBlur(this);\n
\n
    for (var opt in optionHandlers) if (optionHandlers.hasOwnProperty(opt))\n
      optionHandlers[opt](this, options[opt], Init);\n
    maybeUpdateLineNumberWidth(this);\n
    if (options.finishInit) options.finishInit(this);\n
    for (var i = 0; i < initHooks.length; ++i) initHooks[i](this);\n
    endOperation(this);\n
    // Suppress optimizelegibility in Webkit, since it breaks text\n
    // measuring on line wrapping boundaries.\n
    if (webkit && options.lineWrapping &&\n
        getComputedStyle(display.lineDiv).textRendering == "optimizelegibility")\n
      display.lineDiv.style.textRendering = "auto";\n
  }\n
\n
  // DISPLAY CONSTRUCTOR\n
\n
  // The display handles the DOM integration, both for input reading\n
  // and content drawing. It holds references to DOM nodes and\n
  // display-related state.\n
\n
  function Display(place, doc, input) {\n
    var d = this;\n
    this.input = input;\n
\n
    // Covers bottom-right square when both scrollbars are present.\n
    d.scrollbarFiller = elt("div", null, "CodeMirror-scrollbar-filler");\n
    d.scrollbarFiller.setAttribute("cm-not-content", "true");\n
    // Covers bottom of gutter when coverGutterNextToScrollbar is on\n
    // and h scrollbar is present.\n
    d.gutterFiller = elt("div", null, "CodeMirror-gutter-filler");\n
    d.gutterFiller.setAttribute("cm-not-content", "true");\n
    // Will contain the actual code, positioned to cover the viewport.\n
    d.lineDiv = elt("div", null, "CodeMirror-code");\n
    // Elements are added to these to represent selection and cursors.\n
    d.selectionDiv = elt("div", null, null, "position: relative; z-index: 1");\n
    d.cursorDiv = elt("div", null, "CodeMirror-cursors");\n
    // A visibility: hidden element used to find the size of things.\n
    d.measure = elt("div", null, "CodeMirror-measure");\n
    // When lines outside of the viewport are measured, they are drawn in this.\n
    d.lineMeasure = elt("div", null, "CodeMirror-measure");\n
    // Wraps everything that needs to exist inside the vertically-padded coordinate system\n
    d.lineSpace = elt("div", [d.measure, d.lineMeasure, d.selectionDiv, d.cursorDiv, d.lineDiv],\n
                      null, "position: relative; outline: none");\n
    // Moved around its parent to cover visible view.\n
    d.mover = elt("div", [elt("div", [d.lineSpace], "CodeMirror-lines")], null, "position: relative");\n
    // Set to the height of the document, allowing scrolling.\n
    d.sizer = elt("div", [d.mover], "CodeMirror-sizer");\n
    d.sizerWidth = null;\n
    // Behavior of elts with overflow: auto and padding is\n
    // inconsistent across browsers. This is used to ensure the\n
    // scrollable area is big enough.\n
    d.heightForcer = elt("div", null, null, "position: absolute; height: " + scrollerGap + "px; width: 1px;");\n
    // Will contain the gutters, if any.\n
    d.gutters = elt("div", null, "CodeMirror-gutters");\n
    d.lineGutter = null;\n
    // Actual scrollable element.\n
    d.scroller = elt("div", [d.sizer, d.heightForcer, d.gutters], "CodeMirror-scroll");\n
    d.scroller.setAttribute("tabIndex", "-1");\n
    // The element in which the editor lives.\n
    d.wrapper = elt("div", [d.scrollbarFiller, d.gutterFiller, d.scroller], "CodeMirror");\n
\n
    // Work around IE7 z-index bug (not perfect, hence IE7 not really being supported)\n
    if (ie && ie_version < 8) { d.gutters.style.zIndex = -1; d.scroller.style.paddingRight = 0; }\n
    if (!webkit && !(gecko && mobile)) d.scroller.draggable = true;\n
\n
    if (place) {\n
      if (place.appendChild) place.appendChild(d.wrapper);\n
      else place(d.wrapper);\n
    }\n
\n
    // Current rendered range (may be bigger than the view window).\n
    d.viewFrom = d.viewTo = doc.first;\n
    d.reportedViewFrom = d.reportedViewTo = doc.first;\n
    // Information about the rendered lines.\n
    d.view = [];\n
    d.renderedView = null;\n
    // Holds info about a single rendered line when it was rendered\n
    // for measurement, while not in view.\n
    d.externalMeasured = null;\n
    // Empty space (in pixels) above the view\n
    d.viewOffset = 0;\n
    d.lastWrapHeight = d.lastWrapWidth = 0;\n
    d.updateLineNumbers = null;\n
\n
    d.nativeBarWidth = d.barHeight = d.barWidth = 0;\n
    d.scrollbarsClipped = false;\n
\n
    // Used to only resize the line number gutter when necessary (when\n
    // the amount of lines crosses a boundary that makes its width change)\n
    d.lineNumWidth = d.lineNumInnerWidth = d.lineNumChars = null;\n
    // Set to true when a non-horizontal-scrolling line widget is\n
    // added. As an optimization, line widget aligning is skipped when\n
    // this is false.\n
    d.alignWidgets = false;\n
\n
    d.cachedCharWidth = d.cachedTextHeight = d.cachedPaddingH = null;\n
\n
    // Tracks the maximum line length so that the horizontal scrollbar\n
    // can be kept static when scrolling.\n
    d.maxLine = null;\n
    d.maxLineLength = 0;\n
    d.maxLineChanged = false;\n
\n
    // Used for measuring wheel scrolling granularity\n
    d.wheelDX = d.wheelDY = d.wheelStartX = d.wheelStartY = null;\n
\n
    // True when shift is held down.\n
    d.shift = false;\n
\n
    // Used to track whether anything happened since the context menu\n
    // was opened.\n
    d.selForContextMenu = null;\n
\n
    d.activeTouch = null;\n
\n
    input.init(d);\n
  }\n
\n
  // STATE UPDATES\n
\n
  // Used to get the editor into a consistent state again when options change.\n
\n
  function loadMode(cm) {\n
    cm.doc.mode = CodeMirror.getMode(cm.options, cm.doc.modeOption);\n
    resetModeState(cm);\n
  }\n
\n
  function resetModeState(cm) {\n
    cm.doc.iter(function(line) {\n
      if (line.stateAfter) line.stateAfter = null;\n
      if (line.styles) line.styles = null;\n
    });\n
    cm.doc.frontier = cm.doc.first;\n
    startWorker(cm, 100);\n
    cm.state.modeGen++;\n
    if (cm.curOp) regChange(cm);\n
  }\n
\n
  function wrappingChanged(cm) {\n
    if (cm.options.lineWrapping) {\n
      addClass(cm.display.wrapper, "CodeMirror-wrap");\n
      cm.display.sizer.style.minWidth = "";\n
      cm.display.sizerWidth = null;\n
    } else {\n
      rmClass(cm.display.wrapper, "CodeMirror-wrap");\n
      findMaxLine(cm);\n
    }\n
    estimateLineHeights(cm);\n
    regChange(cm);\n
    clearCaches(cm);\n
    setTimeout(function(){updateScrollbars(cm);}, 100);\n
  }\n
\n
  // Returns a function that estimates the height of a line, to use as\n
  // first approximation until the line becomes visible (and is thus\n
  // properly measurable).\n
  function estimateHeight(cm) {\n
    var th = textHeight(cm.display), wrapping = cm.options.lineWrapping;\n
    var perLine = wrapping && Math.max(5, cm.display.scroller.clientWidth / charWidth(cm.display) - 3);\n
    return function(line) {\n
      if (lineIsHidden(cm.doc, line)) return 0;\n
\n
      var widgetsHeight = 0;\n
      if (line.widgets) for (var i = 0; i < line.widgets.length; i++) {\n
        if (line.widgets[i].height) widgetsHeight += line.widgets[i].height;\n
      }\n
\n
      if (wrapping)\n
        return widgetsHeight + (Math.ceil(line.text.length / perLine) || 1) * th;\n
      else\n
        return widgetsHeight + th;\n
    };\n
  }\n
\n
  function estimateLineHeights(cm) {\n
    var doc = cm.doc, est = estimateHeight(cm);\n
    doc.iter(function(line) {\n
      var estHeight = est(line);\n
      if (estHeight != line.height) updateLineHeight(line, estHeight);\n
    });\n
  }\n
\n
  function themeChanged(cm) {\n
    cm.display.wrapper.className = cm.display.wrapper.className.replace(/\\s*cm-s-\\S+/g, "") +\n
      cm.options.theme.replace(/(^|\\s)\\s*/g, " cm-s-");\n
    clearCaches(cm);\n
  }\n
\n
  function guttersChanged(cm) {\n
    updateGutters(cm);\n
    regChange(cm);\n
    setTimeout(function(){alignHorizontally(cm);}, 20);\n
  }\n
\n
  // Rebuild the gutter elements, ensure the margin to the left of the\n
  // code matches their width.\n
  function updateGutters(cm) {\n
    var gutters = cm.display.gutters, specs = cm.options.gutters;\n
    removeChildren(gutters);\n
    for (var i = 0; i < specs.length; ++i) {\n
      var gutterClass = specs[i];\n
      var gElt = gutters.appendChild(elt("div", null, "CodeMirror-gutter " + gutterClass));\n
      if (gutterClass == "CodeMirror-linenumbers") {\n
        cm.display.lineGutter = gElt;\n
        gElt.style.width = (cm.display.lineNumWidth || 1) + "px";\n
      }\n
    }\n
    gutters.style.display = i ? "" : "none";\n
    updateGutterSpace(cm);\n
  }\n
\n
  function updateGutterSpace(cm) {\n
    var width = cm.display.gutters.offsetWidth;\n
    cm.display.sizer.style.marginLeft = width + "px";\n
  }\n
\n
  // Compute the character length of a line, taking into account\n
  // collapsed ranges (see markText) that might hide parts, and join\n
  // other lines onto it.\n
  function lineLength(line) {\n
    if (line.height == 0) return 0;\n
    var len = line.text.length, merged, cur = line;\n
    while (merged = collapsedSpanAtStart(cur)) {\n
      var found = merged.find(0, true);\n
      cur = found.from.line;\n
      len += found.from.ch - found.to.ch;\n
    }\n
    cur = line;\n
    while (merged = collapsedSpanAtEnd(cur)) {\n
      var found = merged.find(0, true);\n
      len -= cur.text.length - found.from.ch;\n
      cur = found.to.line;\n
      len += cur.text.length - found.to.ch;\n
    }\n
    return len;\n
  }\n
\n
  // Find the longest line in the document.\n
  function findMaxLine(cm) {\n
    var d = cm.display, doc = cm.doc;\n
    d.maxLine = getLine(doc, doc.first);\n
    d.maxLineLength = lineLength(d.maxLine);\n
    d.maxLineChanged = true;\n
    doc.iter(function(line) {\n
      var len = lineLength(line);\n
      if (len > d.maxLineLength) {\n
        d.maxLineLength = len;\n
        d.maxLine = line;\n
      }\n
    });\n
  }\n
\n
  // Make sure the gutters options contains the element\n
  // "CodeMirror-linenumbers" when the lineNumbers option is true.\n
  function setGuttersForLineNumbers(options) {\n
    var found = indexOf(options.gutters, "CodeMirror-linenumbers");\n
    if (found == -1 && options.lineNumbers) {\n
      options.gutters = options.gutters.concat(["CodeMirror-linenumbers"]);\n
    } else if (found > -1 && !options.lineNumbers) {\n
      options.gutters = options.gutters.slice(0);\n
      options.gutters.splice(found, 1);\n
    }\n
  }\n
\n
  // SCROLLBARS\n
\n
  // Prepare DOM reads needed to update the scrollbars. Done in one\n
  // shot to minimize update/measure roundtrips.\n
  function measureForScrollbars(cm) {\n
    var d = cm.display, gutterW = d.gutters.offsetWidth;\n
    var docH = Math.round(cm.doc.height + paddingVert(cm.display));\n
    return {\n
      clientHeight: d.scroller.clientHeight,\n
      viewHeight: d.wrapper.clientHeight,\n
      scrollWidth: d.scroller.scrollWidth, clientWidth: d.scroller.clientWidth,\n
      viewWidth: d.wrapper.clientWidth,\n
      barLeft: cm.options.fixedGutter ? gutterW : 0,\n
      docHeight: docH,\n
      scrollHeight: docH + scrollGap(cm) + d.barHeight,\n
      nativeBarWidth: d.nativeBarWidth,\n
      gutterWidth: gutterW\n
    };\n
  }\n
\n
  function NativeScrollbars(place, scroll, cm) {\n
    this.cm = cm;\n
    var vert = this.vert = elt("div", [elt("div", null, null, "min-width: 1px")], "CodeMirror-vscrollbar");\n
    var horiz = this.horiz = elt("div", [elt("div", null, null, "height: 100%; min-height: 1px")], "CodeMirror-hscrollbar");\n
    place(vert); place(horiz);\n
\n
    on(vert, "scroll", function() {\n
      if (vert.clientHeight) scroll(vert.scrollTop, "vertical");\n
    });\n
    on(horiz, "scroll", function() {\n
      if (horiz.clientWidth) scroll(horiz.scrollLeft, "horizontal");\n
    });\n
\n
    this.checkedZeroWidth = false;\n
    // Need to set a minimum width to see the scrollbar on IE7 (but must not set it on IE8).\n
    if (ie && ie_version < 8) this.horiz.style.minHeight = this.vert.style.minWidth = "18px";\n
  }\n
\n
  NativeScrollbars.prototype = copyObj({\n
    update: function(measure) {\n
      var needsH = measure.scrollWidth > measure.clientWidth + 1;\n
      var needsV = measure.scrollHeight > measure.clientHeight + 1;\n
      var sWidth = measure.nativeBarWidth;\n
\n
      if (needsV) {\n
        this.vert.style.display = "block";\n
        this.vert.style.bottom = needsH ? sWidth + "px" : "0";\n
        var totalHeight = measure.viewHeight - (needsH ? sWidth : 0);\n
        // A bug in IE8 can cause this value to be negative, so guard it.\n
        this.vert.firstChild.style.height =\n
          Math.max(0, measure.scrollHeight - measure.clientHeight + totalHeight) + "px";\n
      } else {\n
        this.vert.style.display = "";\n
        this.vert.firstChild.style.height = "0";\n
      }\n
\n
      if (needsH) {\n
        this.horiz.style.display = "block";\n
        this.horiz.style.right = needsV ? sWidth + "px" : "0";\n
        this.horiz.style.left = measure.barLeft + "px";\n
        var totalWidth = measure.viewWidth - measure.barLeft - (needsV ? sWidth : 0);\n
        this.horiz.firstChild.style.width =\n
          (measure.scrollWidth - measure.clientWidth + totalWidth) + "px";\n
      } else {\n
        this.horiz.style.display = "";\n
        this.horiz.firstChild.style.width = "0";\n
      }\n
\n
      if (!this.checkedZeroWidth && measure.clientHeight > 0) {\n
        if (sWidth == 0) this.zeroWidthHack();\n
        this.checkedZeroWidth = true;\n
      }\n
\n
      return {right: needsV ? sWidth : 0, bottom: needsH ? sWidth : 0};\n
    },\n
    setScrollLeft: function(pos) {\n
      if (this.horiz.scrollLeft != pos) this.horiz.scrollLeft = pos;\n
      if (this.disableHoriz) this.enableZeroWidthBar(this.horiz, this.disableHoriz);\n
    },\n
    setScrollTop: function(pos) {\n
      if (this.vert.scrollTop != pos) this.vert.scrollTop = pos;\n
      if (this.disableVert) this.enableZeroWidthBar(this.vert, this.disableVert);\n
    },\n
    zeroWidthHack: function() {\n
      var w = mac && !mac_geMountainLion ? "12px" : "18px";\n
      this.horiz.style.height = this.vert.style.width = w;\n
      this.horiz.style.pointerEvents = this.vert.style.pointerEvents = "none";\n
      this.disableHoriz = new Delayed;\n
      this.disableVert = new Delayed;\n
    },\n
    enableZeroWidthBar: function(bar, delay) {\n
      bar.style.pointerEvents = "auto";\n
      function maybeDisable() {\n
        // To find out whether the scrollbar is still visible, we\n
        // check whether the element under the pixel in the bottom\n
        // left corner of the scrollbar box is the scrollbar box\n
        // itself (when the bar is still visible) or its filler child\n
        // (when the bar is hidden). If it is still visible, we keep\n
        // it enabled, if it\'s hidden, we disable pointer events.\n
        var box = bar.getBoundingClientRect();\n
        var elt = document.elementFromPoint(box.left + 1, box.bottom - 1);\n
        if (elt != bar) bar.style.pointerEvents = "none";\n
        else delay.set(1000, maybeDisable);\n
      }\n
      delay.set(1000, maybeDisable);\n
    },\n
    clear: function() {\n
      var parent = this.horiz.parentNode;\n
      parent.removeChild(this.horiz);\n
      parent.removeChild(this.vert);\n
    }\n
  }, NativeScrollbars.prototype);\n
\n
  function NullScrollbars() {}\n
\n
  NullScrollbars.prototype = copyObj({\n
    update: function() { return {bottom: 0, right: 0}; },\n
    setScrollLeft: function() {},\n
    setScrollTop: function() {},\n
    clear: function() {}\n
  }, NullScrollbars.prototype);\n
\n
  CodeMirror.scrollbarModel = {"native": NativeScrollbars, "null": NullScrollbars};\n
\n
  function initScrollbars(cm) {\n
    if (cm.display.scrollbars) {\n
      cm.display.scrollbars.clear();\n
      if (cm.display.scrollbars.addClass)\n
        rmClass(cm.display.wrapper, cm.display.scrollbars.addClass);\n
    }\n
\n
    cm.display.scrollbars = new CodeMirror.scrollbarModel[cm.options.scrollbarStyle](function(node) {\n
      cm.display.wrapper.insertBefore(node, cm.display.scrollbarFiller);\n
      // Prevent clicks in the scrollbars from killing focus\n
      on(node, "mousedown", function() {\n
        if (cm.state.focused) setTimeout(function() { cm.display.input.focus(); }, 0);\n
      });\n
      node.setAttribute("cm-not-content", "true");\n
    }, function(pos, axis) {\n
      if (axis == "horizontal") setScrollLeft(cm, pos);\n
      else setScrollTop(cm, pos);\n
    }, cm);\n
    if (cm.display.scrollbars.addClass)\n
      addClass(cm.display.wrapper, cm.display.scrollbars.addClass);\n
  }\n
\n
  function updateScrollbars(cm, measure) {\n
    if (!measure) measure = measureForScrollbars(cm);\n
    var startWidth = cm.display.barWidth, startHeight = cm.display.barHeight;\n
    updateScrollbarsInner(cm, measure);\n
    for (var i = 0; i < 4 && startWidth != cm.display.barWidth || startHeight != cm.display.barHeight; i++) {\n
      if (startWidth != cm.display.barWidth && cm.options.lineWrapping)\n
        updateHeightsInViewport(cm);\n
      updateScrollbarsInner(cm, measureForScrollbars(cm));\n
      startWidth = cm.display.barWidth; startHeight = cm.display.barHeight;\n
    }\n
  }\n
\n
  // Re-synchronize the fake scrollbars with the actual size of the\n
  // content.\n
  function updateScrollbarsInner(cm, measure) {\n
    var d = cm.display;\n
    var sizes = d.scrollbars.update(measure);\n
\n
    d.sizer.style.paddingRight = (d.barWidth = sizes.right) + "px";\n
    d.sizer.style.paddingBottom = (d.barHeight = sizes.bottom) + "px";\n
\n
    if (sizes.right && sizes.bottom) {\n
      d.scrollbarFiller.style.display = "block";\n
      d.scrollbarFiller.style.height = sizes.bottom + "px";\n
      d.scrollbarFiller.style.width = sizes.right + "px";\n
    } else d.scrollbarFiller.style.display = "";\n
    if (sizes.bottom && cm.options.coverGutterNextToScrollbar && cm.options.fixedGutter) {\n
      d.gutterFiller.style.display = "block";\n
      d.gutterFiller.style.height = sizes.bottom + "px";\n
      d.gutterFiller.style.width = measure.gutterWidth + "px";\n
    } else d.gutterFiller.style.display = "";\n
  }\n
\n
  // Compute the lines that are visible in a given viewport (defaults\n
  // the the current scroll position). viewport may contain top,\n
  // height, and ensure (see op.scrollToPos) properties.\n
  function visibleLines(display, doc, viewport) {\n
    var top = viewport && viewport.top != null ? Math.max(0, viewport.top) : display.scroller.scrollTop;\n
    top = Math.floor(top - paddingTop(display));\n
    var bottom = viewport && viewport.bottom != null ? viewport.bottom : top + display.wrapper.clientHeight;\n
\n
    var from = lineAtHeight(doc, top), to = lineAtHeight(doc, bottom);\n
    // Ensure is a {from: {line, ch}, to: {line, ch}} object, and\n
    // forces those lines into the viewport (if possible).\n
    if (viewport && viewport.ensure) {\n
      var ensureFrom = viewport.ensure.from.line, ensureTo = viewport.ensure.to.line;\n
      if (ensureFrom < from) {\n
        from = ensureFrom;\n
        to = lineAtHeight(doc, heightAtLine(getLine(doc, ensureFrom)) + display.wrapper.clientHeight);\n
      } else if (Math.min(ensureTo, doc.lastLine()) >= to) {\n
        from = lineAtHeight(doc, heightAtLine(getLine(doc, ensureTo)) - display.wrapper.clientHeight);\n
        to = ensureTo;\n
      }\n
    }\n
    return {from: from, to: Math.max(to, from + 1)};\n
  }\n
\n
  // LINE NUMBERS\n
\n
  // Re-align line numbers and gutter marks to compensate for\n
  // horizontal scrolling.\n
  function alignHorizontally(cm) {\n
    var display = cm.display, view = display.view;\n
    if (!display.alignWidgets && (!display.gutters.firstChild || !cm.options.fixedGutter)) return;\n
    var comp = compensateForHScroll(display) - display.scroller.scrollLeft + cm.doc.scrollLeft;\n
    var gutterW = display.gutters.offsetWidth, left = comp + "px";\n
    for (var i = 0; i < view.length; i++) if (!view[i].hidden) {\n
      if (cm.options.fixedGutter && view[i].gutter)\n
        view[i].gutter.style.left = left;\n
      var align = view[i].alignable;\n
      if (align) for (var j = 0; j < align.length; j++)\n
        align[j].style.left = left;\n
    }\n
    if (cm.options.fixedGutter)\n
      display.gutters.style.left = (comp + gutterW) + "px";\n
  }\n
\n
  // Used to ensure that the line number gutter is still the right\n
  // size for the current document size. Returns true when an update\n
  // is needed.\n
  function maybeUpdateLineNumberWidth(cm) {\n
    if (!cm.options.lineNumbers) return false;\n
    var doc = cm.doc, last = lineNumberFor(cm.options, doc.first + doc.size - 1), display = cm.display;\n
    if (last.length != display.lineNumChars) {\n
      var test = display.measure.appendChild(elt("div", [elt("div", last)],\n
                                                 "CodeMirror-linenumber CodeMirror-gutter-elt"));\n
      var innerW = test.firstChild.offsetWidth, padding = test.offsetWidth - innerW;\n
      display.lineGutter.style.width = "";\n
      display.lineNumInnerWidth = Math.max(innerW, display.lineGutter.offsetWidth - padding) + 1;\n
      display.lineNumWidth = display.lineNumInnerWidth + padding;\n
      display.lineNumChars = display.lineNumInnerWidth ? last.length : -1;\n
      display.lineGutter.style.width = display.lineNumWidth + "px";\n
      updateGutterSpace(cm);\n
      return true;\n
    }\n
    return false;\n
  }\n
\n
  function lineNumberFor(options, i) {\n
    return String(options.lineNumberFormatter(i + options.firstLineNumber));\n
  }\n
\n
  // Computes display.scroller.scrollLeft + display.gutters.offsetWidth,\n
  // but using getBoundingClientRect to get a sub-pixel-accurate\n
  // result.\n
  function compensateForHScroll(display) {\n
    return display.scroller.getBoundingClientRect().left - display.sizer.getBoundingClientRect().left;\n
  }\n
\n
  // DISPLAY DRAWING\n
\n
  function DisplayUpdate(cm, viewport, force) {\n
    var display = cm.display;\n
\n
    this.viewport = viewport;\n
    // Store some values that we\'ll need later (but don\'t want to force a relayout for)\n
    this.visible = visibleLines(display, cm.doc, viewport);\n
    this.editorIsHidden = !display.wrapper.offsetWidth;\n
    this.wrapperHeight = display.wrapper.clientHeight;\n
    this.wrapperWidth = display.wrapper.clientWidth;\n
    this.oldDisplayWidth = displayWidth(cm);\n
    this.force = force;\n
    this.dims = getDimensions(cm);\n
    this.events = [];\n
  }\n
\n
  DisplayUpdate.prototype.signal = function(emitter, type) {\n
    if (hasHandler(emitter, type))\n
      this.events.push(arguments);\n
  };\n
  DisplayUpdate.prototype.finish = function() {\n
    for (var i = 0; i < this.events.length; i++)\n
      signal.apply(null, this.events[i]);\n
  };\n
\n
  function maybeClipScrollbars(cm) {\n
    var display = cm.display;\n
    if (!display.scrollbarsClipped && display.scroller.offsetWidth) {\n
      display.nativeBarWidth = display.scroller.offsetWidth - display.scroller.clientWidth;\n
      display.heightForcer.style.height = scrollGap(cm) + "px";\n
      display.sizer.style.marginBottom = -display.nativeBarWidth + "px";\n
      display.sizer.style.borderRightWidth = scrollGap(cm) + "px";\n
      display.scrollbarsClipped = true;\n
    }\n
  }\n
\n
  // Does the actual updating of the line display. Bails out\n
  // (returning false) when there is nothing to be done and forced is\n
  // false.\n
  function updateDisplayIfNeeded(cm, update) {\n
    var display = cm.display, doc = cm.doc;\n
\n
    if (update.editorIsHidden) {\n
      resetView(cm);\n
      return false;\n
    }\n
\n
    // Bail out if the visible area is already rendered and nothing changed.\n
    if (!update.force &&\n
        update.visible.from >= display.viewFrom && update.visible.to <= display.viewTo &&\n
        (display.updateLineNumbers == null || display.updateLineNumbers >= display.viewTo) &&\n
        display.renderedView == display.view && countDirtyView(cm) == 0)\n
      return false;\n
\n
    if (maybeUpdateLineNumberWidth(cm)) {\n
      resetView(cm);\n
      update.dims = getDimensions(cm);\n
    }\n
\n
    // Compute a suitable new viewport (from & to)\n
    var end = doc.first + doc.size;\n
    var from = Math.max(update.visible.from - cm.options.viewportMargin, doc.first);\n
    var to = Math.min(end, update.visible.to + cm.options.viewportMargin);\n
    if (display.viewFrom < from && from - display.viewFrom < 20) from = Math.max(doc.first, display.viewFrom);\n
    if (display.viewTo > to && display.viewTo - to < 20) to = Math.min(end, display.viewTo);\n
    if (sawCollapsedSpans) {\n
      from = visualLineNo(cm.doc, from);\n
      to = visualLineEndNo(cm.doc, to);\n
    }\n
\n
    var different = from != display.viewFrom || to != display.viewTo ||\n
      display.lastWrapHeight != update.wrapperHeight || display.lastWrapWidth != update.wrapperWidth;\n
    adjustView(cm, from, to);\n
\n
    display.viewOffset = heightAtLine(getLine(cm.doc, display.viewFrom));\n
    // Position the mover div to align with the current scroll position\n
    cm.display.mover.style.top = display.viewOffset + "px";\n
\n
    var toUpdate = countDirtyView(cm);\n
    if (!different && toUpdate == 0 && !update.force && display.renderedView == display.view &&\n
        (display.updateLineNumbers == null || display.updateLineNumbers >= display.viewTo))\n
      return false;\n
\n
    // For big changes, we hide the enclosing element during the\n
    // update, since that speeds up the operations on most browsers.\n
    var focused = activeElt();\n
    if (toUpdate > 4) display.lineDiv.style.display = "none";\n
    patchDisplay(cm, display.updateLineNumbers, update.dims);\n
    if (toUpdate > 4) display.lineDiv.style.display = "";\n
    display.renderedView = display.view;\n
    // There might have been a widget with a focused element that got\n
    // hidden or updated, if so re-focus it.\n
    if (focused && activeElt() != focused && focused.offsetHeight) focused.focus();\n
\n
    // Prevent selection and cursors from interfering with the scroll\n
    // width and height.\n
    removeChildren(display.cursorDiv);\n
    removeChildren(display.selectionDiv);\n
    display.gutters.style.height = display.sizer.style.minHeight = 0;\n
\n
    if (different) {\n
      display.lastWrapHeight = update.wrapperHeight;\n
      display.lastWrapWidth = update.wrapperWidth;\n
      startWorker(cm, 400);\n
    }\n
\n
    display.updateLineNumbers = null;\n
\n
    return true;\n
  }\n
\n
  function postUpdateDisplay(cm, update) {\n
    var viewport = update.viewport;\n
    for (var first = true;; first = false) {\n
      if (!first || !cm.options.lineWrapping || update.oldDisplayWidth == displayWidth(cm)) {\n
        // Clip forced viewport to actual scrollable area.\n
        if (viewport && viewport.top != null)\n
          viewport = {top: Math.min(cm.doc.height + paddingVert(cm.display) - displayHeight(cm), viewport.top)};\n
        // Updated line heights might result in the drawn area not\n
        // actually covering the viewport. Keep looping until it does.\n
        update.visible = visibleLines(cm.display, cm.doc, viewport);\n
        if (update.visible.from >= cm.display.viewFrom && update.visible.to <= cm.display.viewTo)\n
          break;\n
      }\n
      if (!updateDisplayIfNeeded(cm, update)) break;\n
      updateHeightsInViewport(cm);\n
      var barMeasure = measureForScrollbars(cm);\n
      updateSelection(cm);\n
      setDocumentHeight(cm, barMeasure);\n
      updateScrollbars(cm, barMeasure);\n
    }\n
\n
    update.signal(cm, "update", cm);\n
    if (cm.display.viewFrom != cm.display.reportedViewFrom || cm.display.viewTo != cm.display.reportedViewTo) {\n
      update.signal(cm, "viewportChange", cm, cm.display.viewFrom, cm.display.viewTo);\n
      cm.display.reportedViewFrom = cm.display.viewFrom; cm.display.reportedViewTo = cm.display.viewTo;\n
    }\n
  }\n
\n
  function updateDisplaySimple(cm, viewport) {\n
    var update = new DisplayUpdate(cm, viewport);\n
    if (updateDisplayIfNeeded(cm, update)) {\n
      updateHeightsInViewport(cm);\n
      postUpdateDisplay(cm, update);\n
      var barMeasure = measureForScrollbars(cm);\n
      updateSelection(cm);\n
      setDocumentHeight(cm, barMeasure);\n
      updateScrollbars(cm, barMeasure);\n
      update.finish();\n
    }\n
  }\n
\n
  function setDocumentHeight(cm, measure) {\n
    cm.display.sizer.style.minHeight = measure.docHeight + "px";\n
    var total = measure.docHeight + cm.display.barHeight;\n
    cm.display.heightForcer.style.top = total + "px";\n
    cm.display.gutters.style.height = Math.max(total + scrollGap(cm), measure.clientHeight) + "px";\n
  }\n
\n
  // Read the actual heights of the rendered lines, and update their\n
  // stored heights to match.\n
  function updateHeightsInViewport(cm) {\n
    var display = cm.display;\n
    var prevBottom = display.lineDiv.offsetTop;\n
    for (var i = 0; i < display.view.length; i++) {\n
      var cur = display.view[i], height;\n
      if (cur.hidden) continue;\n
      if (ie && ie_version < 8) {\n
        var bot = cur.node.offsetTop + cur.node.offsetHeight;\n
        height = bot - prevBottom;\n
        prevBottom = bot;\n
      } else {\n
        var box = cur.node.getBoundingClientRect();\n
        height = box.bottom - box.top;\n
      }\n
      var diff = cur.line.height - height;\n
      if (height < 2) height = textHeight(display);\n
      if (diff > .001 || diff < -.001) {\n
        updateLineHeight(cur.line, height);\n
        updateWidgetHeight(cur.line);\n
        if (cur.rest) for (var j = 0; j < cur.rest.length; j++)\n
          updateWidgetHeight(cur.rest[j]);\n
      }\n
    }\n
  }\n
\n
  // Read and store the height of line widgets associated with the\n
  // given line.\n
  function updateWidgetHeight(line) {\n
    if (line.widgets) for (var i = 0; i < line.widgets.length; ++i)\n
      line.widgets[i].height = line.widgets[i].node.parentNode.offsetHeight;\n
  }\n
\n
  // Do a bulk-read of the DOM positions and sizes needed to draw the\n
  // view, so that we don\'t interleave reading and writing to the DOM.\n
  function getDimensions(cm) {\n
    var d = cm.display, left = {}, width = {};\n
    var gutterLeft = d.gutters.clientLeft;\n
    for (var n = d.gutters.firstChild, i = 0; n; n = n.nextSibling, ++i) {\n
      left[cm.options.gutters[i]] = n.offsetLeft + n.clientLeft + gutterLeft;\n
      width[cm.options.gutters[i]] = n.clientWidth;\n
    }\n
    return {fixedPos: compensateForHScroll(d),\n
            gutterTotalWidth: d.gutters.offsetWidth,\n
            gutterLeft: left,\n
            gutterWidth: width,\n
            wrapperWidth: d.wrapper.clientWidth};\n
  }\n
\n
  // Sync the actual display DOM structure with display.view, removing\n
  // nodes for lines that are no longer in view, and creating the ones\n
  // that are not there yet, and updating the ones that are out of\n
  // date.\n
  function patchDisplay(cm, updateNumbersFrom, dims) {\n
    var display = cm.display, lineNumbers = cm.options.lineNumbers;\n
    var container = display.lineDiv, cur = container.firstChild;\n
\n
    function rm(node) {\n
      var next = node.nextSibling;\n
      // Works around a throw-scroll bug in OS X Webkit\n
      if (webkit && mac && cm.display.currentWheelTarget == node)\n
        node.style.display = "none";\n
      else\n
        node.parentNode.removeChild(node);\n
      return next;\n
    }\n
\n
    var view = display.view, lineN = display.viewFrom;\n
    // Loop over the elements in the view, syncing cur (the DOM nodes\n
    // in display.lineDiv) with the view as we go.\n
    for (var i = 0; i < view.length; i++) {\n
      var lineView = view[i];\n
      if (lineView.hidden) {\n
      } else if (!lineView.node || lineView.node.parentNode != container) { // Not drawn yet\n
        var node = buildLineElement(cm, lineView, lineN, dims);\n
        container.insertBefore(node, cur);\n
      } else { // Already drawn\n
        while (cur != lineView.node) cur = rm(cur);\n
        var updateNumber = lineNumbers && updateNumbersFrom != null &&\n
          updateNumbersFrom <= lineN && lineView.lineNumber;\n
        if (lineView.changes) {\n
          if (indexOf(lineView.changes, "gutter") > -1) updateNumber = false;\n
          updateLineForChanges(cm, lineView, lineN, dims);\n
        }\n
        if (updateNumber) {\n
          removeChildren(lineView.lineNumber);\n
          lineView.lineNumber.appendChild(document.createTextNode(lineNumberFor(cm.options, lineN)));\n
        }\n
        cur = lineView.node.nextSibling;\n
      }\n
      lineN += lineView.size;\n
    }\n
    while (cur) cur = rm(cur);\n
  }\n
\n
  // When an aspect of a line changes, a string is added to\n
  // lineView.changes. This updates the relevant part of the line\'s\n
  // DOM structure.\n
  function updateLineForChanges(cm, lineView, lineN, dims) {\n
    for (var j = 0; j < lineView.changes.length; j++) {\n
      var type = lineView.changes[j];\n
      if (type == "text") updateLineText(cm, lineView);\n
      else if (type == "gutter") updateLineGutter(cm, lineView, lineN, dims);\n
      else if (type == "class") updateLineClasses(lineView);\n
      else if (type == "widget") updateLineWidgets(cm, lineView, dims);\n
    }\n
    lineView.changes = null;\n
  }\n
\n
  // Lines with gutter elements, widgets or a background class need to\n
  // be wrapped, and have the extra elements added to the wrapper div\n
  function ensureLineWrapped(lineView) {\n
    if (lineView.node == lineView.text) {\n
      lineView.node = elt("div", null, null, "position: relative");\n
      if (lineView.text.parentNode)\n
        lineView.text.parentNode.replaceChild(lineView.node, lineView.text);\n
      lineView.node.appendChild(lineView.text);\n
      if (ie && ie_version < 8) lineView.node.style.zIndex = 2;\n
    }\n
    return lineView.node;\n
  }\n
\n
  function updateLineBackground(lineView) {\n
    var cls = lineView.bgClass ? lineView.bgClass + " " + (lineView.line.bgClass || "") : lineView.line.bgClass;\n
    if (cls) cls += " CodeMirror-linebackground";\n
    if (lineView.background) {\n
      if (cls) lineView.background.className = cls;\n
      else { lineView.background.parentNode.removeChild(lineView.background); lineView.background = null; }\n
    } else if (cls) {\n
      var wrap = ensureLineWrapped(lineView);\n
      lineView.background = wrap.insertBefore(elt("div", null, cls), wrap.firstChild);\n
    }\n
  }\n
\n
  // Wrapper around buildLineContent which will reuse the structure\n
  // in display.externalMeasured when possible.\n
  function getLineContent(cm, lineView) {\n
    var ext = cm.display.externalMeasured;\n
    if (ext && ext.line == lineView.line) {\n
      cm.display.externalMeasured = null;\n
      lineView.measure = ext.measure;\n
      return ext.built;\n
    }\n
    return buildLineContent(cm, lineView);\n
  }\n
\n
  // Redraw the line\'s text. Interacts with the background and text\n
  // classes because the mode may output tokens that influence these\n
  // classes.\n
  function updateLineText(cm, lineView) {\n
    var cls = lineView.text.className;\n
    var built = getLineContent(cm, lineView);\n
    if (lineView.text == lineView.node) lineView.node = built.pre;\n
    lineView.text.parentNode.replaceChild(built.pre, lineView.text);\n
    lineView.text = built.pre;\n
    if (built.bgClass != lineView.bgClass || built.textClass != lineView.textClass) {\n
      lineView.bgClass = built.bgClass;\n
      lineView.textClass = built.textClass;\n
      updateLineClasses(lineView);\n
    } else if (cls) {\n
      lineView.text.className = cls;\n
    }\n
  }\n
\n
  function updateLineClasses(lineView) {\n
    updateLineBackground(lineView);\n
    if (lineView.line.wrapClass)\n
      ensureLineWrapped(lineView).className = lineView.line.wrapClass;\n
    else if (lineView.node != lineView.text)\n
      lineView.node.className = "";\n
    var textClass = lineView.textClass ? lineView.textClass + " " + (lineView.line.textClass || "") : lineView.line.textClass;\n
    lineView.text.className = textClass || "";\n
  }\n
\n
  function updateLineGutter(cm, lineView, lineN, dims) {\n
    if (lineView.gutter) {\n
      lineView.node.removeChild(lineView.gutter);\n
      lineView.gutter = null;\n
    }\n
    if (lineView.gutterBackground) {\n
      lineView.node.removeChild(lineView.gutterBackground);\n
      lineView.gutterBackground = null;\n
    }\n
    if (lineView.line.gutterClass) {\n
      var wrap = ensureLineWrapped(lineView);\n
      lineView.gutterBackground = elt("div", null, "CodeMirror-gutter-background " + lineView.line.gutterClass,\n
                                      "left: " + (cm.options.fixedGutter ? dims.fixedPos : -dims.gutterTotalWidth) +\n
                                      "px; width: " + dims.gutterTotalWidth + "px");\n
      wrap.insertBefore(lineView.gutterBackground, lineView.text);\n
    }\n
    var markers = lineView.line.gutterMarkers;\n
    if (cm.options.lineNumbers || markers) {\n
      var wrap = ensureLineWrapped(lineView);\n
      var gutterWrap = lineView.gutter = elt("div", null, "CodeMirror-gutter-wrapper", "left: " +\n
                                             (cm.options.fixedGutter ? dims.fixedPos : -dims.gutterTotalWidth) + "px");\n
      cm.display.input.setUneditable(gutterWrap);\n
      wrap.insertBefore(gutterWrap, lineView.text);\n
      if (lineView.line.gutterClass)\n
        gutterWrap.className += " " + lineView.line.gutterClass;\n
      if (cm.options.lineNumbers && (!markers || !markers["CodeMirror-linenumbers"]))\n
        lineView.lineNumber = gutterWrap.appendChild(\n
          elt("div", lineNumberFor(cm.options, lineN),\n
              "CodeMirror-linenumber CodeMirror-gutter-elt",\n
              "left: " + dims.gutterLeft["CodeMirror-linenumbers"] + "px; width: "\n
              + cm.display.lineNumInnerWidth + "px"));\n
      if (markers) for (var k = 0; k < cm.options.gutters.length; ++k) {\n
        var id = cm.options.gutters[k], found = markers.hasOwnProperty(id) && markers[id];\n
        if (found)\n
          gutterWrap.appendChild(elt("div", [found], "CodeMirror-gutter-elt", "left: " +\n
                                     dims.gutterLeft[id] + "px; width: " + dims.gutterWidth[id] + "px"));\n
      }\n
    }\n
  }\n
\n
  function updateLineWidgets(cm, lineView, dims) {\n
    if (lineView.alignable) lineView.alignable = null;\n
    for (var node = lineView.node.firstChild, next; node; node = next) {\n
      var next = node.nextSibling;\n
      if (node.className == "CodeMirror-linewidget")\n
        lineView.node.removeChild(node);\n
    }\n
    insertLineWidgets(cm, lineView, dims);\n
  }\n
\n
  // Build a line\'s DOM representation from scratch\n
  function buildLineElement(cm, lineView, lineN, dims) {\n
    var built = getLineContent(cm, lineView);\n
    lineView.text = lineView.node = built.pre;\n
    if (built.bgClass) lineView.bgClass = built.bgClass;\n
    if (built.textClass) lineView.textClass = built.textClass;\n
\n
    updateLineClasses(lineView);\n
    updateLineGutter(cm, lineView, lineN, dims);\n
    insertLineWidgets(cm, lineView, dims);\n
    return lineView.node;\n
  }\n
\n
  // A lineView may contain multiple logical lines (when merged by\n
  // collapsed spans). The widgets for all of them need to be drawn.\n
  function insertLineWidgets(cm, lineView, dims) {\n
    insertLineWidgetsFor(cm, lineView.line, lineView, dims, true);\n
    if (lineView.rest) for (var i = 0; i < lineView.rest.length; i++)\n
      insertLineWidgetsFor(cm, lineView.rest[i], lineView, dims, false);\n
  }\n
\n
  function insertLineWidgetsFor(cm, line, lineView, dims, allowAbove) {\n
    if (!line.widgets) return;\n
    var wrap = ensureLineWrapped(lineView);\n
    for (var i = 0, ws = line.widgets; i < ws.length; ++i) {\n
      var widget = ws[i], node = elt("div", [widget.node], "CodeMirror-linewidget");\n
      if (!widget.handleMouseEvents) node.setAttribute("cm-ignore-events", "true");\n
      positionLineWidget(widget, node, lineView, dims);\n
      cm.display.input.setUneditable(node);\n
      if (allowAbove && widget.above)\n
        wrap.insertBefore(node, lineView.gutter || lineView.text);\n
      else\n
        wrap.appendChild(node);\n
      signalLater(widget, "redraw");\n
    }\n
  }\n
\n
  function positionLineWidget(widget, node, lineView, dims) {\n
    if (widget.noHScroll) {\n
      (lineView.alignable || (lineView.alignable = [])).push(node);\n
      var width = dims.wrapperWidth;\n
      node.style.left = dims.fixedPos + "px";\n
      if (!widget.coverGutter) {\n
        width -= dims.gutterTotalWidth;\n
        node.style.paddingLeft = dims.gutterTotalWidth + "px";\n
      }\n
      node.style.width = width + "px";\n
    }\n
    if (widget.coverGutter) {\n
      node.style.zIndex = 5;\n
      node.style.position = "relative";\n
      if (!widget.noHScroll) node.style.marginLeft = -dims.gutterTotalWidth + "px";\n
    }\n
  }\n
\n
  // POSITION OBJECT\n
\n
  // A Pos instance represents a position within the text.\n
  var Pos = CodeMirror.Pos = function(line, ch) {\n
    if (!(this instanceof Pos)) return new Pos(line, ch);\n
    this.line = line; this.ch = ch;\n
  };\n
\n
  // Compare two positions, return 0 if they are the same, a negative\n
  // number when a is less, and a positive number otherwise.\n
  var cmp = CodeMirror.cmpPos = function(a, b) { return a.line - b.line || a.ch - b.ch; };\n
\n
  function copyPos(x) {return Pos(x.line, x.ch);}\n
  function maxPos(a, b) { return cmp(a, b) < 0 ? b : a; }\n
  function minPos(a, b) { return cmp(a, b) < 0 ? a : b; }\n
\n
  // INPUT HANDLING\n
\n
  function ensureFocus(cm) {\n
    if (!cm.state.focused) { cm.display.input.focus(); onFocus(cm); }\n
  }\n
\n
  // This will be set to an array of strings when copying, so that,\n
  // when pasting, we know what kind of selections the copied text\n
  // was made out of.\n
  var lastCopied = null;\n
\n
  function applyTextInput(cm, inserted, deleted, sel, origin) {\n
    var doc = cm.doc;\n
    cm.display.shift = false;\n
    if (!sel) sel = doc.sel;\n
\n
    var paste = cm.state.pasteIncoming || origin == "paste";\n
    var textLines = doc.splitLines(inserted), multiPaste = null;\n
    // When pasing N lines into N selections, insert one line per selection\n
    if (paste && sel.ranges.length > 1) {\n
      if (lastCopied && lastCopied.join("\\n") == inserted) {\n
        if (sel.ranges.length % lastCopied.length == 0) {\n
          multiPaste = [];\n
          for (var i = 0; i < lastCopied.length; i++)\n
            multiPaste.push(doc.splitLines(lastCopied[i]));\n
        }\n
      } else if (textLines.length == sel.ranges.length) {\n
        multiPaste = map(textLines, function(l) { return [l]; });\n
      }\n
    }\n
\n
    // Normal behavior is to insert the new text into every selection\n
    for (var i = sel.ranges.length - 1; i >= 0; i--) {\n
      var range = sel.ranges[i];\n
      var from = range.from(), to = range.to();\n
      if (range.empty()) {\n
        if (deleted && deleted > 0) // Handle deletion\n
          from = Pos(from.line, from.ch - deleted);\n
        else if (cm.state.overwrite && !paste) // Handle overwrite\n
          to = Pos(to.line, Math.min(getLine(doc, to.line).text.length, to.ch + lst(textLines).length));\n
      }\n
      var updateInput = cm.curOp.updateInput;\n
      var changeEvent = {from: from, to: to, text: multiPaste ? multiPaste[i % multiPaste.length] : textLines,\n
                         origin: origin || (paste ? "paste" : cm.state.cutIncoming ? "cut" : "+input")};\n
      makeChange(cm.doc, changeEvent);\n
      signalLater(cm, "inputRead", cm, changeEvent);\n
    }\n
    if (inserted && !paste)\n
      triggerElectric(cm, inserted);\n
\n
    ensureCursorVisible(cm);\n
    cm.curOp.updateInput = updateInput;\n
    cm.curOp.typing = true;\n
    cm.state.pasteIncoming = cm.state.cutIncoming = false;\n
  }\n
\n
  function handlePaste(e, cm) {\n
    var pasted = e.clipboardData && e.clipboardData.getData("text/plain");\n
    if (pasted) {\n
      e.preventDefault();\n
      if (!cm.isReadOnly() && !cm.options.disableInput)\n
        runInOp(cm, function() { applyTextInput(cm, pasted, 0, null, "paste"); });\n
      return true;\n
    }\n
  }\n
\n
  function triggerElectric(cm, inserted) {\n
    // When an \'electric\' character is inserted, immediately trigger a reindent\n
    if (!cm.options.electricChars || !cm.options.smartIndent) return;\n
    var sel = cm.doc.sel;\n
\n
    for (var i = sel.ranges.length - 1; i >= 0; i--) {\n
      var range = sel.ranges[i];\n
      if (range.head.ch > 100 || (i && sel.ranges[i - 1].head.line == range.head.line)) continue;\n
      var mode = cm.getModeAt(range.head);\n
      var indented = false;\n
      if (mode.electricChars) {\n
        for (var j = 0; j < mode.electricChars.length; j++)\n
          if (inserted.indexOf(mode.electricChars.charAt(j)) > -1) {\n
            indented = indentLine(cm, range.head.line, "smart");\n
            break;\n
          }\n
      } else if (mode.electricInput) {\n
        if (mode.electricInput.test(getLine(cm.doc, range.head.line).text.slice(0, range.head.ch)))\n
          indented = indentLine(cm, range.head.line, "smart");\n
      }\n
      if (indented) signalLater(cm, "electricInput", cm, range.head.line);\n
    }\n
  }\n
\n
  function copyableRanges(cm) {\n
    var text = [], ranges = [];\n
    for (var i = 0; i < cm.doc.sel.ranges.length; i++) {\n
      var line = cm.doc.sel.ranges[i].head.line;\n
      var lineRange = {anchor: Pos(line, 0), head: Pos(line + 1, 0)};\n
      ranges.push(lineRange);\n
      text.push(cm.getRange(lineRange.anchor, lineRange.head));\n
    }\n
    return {text: text, ranges: ranges};\n
  }\n
\n
  function disableBrowserMagic(field) {\n
    field.setAttribute("autocorrect", "off");\n
    field.setAttribute("autocapitalize", "off");\n
    field.setAttribute("spellcheck", "false");\n
  }\n
\n
  // TEXTAREA INPUT STYLE\n
\n
  function TextareaInput(cm) {\n
    this.cm = cm;\n
    // See input.poll and input.reset\n
    this.prevInput = "";\n
\n
    // Flag that indicates whether we expect input to appear real soon\n
    // now (after some event like \'keypress\' or \'input\') and are\n
    // polling intensively.\n
    this.pollingFast = false;\n
    // Self-resetting timeout for the poller\n
    this.polling = new Delayed();\n
    // Tracks when input.reset has punted to just putting a short\n
    // string into the textarea instead of the full selection.\n
    this.inaccurateSelection = false;\n
    // Used to work around IE issue with selection being forgotten when focus moves away from textarea\n
    this.hasSelection = false;\n
    this.composing = null;\n
  };\n
\n
  function hiddenTextarea() {\n
    var te = elt("textarea", null, null, "position: absolute; padding: 0; width: 1px; height: 1em; outline: none");\n
    var div = elt("div", [te], null, "overflow: hidden; position: relative; width: 3px; height: 0px;");\n
    // The textarea is kept positioned near the cursor to prevent the\n
    // fact that it\'ll be scrolled into view on input from scrolling\n
    // our fake cursor out of view. On webkit, when wrap=off, paste is\n
    // very slow. So make the area wide instead.\n
    if (webkit) te.style.width = "1000px";\n
    else te.setAttribute("wrap", "off");\n
    // If border: 0; -- iOS fails to open keyboard (issue #1287)\n
    if (ios) te.style.border = "1px solid black";\n
    disableBrowserMagic(te);\n
    return div;\n
  }\n
\n
  TextareaInput.prototype = copyObj({\n
    init: function(display) {\n
      var input = this, cm = this.cm;\n
\n
      // Wraps and hides input textarea\n
      var div = this.wrapper = hiddenTextarea();\n
      // The semihidden textarea that is focused when the editor is\n
      // focused, and receives input.\n
      var te = this.textarea = div.firstChild;\n
      display.wrapper.insertBefore(div, display.wrapper.firstChild);\n
\n
      // Needed to hide big blue blinking cursor on Mobile Safari (doesn\'t seem to work in iOS 8 anymore)\n
      if (ios) te.style.width = "0px";\n
\n
      on(te, "input", function() {\n
        if (ie && ie_version >= 9 && input.hasSelection) input.hasSelection = null;\n
        input.poll();\n
      });\n
\n
      on(te, "paste", function(e) {\n
        if (signalDOMEvent(cm, e) || handlePaste(e, cm)) return\n
\n
        cm.state.pasteIncoming = true;\n
        input.fastPoll();\n
      });\n
\n
      function prepareCopyCut(e) {\n
        if (cm.somethingSelected()) {\n
          lastCopied = cm.getSelections();\n
          if (input.inaccurateSelection) {\n
            input.prevInput = "";\n
            input.inaccurateSelection = false;\n
            te.value = lastCopied.join("\\n");\n
            selectInput(te);\n
          }\n
        } else if (!cm.options.lineWiseCopyCut) {\n
          return;\n
        } else {\n
          var ranges = copyableRanges(cm);\n
          lastCopied = ranges.text;\n
          if (e.type == "cut") {\n
            cm.setSelections(ranges.ranges, null, sel_dontScroll);\n
          } else {\n
            input.prevInput = "";\n
            te.value = ranges.text.join("\\n");\n
            selectInput(te);\n
          }\n
        }\n
        if (e.type == "cut") cm.state.cutIncoming = true;\n
      }\n
      on(te, "cut", prepareCopyCut);\n
      on(te, "copy", prepareCopyCut);\n
\n
      on(display.scroller, "paste", function(e) {\n
        if (eventInWidget(display, e) || signalDOMEvent(cm, e)) return;\n
        cm.state.pasteIncoming = true;\n
        input.focus();\n
      });\n
\n
      // Prevent normal selection in the editor (we handle our own)\n
      on(display.lineSpace, "selectstart", function(e) {\n
        if (!eventInWidget(display, e)) e_preventDefault(e);\n
      });\n
\n
      on(te, "compositionstart", function() {\n
        var start = cm.getCursor("from");\n
        if (input.composing) input.composing.range.clear()\n
        input.composing = {\n
          start: start,\n
          range: cm.markText(start, cm.getCursor("to"), {className: "CodeMirror-composing"})\n
        };\n
      });\n
      on(te, "compositionend", function() {\n
        if (input.composing) {\n
          input.poll();\n
          input.composing.range.clear();\n
          input.composing = null;\n
        }\n
      });\n
    },\n
\n
    prepareSelection: function() {\n
      // Redraw the selection and/or cursor\n
      var cm = this.cm, display = cm.display, doc = cm.doc;\n
      var result = prepareSelection(cm);\n
\n
      // Move the hidden textarea near the cursor to prevent scrolling artifacts\n
      if (cm.options.moveInputWithCursor) {\n
        var headPos = cursorCoords(cm, doc.sel.primary().head, "div");\n
        var wrapOff = display.wrapper.getBoundingClientRect(), lineOff = display.lineDiv.getBoundingClientRect();\n
        result.teTop = Math.max(0, Math.min(display.wrapper.clientHeight - 10,\n
                                            headPos.top + lineOff.top - wrapOff.top));\n
        result.teLeft = Math.max(0, Math.min(display.wrapper.clientWidth - 10,\n
                                             headPos.left + lineOff.left - wrapOff.left));\n
      }\n
\n
      return result;\n
    },\n
\n
    showSelection: function(drawn) {\n
      var cm = this.cm, display = cm.display;\n
      removeChildrenAndAdd(display.cursorDiv, drawn.cursors);\n
      removeChildrenAndAdd(display.selectionDiv, drawn.selection);\n
      if (drawn.teTop != null) {\n
        this.wrapper.style.top = drawn.teTop + "px";\n
        this.wrapper.style.left = drawn.teLeft + "px";\n
      }\n
    },\n
\n
    // Reset the input to correspond to the selection (or to be empty,\n
    // when not typing and nothing is selected)\n
    reset: function(typing) {\n
      if (this.contextMenuPending) return;\n
      var minimal, selected, cm = this.cm, doc = cm.doc;\n
      if (cm.somethingSelected()) {\n
        this.prevInput = "";\n
        var range = doc.sel.primary();\n
        minimal = hasCopyEvent &&\n
          (range.to().line - range.from().line > 100 || (selected = cm.getSelection()).length > 1000);\n
        var content = minimal ? "-" : selected || cm.getSelection();\n
        this.textarea.value = content;\n
        if (cm.state.focused) selectInput(this.textarea);\n
        if (ie && ie_version >= 9) this.hasSelection = content;\n
      } else if (!typing) {\n
        this.prevInput = this.textarea.value = "";\n
        if (ie && ie_version >= 9) this.hasSelection = null;\n
      }\n
      this.inaccurateSelection = minimal;\n
    },\n
\n
    getField: function() { return this.textarea; },\n
\n
    supportsTouch: function() { return false; },\n
\n
    focus: function() {\n
      if (this.cm.options.readOnly != "nocursor" && (!mobile || activeElt() != this.textarea)) {\n
        try { this.textarea.focus(); }\n
        catch (e) {} // IE8 will throw if the textarea is display: none or not in DOM\n
      }\n
    },\n
\n
    blur: function() { this.textarea.blur(); },\n
\n
    resetPosition: function() {\n
      this.wrapper.style.top = this.wrapper.style.left = 0;\n
    },\n
\n
    receivedFocus: function() { this.slowPoll(); },\n
\n
    // Poll for input changes, using the normal rate of polling. This\n
    // runs as long as the editor is focused.\n
    slowPoll: function() {\n
      var input = this;\n
      if (input.pollingFast) return;\n
      input.polling.set(this.cm.options.pollInterval, function() {\n
        input.poll();\n
        if (input.cm.state.focused) input.slowPoll();\n
      });\n
    },\n
\n
    // When an event has just come in that is likely to add or change\n
    // something in the input textarea, we poll faster, to ensure that\n
    // the change appears on the screen quickly.\n
    fastPoll: function() {\n
      var missed = false, input = this;\n
      input.pollingFast = true;\n
      function p() {\n
        var changed = input.poll();\n
        if (!changed && !missed) {missed = true; input.polling.set(60, p);}\n
        else {input.pollingFast = false; input.slowPoll();}\n
      }\n
      input.polling.set(20, p);\n
    },\n
\n
    // Read input from the textarea, and update the document to match.\n
    // When something is selected, it is present in the textarea, and\n
    // selected (unless it is huge, in which case a placeholder is\n
    // used). When nothing is selected, the cursor sits after previously\n
    // seen text (can be empty), which is stored in prevInput (we must\n
    // not reset the textarea when typing, because that breaks IME).\n
    poll: function() {\n
      var cm = this.cm, input = this.textarea, prevInput = this.prevInput;\n
      // Since this is called a *lot*, try to bail out as cheaply as\n
      // possible when it is clear that nothing happened. hasSelection\n
      // will be the case when there is a lot of text in the textarea,\n
      // in which case reading its value would be expensive.\n
      if (this.contextMenuPending || !cm.state.focused ||\n
          (hasSelection(input) && !prevInput && !this.composing) ||\n
          cm.isReadOnly() || cm.options.disableInput || cm.state.keySeq)\n
        return false;\n
\n
      var text = input.value;\n
      // If nothing changed, bail.\n
      if (text == prevInput && !cm.somethingSelected()) return false;\n
      // Work around nonsensical selection resetting in IE9/10, and\n
      // inexplicable appearance of private area unicode characters on\n
      // some key combos in Mac (#2689).\n
      if (ie && ie_version >= 9 && this.hasSelection === text ||\n
          mac && /[\\uf700-\\uf7ff]/.test(text)) {\n
        cm.display.input.reset();\n
        return false;\n
      }\n
\n
      if (cm.doc.sel == cm.display.selForContextMenu) {\n
        var first = text.charCodeAt(0);\n
        if (first == 0x200b && !prevInput) prevInput = "\\u200b";\n
        if (first == 0x21da) { this.reset(); return this.cm.execCommand("undo"); }\n
      }\n
      // Find the part of the input that is actually new\n
      var same = 0, l = Math.min(prevInput.length, text.length);\n
      while (same < l && prevInput.charCodeAt(same) == text.charCodeAt(same)) ++same;\n
\n
      var self = this;\n
      runInOp(cm, function() {\n
        applyTextInput(cm, text.slice(same), prevInput.length - same,\n
                       null, self.composing ? "*compose" : null);\n
\n
        // Don\'t leave long text in the textarea, since it makes further polling slow\n
        if (text.length > 1000 || text.indexOf("\\n") > -1) input.value = self.prevInput = "";\n
        else self.prevInput = text;\n
\n
        if (self.composing) {\n
          self.composing.range.clear();\n
          self.composing.range = cm.markText(self.composing.start, cm.getCursor("to"),\n
                                             {className: "CodeMirror-composing"});\n
        }\n
      });\n
      return true;\n
    },\n
\n
    ensurePolled: function() {\n
      if (this.pollingFast && this.poll()) this.pollingFast = false;\n
    },\n
\n
    onKeyPress: function() {\n
      if (ie && ie_version >= 9) this.hasSelection = null;\n
      this.fastPoll();\n
    },\n
\n
    onContextMenu: function(e) {\n
      var input = this, cm = input.cm, display = cm.display, te = input.textarea;\n
      var pos = posFromMouse(cm, e), scrollPos = display.scroller.scrollTop;\n
      if (!pos || presto) return; // Opera is difficult.\n
\n
      // Reset the current text selection only if the click is done outside of the selection\n
      // and \'resetSelectionOnContextMenu\' option is true.\n
      var reset = cm.options.resetSelectionOnContextMenu;\n
      if (reset && cm.doc.sel.contains(pos) == -1)\n
        operation(cm, setSelection)(cm.doc, simpleSelection(pos), sel_dontScroll);\n
\n
      var oldCSS = te.style.cssText;\n
      input.wrapper.style.position = "absolute";\n
      te.style.cssText = "position: fixed; width: 30px; height: 30px; top: " + (e.clientY - 5) +\n
        "px; left: " + (e.clientX - 5) + "px; z-index: 1000; background: " +\n
        (ie ? "rgba(255, 255, 255, .05)" : "transparent") +\n
        "; outline: none; border-width: 0; outline: none; overflow: hidden; opacity: .05; filter: alpha(opacity=5);";\n
      if (webkit) var oldScrollY = window.scrollY; // Work around Chrome issue (#2712)\n
      display.input.focus();\n
      if (webkit) window.scrollTo(null, oldScrollY);\n
      display.input.reset();\n
      // Adds "Select all" to context menu in FF\n
      if (!cm.somethingSelected()) te.value = input.prevInput = " ";\n
      input.contextMenuPending = true;\n
      display.selForContextMenu = cm.doc.sel;\n
      clearTimeout(display.detectingSelectAll);\n
\n
      // Select-all will be greyed out if there\'s nothing to select, so\n
      // this adds a zero-width space so that we can later check whether\n
      // it got selected.\n
      function prepareSelectAllHack() {\n
        if (te.selectionStart != null) {\n
          var selected = cm.somethingSelected();\n
          var extval = "\\u200b" + (selected ? te.value : "");\n
          te.value = "\\u21da"; // Used to catch context-menu undo\n
          te.value = extval;\n
          input.prevInput = selected ? "" : "\\u200b";\n
          te.selectionStart = 1; te.selectionEnd = extval.length;\n
          // Re-set this, in case some other handler touched the\n
          // selection in the meantime.\n
          display.selForContextMenu = cm.doc.sel;\n
        }\n
      }\n
      function rehide() {\n
        input.contextMenuPending = false;\n
        input.wrapper.style.position = "relative";\n
        te.style.cssText = oldCSS;\n
        if (ie && ie_version < 9) display.scrollbars.setScrollTop(display.scroller.scrollTop = scrollPos);\n
\n
        // Try to detect the user choosing select-all\n
        if (te.selectionStart != null) {\n
          if (!ie || (ie && ie_version < 9)) prepareSelectAllHack();\n
          var i = 0, poll = function() {\n
            if (display.selForContextMenu == cm.doc.sel && te.selectionStart == 0 &&\n
                te.selectionEnd > 0 && input.prevInput == "\\u200b")\n
              operation(cm, commands.selectAll)(cm);\n
            else if (i++ < 10) display.detectingSelectAll = setTimeout(poll, 500);\n
            else display.input.reset();\n
          };\n
          display.detectingSelectAll = setTimeout(poll, 200);\n
        }\n
      }\n
\n
      if (ie && ie_version >= 9) prepareSelectAllHack();\n
      if (captureRightClick) {\n
        e_stop(e);\n
        var mouseup = function() {\n
          off(window, "mouseup", mouseup);\n
          setTimeout(rehide, 20);\n
        };\n
        on(window, "mouseup", mouseup);\n
      } else {\n
        setTimeout(rehide, 50);\n
      }\n
    },\n
\n
    readOnlyChanged: function(val) {\n
      if (!val) this.reset();\n
    },\n
\n
    setUneditable: nothing,\n
\n
    needsContentAttribute: false\n
  }, TextareaInput.prototype);\n
\n
  // CONTENTEDITABLE INPUT STYLE\n
\n
  function ContentEditableInput(cm) {\n
    this.cm = cm;\n
    this.lastAnchorNode = this.lastAnchorOffset = this.lastFocusNode = this.lastFocusOffset = null;\n
    this.polling = new Delayed();\n
    this.gracePeriod = false;\n
  }\n
\n
  ContentEditableInput.prototype = copyObj({\n
    init: function(display) {\n
      var input = this, cm = input.cm;\n
      var div = input.div = display.lineDiv;\n
      disableBrowserMagic(div);\n
\n
      on(div, "paste", function(e) {\n
        if (!signalDOMEvent(cm, e)) handlePaste(e, cm);\n
      })\n
\n
      on(div, "compositionstart", function(e) {\n
        var data = e.data;\n
        input.composing = {sel: cm.doc.sel, data: data, startData: data};\n
        if (!data) return;\n
        var prim = cm.doc.sel.primary();\n
        var line = cm.getLine(prim.head.line);\n
        var found = line.indexOf(data, Math.max(0, prim.head.ch - data.length));\n
        if (found > -1 && found <= prim.head.ch)\n
          input.composing.sel = simpleSelection(Pos(prim.head.line, found),\n
                                                Pos(prim.head.line, found + data.length));\n
      });\n
      on(div, "compositionupdate", function(e) {\n
        input.composing.data = e.data;\n
      });\n
      on(div, "compositionend", function(e) {\n
        var ours = input.composing;\n
        if (!ours) return;\n
        if (e.data != ours.startData && !/\\u200b/.test(e.data))\n
          ours.data = e.data;\n
        // Need a small delay to prevent other code (input event,\n
        // selection polling) from doing damage when fired right after\n
        // compositionend.\n
        setTimeout(function() {\n
          if (!ours.handled)\n
            input.applyComposition(ours);\n
          if (input.composing == ours)\n
            input.composing = null;\n
        }, 50);\n
      });\n
\n
      on(div, "touchstart", function() {\n
        input.forceCompositionEnd();\n
      });\n
\n
      on(div, "input", function() {\n
        if (input.composing) return;\n
        if (cm.isReadOnly() || !input.pollContent())\n
          runInOp(input.cm, function() {regChange(cm);});\n
      });\n
\n
      function onCopyCut(e) {\n
        if (cm.somethingSelected()) {\n
          lastCopied = cm.getSelections();\n
          if (e.type == "cut") cm.replaceSelection("", null, "cut");\n
        } else if (!cm.options.lineWiseCopyCut) {\n
          return;\n
        } else {\n
          var ranges = copyableRanges(cm);\n
          lastCopied = ranges.text;\n
          if (e.type == "cut") {\n
            cm.operation(function() {\n
              cm.setSelections(ranges.ranges, 0, sel_dontScroll);\n
              cm.replaceSelection("", null, "cut");\n
            });\n
          }\n
        }\n
        // iOS exposes the clipboard API, but seems to discard content inserted into it\n
        if (e.clipboardData && !ios) {\n
          e.preventDefault();\n
          e.clipboardData.clearData();\n
          e.clipboardData.setData("text/plain", lastCopied.join("\\n"));\n
        } else {\n
          // Old-fashioned briefly-focus-a-textarea hack\n
          var kludge = hiddenTextarea(), te = kludge.firstChild;\n
          cm.display.lineSpace.insertBefore(kludge, cm.display.lineSpace.firstChild);\n
          te.value = lastCopied.join("\\n");\n
          var hadFocus = document.activeElement;\n
          selectInput(te);\n
          setTimeout(function() {\n
            cm.display.lineSpace.removeChild(kludge);\n
            hadFocus.focus();\n
          }, 50);\n
        }\n
      }\n
      on(div, "copy", onCopyCut);\n
      on(div, "cut", onCopyCut);\n
    },\n
\n
    prepareSelection: function() {\n
      var result = prepareSelection(this.cm, false);\n
      result.focus = this.cm.state.focused;\n
      return result;\n
    },\n
\n
    showSelection: function(info) {\n
      if (!info || !this.cm.display.view.length) return;\n
      if (info.focus) this.showPrimarySelection();\n
      this.showMultipleSelections(info);\n
    },\n
\n
    showPrimarySelection: function() {\n
      var sel = window.getSelection(), prim = this.cm.doc.sel.primary();\n
      var curAnchor = domToPos(this.cm, sel.anchorNode, sel.anchorOffset);\n
      var curFocus = domToPos(this.cm, sel.focusNode, sel.focusOffset);\n
      if (curAnchor && !curAnchor.bad && curFocus && !curFocus.bad &&\n
          cmp(minPos(curAnchor, curFocus), prim.from()) == 0 &&\n
          cmp(maxPos(curAnchor, curFocus), prim.to()) == 0)\n
        return;\n
\n
      var start = posToDOM(this.cm, prim.from());\n
      var end = posToDOM(this.cm, prim.to());\n
      if (!start && !end) return;\n
\n
      var view = this.cm.display.view;\n
      var old = sel.rangeCount && sel.getRangeAt(0);\n
      if (!start) {\n
        start = {node: view[0].measure.map[2], offset: 0};\n
      } else if (!end) { // FIXME dangerously hacky\n
        var measure = view[view.length - 1].measure;\n
        var map = measure.maps ? measure.maps[measure.maps.length - 1] : measure.map;\n
        end = {node: map[map.length - 1], offset: map[map.length - 2] - map[map.length - 3]};\n
      }\n
\n
      try { var rng = range(start.node, start.offset, end.offset, end.node); }\n
      catch(e) {} // Our model of the DOM might be outdated, in which case the range we try to set can be impossible\n
      if (rng) {\n
        if (!gecko && this.cm.state.focused) {\n
          sel.collapse(start.node, start.offset);\n
          if (!rng.collapsed) sel.addRange(rng);\n
        } else {\n
          sel.removeAllRanges();\n
          sel.addRange(rng);\n
        }\n
        if (old && sel.anchorNode == null) sel.addRange(old);\n
        else if (gecko) this.startGracePeriod();\n
      }\n
      this.rememberSelection();\n
    },\n
\n
    startGracePeriod: function() {\n
      var input = this;\n
      clearTimeout(this.gracePeriod);\n
      this.gracePeriod = setTimeout(function() {\n
        input.gracePeriod = false;\n
        if (input.selectionChanged())\n
          input.cm.operation(function() { input.cm.curOp.selectionChanged = true; });\n
      }, 20);\n
    },\n
\n
    showMultipleSelections: function(info) {\n
      removeChildrenAndAdd(this.cm.display.cursorDiv, info.cursors);\n
      removeChildrenAndAdd(this.cm.display.selectionDiv, info.selection);\n
    },\n
\n
    rememberSelection: function() {\n
      var sel = window.getSelection();\n
      this.lastAnchorNode = sel.anchorNode; this.lastAnchorOffset = sel.anchorOffset;\n
      this.lastFocusNode = sel.focusNode; this.lastFocusOffset = sel.focusOffset;\n
    },\n
\n
    selectionInEditor: function() {\n
      var sel = window.getSelection();\n
      if (!sel.rangeCount) return false;\n
      var node = sel.getRangeAt(0).commonAncestorContainer;\n
      return contains(this.div, node);\n
    },\n
\n
    focus: function() {\n
      if (this.cm.options.readOnly != "nocursor") this.div.focus();\n
    },\n
    blur: function() { this.div.blur(); },\n
    getField: function() { return this.div; },\n
\n
    supportsTouch: function() { return true; },\n
\n
    receivedFocus: function() {\n
      var input = this;\n
      if (this.selectionInEditor())\n
        this.pollSelection();\n
      else\n
        runInOp(this.cm, function() { input.cm.curOp.selectionChanged = true; });\n
\n
      function poll() {\n
        if (input.cm.state.focused) {\n
          input.pollSelection();\n
          input.polling.set(input.cm.options.pollInterval, poll);\n
        }\n
      }\n
      this.polling.set(this.cm.options.pollInterval, poll);\n
    },\n
\n
    selectionChanged: function() {\n
      var sel = window.getSelection();\n
      return sel.anchorNode != this.lastAnchorNode || sel.anchorOffset != this.lastAnchorOffset ||\n
        sel.focusNode != this.lastFocusNode || sel.focusOffset != this.lastFocusOffset;\n
    },\n
\n
    pollSelection: function() {\n
      if (!this.composing && !this.gracePeriod && this.selectionChanged()) {\n
        var sel = window.getSelection(), cm = this.cm;\n
        this.rememberSelection();\n
        var anchor = domToPos(cm, sel.anchorNode, sel.anchorOffset);\n
        var head = domToPos(cm, sel.focusNode, sel.focusOffset);\n
        if (anchor && head) runInOp(cm, function() {\n
          setSelection(cm.doc, simpleSelection(anchor, head), sel_dontScroll);\n
          if (anchor.bad || head.bad) cm.curOp.selectionChanged = true;\n
        });\n
      }\n
    },\n
\n
    pollContent: function() {\n
      var cm = this.cm, display = cm.display, sel = cm.doc.sel.primary();\n
      var from = sel.from(), to = sel.to();\n
      if (from.line < display.viewFrom || to.line > display.viewTo - 1) return false;\n
\n
      var fromIndex;\n
      if (from.line == display.viewFrom || (fromIndex = findViewIndex(cm, from.line)) == 0) {\n
        var fromLine = lineNo(display.view[0].line);\n
        var fromNode = display.view[0].node;\n
      } else {\n
        var fromLine = lineNo(display.view[fromIndex].line);\n
        var fromNode = display.view[fromIndex - 1].node.nextSibling;\n
      }\n
      var toIndex = findViewIndex(cm, to.line);\n
      if (toIndex == display.view.length - 1) {\n
        var toLine = display.viewTo - 1;\n
        var toNode = display.lineDiv.lastChild;\n
      } else {\n
        var toLine = lineNo(display.view[toIndex + 1].line) - 1;\n
        var toNode = display.view[toIndex + 1].node.previousSibling;\n
      }\n
\n
      var newText = cm.doc.splitLines(domTextBetween(cm, fromNode, toNode, fromLine, toLine));\n
      var oldText = getBetween(cm.doc, Pos(fromLine, 0), Pos(toLine, getLine(cm.doc, toLine).text.length));\n
      while (newText.length > 1 && oldText.length > 1) {\n
        if (lst(newText) == lst(oldText)) { newText.pop(); oldText.pop(); toLine--; }\n
        else if (newText[0] == oldText[0]) { newText.shift(); oldText.shift(); fromLine++; }\n
        else break;\n
      }\n
\n
      var cutFront = 0, cutEnd = 0;\n
      var newTop = newText[0], oldTop = oldText[0], maxCutFront = Math.min(newTop.length, oldTop.length);\n
      while (cutFront < maxCutFront && newTop.charCodeAt(cutFront) == oldTop.charCodeAt(cutFront))\n
        ++cutFront;\n
      var newBot = lst(newText), oldBot = lst(oldText);\n
      var maxCutEnd = Math.min(newBot.length - (newText.length == 1 ? cutFront : 0),\n
                               oldBot.length - (oldText.length == 1 ? cutFront : 0));\n
      while (cutEnd < maxCutEnd &&\n
             newBot.charCodeAt(newBot.length - cutEnd - 1) == oldBot.charCodeAt(oldBot.length - cutEnd - 1))\n
        ++cutEnd;\n
\n
      newText[newText.length - 1] = newBot.slice(0, newBot.length - cutEnd);\n
      newText[0] = newText[0].slice(cutFront);\n
\n
      var chFrom = Pos(fromLine, cutFront);\n
      var chTo = Pos(toLine, oldText.length ? lst(oldText).length - cutEnd : 0);\n
      if (newText.length > 1 || newText[0] || cmp(chFrom, chTo)) {\n
        replaceRange(cm.doc, newText, chFrom, chTo, "+input");\n
        return true;\n
      }\n
    },\n
\n
    ensurePolled: function() {\n
      this.forceCompositionEnd();\n
    },\n
    reset: function() {\n
      this.forceCompositionEnd();\n
    },\n
    forceCompositionEnd: function() {\n
      if (!this.composing || this.composing.handled) return;\n
      this.applyComposition(this.composing);\n
      this.composing.handled = true;\n
      this.div.blur();\n
      this.div.focus();\n
    },\n
    applyComposition: function(composing) {\n
      if (this.cm.isReadOnly())\n
        operation(this.cm, regChange)(this.cm)\n
      else if (composing.data && composing.data != composing.startData)\n
        operation(this.cm, applyTextInput)(this.cm, composing.data, 0, composing.sel);\n
    },\n
\n
    setUneditable: function(node) {\n
      node.contentEditable = "false"\n
    },\n
\n
    onKeyPress: function(e) {\n
      e.preventDefault();\n
      if (!this.cm.isReadOnly())\n
        operation(this.cm, applyTextInput)(this.cm, String.fromCharCode(e.charCode == null ? e.keyCode : e.charCode), 0);\n
    },\n
\n
    readOnlyChanged: function(val) {\n
      this.div.contentEditable = String(val != "nocursor")\n
    },\n
\n
    onContextMenu: nothing,\n
    resetPosition: nothing,\n
\n
    needsContentAttribute: true\n
  }, ContentEditableInput.prototype);\n
\n
  function posToDOM(cm, pos) {\n
    var view = findViewForLine(cm, pos.line);\n
    if (!view || view.hidden) return null;\n
    var line = getLine(cm.doc, pos.line);\n
    var info = mapFromLineView(view, line, pos.line);\n
\n
    var order = getOrder(line), side = "left";\n
    if (order) {\n
      var partPos = getBidiPartAt(order, pos.ch);\n
      side = partPos % 2 ? "right" : "left";\n
    }\n
    var result = nodeAndOffsetInLineMap(info.map, pos.ch, side);\n
    result.offset = result.collapse == "right" ? result.end : result.start;\n
    return result;\n
  }\n
\n
  function badPos(pos, bad) { if (bad) pos.bad = true; return pos; }\n
\n
  function domToPos(cm, node, offset) {\n
    var lineNode;\n
    if (node == cm.display.lineDiv) {\n
      lineNode = cm.display.lineDiv.childNodes[offset];\n
      if (!lineNode) return badPos(cm.clipPos(Pos(cm.display.viewTo - 1)), true);\n
      node = null; offset = 0;\n
    } else {\n
      for (lineNode = node;; lineNode = lineNode.parentNode) {\n
        if (!lineNode || lineNode == cm.display.lineDiv) return null;\n
        if (lineNode.parentNode && lineNode.parentNode == cm.display.lineDiv) break;\n
      }\n
    }\n
    for (var i = 0; i < cm.display.view.length; i++) {\n
      var lineView = cm.display.view[i];\n
      if (lineView.node == lineNode)\n
        return locateNodeInLineView(lineView, node, offset);\n
    }\n
  }\n
\n
  function locateNodeInLineView(lineView, node, offset) {\n
    var wrapper = lineView.text.firstChild, bad = false;\n
    if (!node || !contains(wrapper, node)) return badPos(Pos(lineNo(lineView.line), 0), true);\n
    if (node == wrapper) {\n
      bad = true;\n
      node = wrapper.childNodes[offset];\n
      offset = 0;\n
      if (!node) {\n
        var line = lineView.rest ? lst(lineView.rest) : lineView.line;\n
        return badPos(Pos(lineNo(line), line.text.length), bad);\n
      }\n
    }\n
\n
    var textNode = node.nodeType == 3 ? node : null, topNode = node;\n
    if (!textNode && node.childNodes.length == 1 && node.firstChild.nodeType == 3) {\n
      textNode = node.firstChild;\n
      if (offset) offset = textNode.nodeValue.length;\n
    }\n
    while (topNode.parentNode != wrapper) topNode = topNode.parentNode;\n
    var measure = lineView.measure, maps = measure.maps;\n
\n
    function find(textNode, topNode, offset) {\n
      for (var i = -1; i < (maps ? maps.length : 0); i++) {\n
        var map = i < 0 ? measure.map : maps[i];\n
        for (var j = 0; j < map.length; j += 3) {\n
          var curNode = map[j + 2];\n
          if (curNode == textNode || curNode == topNode) {\n
            var line = lineNo(i < 0 ? lineView.line : lineView.rest[i]);\n
            var ch = map[j] + offset;\n
            if (offset < 0 || curNode != textNode) ch = map[j + (offset ? 1 : 0)];\n
            return Pos(line, ch);\n
          }\n
        }\n
      }\n
    }\n
    var found = find(textNode, topNode, offset);\n
    if (found) return badPos(found, bad);\n
\n
    // FIXME this is all really shaky. might handle the few cases it needs to handle, but likely to cause problems\n
    for (var after = topNode.nextSibling, dist = textNode ? textNode.nodeValue.length - offset : 0; after; after = after.nextSibling) {\n
      found = find(after, after.firstChild, 0);\n
      if (found)\n
        return badPos(Pos(found.line, found.ch - dist), bad);\n
      else\n
        dist += after.textContent.length;\n
    }\n
    for (var before = topNode.previousSibling, dist = offset; before; before = before.previousSibling) {\n
      found = find(before, before.firstChild, -1);\n
      if (found)\n
        return badPos(Pos(found.line, found.ch + dist), bad);\n
      else\n
        dist += after.textContent.length;\n
    }\n
  }\n
\n
  function domTextBetween(cm, from, to, fromLine, toLine) {\n
    var text = "", closing = false, lineSep = cm.doc.lineSeparator();\n
    function recognizeMarker(id) { return function(marker) { return marker.id == id; }; }\n
    function walk(node) {\n
      if (node.nodeType == 1) {\n
        var cmText = node.getAttribute("cm-text");\n
        if (cmText != null) {\n
          if (cmText == "") cmText = node.textContent.replace(/\\u200b/g, "");\n
          text += cmText;\n
          return;\n
        }\n
        var markerID = node.getAttribute("cm-marker"), range;\n
        if (markerID) {\n
          var found = cm.findMarks(Pos(fromLine, 0), Pos(toLine + 1, 0), recognizeMarker(+markerID));\n
          if (found.length && (range = found[0].find()))\n
            text += getBetween(cm.doc, range.from, range.to).join(lineSep);\n
          return;\n
        }\n
        if (node.getAttribute("contenteditable") == "false") return;\n
        for (var i = 0; i < node.childNodes.length; i++)\n
          walk(node.childNodes[i]);\n
        if (/^(pre|div|p)$/i.test(node.nodeName))\n
          closing = true;\n
      } else if (node.nodeType == 3) {\n
        var val = node.nodeValue;\n
        if (!val) return;\n
        if (closing) {\n
          text += lineSep;\n
          closing = false;\n
        }\n
        text += val;\n
      }\n
    }\n
    for (;;) {\n
      walk(from);\n
      if (from == to) break;\n
      from = from.nextSibling;\n
    }\n
    return text;\n
  }\n
\n
  CodeMirror.inputStyles = {"textarea": TextareaInput, "contenteditable": ContentEditableInput};\n
\n
  // SELECTION / CURSOR\n
\n
  // Selection objects are immutable. A new one is created every time\n
  // the selection changes. A selection is one or more non-overlapping\n
  // (and non-touching) ranges, sorted, and an integer that indicates\n
  // which one is the primary selection (the one that\'s scrolled into\n
  // view, that getCursor returns, etc).\n
  function Selection(ranges, primIndex) {\n
    this.ranges = ranges;\n
    this.primIndex = primIndex;\n
  }\n
\n
  Selection.prototype = {\n
    primary: function() { return this.ranges[this.primIndex]; },\n
    equals: function(other) {\n
      if (other == this) return true;\n
      if (other.primIndex != this.primIndex || other.ranges.length != this.ranges.length) return false;\n
      for (var i = 0; i < this.ranges.length; i++) {\n
        var here = this.ranges[i], there = other.ranges[i];\n
        if (cmp(here.anchor, there.anchor) != 0 || cmp(here.head, there.head) != 0) return false;\n
      }\n
      return true;\n
    },\n
    deepCopy: function() {\n
      for (var out = [], i = 0; i < this.ranges.length; i++)\n
        out[i] = new Range(copyPos(this.ranges[i].anchor), copyPos(this.ranges[i].head));\n
      return new Selection(out, this.primIndex);\n
    },\n
    somethingSelected: function() {\n
      for (var i = 0; i < this.ranges.length; i++)\n
        if (!this.ranges[i].empty()) return true;\n
      return false;\n
    },\n
    contains: function(pos, end) {\n
      if (!end) end = pos;\n
      for (var i = 0; i < this.ranges.length; i++) {\n
        var range = this.ranges[i];\n
        if (cmp(end, range.from()) >= 0 && cmp(pos, range.to()) <= 0)\n
          return i;\n
      }\n
      return -1;\n
    }\n
  };\n
\n
  function Range(anchor, head) {\n
    this.anchor = anchor; this.head = head;\n
  }\n
\n
  Range.prototype = {\n
    from: function() { return minPos(this.anchor, this.head); },\n
    to: function() { return maxPos(this.anchor, this.head); },\n
    empty: function() {\n
      return this.head.line == this.anchor.line && this.head.ch == this.anchor.ch;\n
    }\n
  };\n
\n
  // Take an unsorted, potentially overlapping set of ranges, and\n
  // build a selection out of it. \'Consumes\' ranges array (modifying\n
  // it).\n
  function normalizeSelection(ranges, primIndex) {\n
    var prim = ranges[primIndex];\n
    ranges.sort(function(a, b) { return cmp(a.from(), b.from()); });\n
    primIndex = indexOf(ranges, prim);\n
    for (var i = 1; i < ranges.length; i++) {\n
      var cur = ranges[i], prev = ranges[i - 1];\n
      if (cmp(prev.to(), cur.from()) >= 0) {\n
        var from = minPos(prev.from(), cur.from()), to = maxPos(prev.to(), cur.to());\n
        var inv = prev.empty() ? cur.from() == cur.head : prev.from() == prev.head;\n
        if (i <= primIndex) --primIndex;\n
        ranges.splice(--i, 2, new Range(inv ? to : from, inv ? from : to));\n
      }\n
    }\n
    return new Selection(ranges, primIndex);\n
  }\n
\n
  function simpleSelection(anchor, head) {\n
    return new Selection([new Range(anchor, head || anchor)], 0);\n
  }\n
\n
  // Most of the external API clips given positions to make sure they\n
  // actually exist within the document.\n
  function clipLine(doc, n) {return Math.max(doc.first, Math.min(n, doc.first + doc.size - 1));}\n
  function clipPos(doc, pos) {\n
    if (pos.line < doc.first) return Pos(doc.first, 0);\n
    var last = doc.first + doc.size - 1;\n
    if (pos.line > last) return Pos(last, getLine(doc, last).text.length);\n
    return clipToLen(pos, getLine(doc, pos.line).text.length);\n
  }\n
  function clipToLen(pos, linelen) {\n
    var ch = pos.ch;\n
    if (ch == null || ch > linelen) return Pos(pos.line, linelen);\n
    else if (ch < 0) return Pos(pos.line, 0);\n
    else return pos;\n
  }\n
  function isLine(doc, l) {return l >= doc.first && l < doc.first + doc.size;}\n
  function clipPosArray(doc, array) {\n
    for (var out = [], i = 0; i < array.length; i++) out[i] = clipPos(doc, array[i]);\n
    return out;\n
  }\n
\n
  // SELECTION UPDATES\n
\n
  // The \'scroll\' parameter given to many of these indicated whether\n
  // the new cursor position should be scrolled into view after\n
  // modifying the selection.\n
\n
  // If shift is held or the extend flag is set, extends a range to\n
  // include a given position (and optionally a second position).\n
  // Otherwise, simply returns the range between the given positions.\n
  // Used for cursor motion and such.\n
  function extendRange(doc, range, head, other) {\n
    if (doc.cm && doc.cm.display.shift || doc.extend) {\n
      var anchor = range.anchor;\n
      if (other) {\n
        var posBefore = cmp(head, anchor) < 0;\n
        if (posBefore != (cmp(other, anchor) < 0)) {\n
          anchor = head;\n
          head = other;\n
        } else if (posBefore != (cmp(head, other) < 0)) {\n
          head = other;\n
        }\n
      }\n
      return new Range(anchor, head);\n
    } else {\n
      return new Range(other || head, head);\n
    }\n
  }\n
\n
  // Extend the primary selection range, discard the rest.\n
  function extendSelection(doc, head, other, options) {\n
    setSelection(doc, new Selection([extendRange(doc, doc.sel.primary(), head, other)], 0), options);\n
  }\n
\n
  // Extend all selections (pos is an array of selections with length\n
  // equal the number of selections)\n
  function extendSelections(doc, heads, options) {\n
    for (var out = [], i = 0; i < doc.sel.ranges.length; i++)\n
      out[i] = extendRange(doc, doc.sel.ranges[i], heads[i], null);\n
    var newSel = normalizeSelection(out, doc.sel.primIndex);\n
    setSelection(doc, newSel, options);\n
  }\n
\n
  // Updates a single range in the selection.\n
  function replaceOneSelection(doc, i, range, options) {\n
    var ranges = doc.sel.ranges.slice(0);\n
    ranges[i] = range;\n
    setSelection(doc, normalizeSelection(ranges, doc.sel.primIndex), options);\n
  }\n
\n
  // Reset the selection to a single range.\n
  function setSimpleSelection(doc, anchor, head, options) {\n
    setSelection(doc, simpleSelection(anchor, head), options);\n
  }\n
\n
  // Give beforeSelectionChange handlers a change to influence a\n
  // selection update.\n
  function filterSelectionChange(doc, sel, options) {\n
    var obj = {\n
      ranges: sel.ranges,\n
      update: function(ranges) {\n
        this.ranges = [];\n
        for (var i = 0; i < ranges.length; i++)\n
          this.ranges[i] = new Range(clipPos(doc, ranges[i].anchor),\n
                                     clipPos(doc, ranges[i].head));\n
      },\n
      origin: options && options.origin\n
    };\n
    signal(doc, "beforeSelectionChange", doc, obj);\n
    if (doc.cm) signal(doc.cm, "beforeSelectionChange", doc.cm, obj);\n
    if (obj.ranges != sel.ranges) return normalizeSelection(obj.ranges, obj.ranges.length - 1);\n
    else return sel;\n
  }\n
\n
  function setSelectionReplaceHistory(doc, sel, options) {\n
    var done = doc.history.done, last = lst(done);\n
    if (last && last.ranges) {\n
      done[done.length - 1] = sel;\n
      setSelectionNoUndo(doc, sel, options);\n
    } else {\n
      setSelection(doc, sel, options);\n
    }\n
  }\n
\n
  // Set a new selection.\n
  function setSelection(doc, sel, options) {\n
    setSelectionNoUndo(doc, sel, options);\n
    addSelectionToHistory(doc, doc.sel, doc.cm ? doc.cm.curOp.id : NaN, options);\n
  }\n
\n
  function setSelectionNoUndo(doc, sel, options) {\n
    if (hasHandler(doc, "beforeSelectionChange") || doc.cm && hasHandler(doc.cm, "beforeSelectionChange"))\n
      sel = filterSelectionChange(doc, sel, options);\n
\n
    var bias = options && options.bias ||\n
      (cmp(sel.primary().head, doc.sel.primary().head) < 0 ? -1 : 1);\n
    setSelectionInner(doc, skipAtomicInSelection(doc, sel, bias, true));\n
\n
    if (!(options && options.scroll === false) && doc.cm)\n
      ensureCursorVisible(doc.cm);\n
  }\n
\n
  function setSelectionInner(doc, sel) {\n
    if (sel.equals(doc.sel)) return;\n
\n
    doc.sel = sel;\n
\n
    if (doc.cm) {\n
      doc.cm.curOp.updateInput = doc.cm.curOp.selectionChanged = true;\n
      signalCursorActivity(doc.cm);\n
    }\n
    signalLater(doc, "cursorActivity", doc);\n
  }\n
\n
  // Verify that the selection does not partially select any atomic\n
  // marked ranges.\n
  function reCheckSelection(doc) {\n
    setSelectionInner(doc, skipAtomicInSelection(doc, doc.sel, null, false), sel_dontScroll);\n
  }\n
\n
  // Return a selection that does not partially select any atomic\n
  // ranges.\n
  function skipAtomicInSelection(doc, sel, bias, mayClear) {\n
    var out;\n
    for (var i = 0; i < sel.ranges.length; i++) {\n
      var range = sel.ranges[i];\n
      var old = sel.ranges.length == doc.sel.ranges.length && doc.sel.ranges[i];\n
      var newAnchor = skipAtomic(doc, range.anchor, old && old.anchor, bias, mayClear);\n
      var newHead = skipAtomic(doc, range.head, old && old.head, bias, mayClear);\n
      if (out || newAnchor != range.anchor || newHead != range.head) {\n
        if (!out) out = sel.ranges.slice(0, i);\n
        out[i] = new Range(newAnchor, newHead);\n
      }\n
    }\n
    return out ? normalizeSelection(out, sel.primIndex) : sel;\n
  }\n
\n
  function skipAtomicInner(doc, pos, oldPos, dir, mayClear) {\n
    var line = getLine(doc, pos.line);\n
    if (line.markedSpans) for (var i = 0; i < line.markedSpans.length; ++i) {\n
      var sp = line.markedSpans[i], m = sp.marker;\n
      if ((sp.from == null || (m.inclusiveLeft ? sp.from <= pos.ch : sp.from < pos.ch)) &&\n
          (sp.to == null || (m.inclusiveRight ? sp.to >= pos.ch : sp.to > pos.ch))) {\n
        if (mayClear) {\n
          signal(m, "beforeCursorEnter");\n
          if (m.explicitlyCleared) {\n
            if (!line.markedSpans) break;\n
            else {--i; continue;}\n
          }\n
        }\n
        if (!m.atomic) continue;\n
\n
        if (oldPos) {\n
          var near = m.find(dir < 0 ? 1 : -1), diff;\n
          if (dir < 0 ? m.inclusiveRight : m.inclusiveLeft) near = movePos(doc, near, -dir, line);\n
          if (near && near.line == pos.line && (diff = cmp(near, oldPos)) && (dir < 0 ? diff < 0 : diff > 0))\n
            return skipAtomicInner(doc, near, pos, dir, mayClear);\n
        }\n
\n
        var far = m.find(dir < 0 ? -1 : 1);\n
        if (dir < 0 ? m.inclusiveLeft : m.inclusiveRight) far = movePos(doc, far, dir, line);\n
        return far ? skipAtomicInner(doc, far, pos, dir, mayClear) : null;\n
      }\n
    }\n
    return pos;\n
  }\n
\n
  // Ensure a given position is not inside an atomic range.\n
  function skipAtomic(doc, pos, oldPos, bias, mayClear) {\n
    var dir = bias || 1;\n
    var found = skipAtomicInner(doc, pos, oldPos, dir, mayClear) ||\n
        (!mayClear && skipAtomicInner(doc, pos, oldPos, dir, true)) ||\n
        skipAtomicInner(doc, pos, oldPos, -dir, mayClear) ||\n
        (!mayClear && skipAtomicInner(doc, pos, oldPos, -dir, true));\n
    if (!found) {\n
      doc.cantEdit = true;\n
      return Pos(doc.first, 0);\n
    }\n
    return found;\n
  }\n
\n
  function movePos(doc, pos, dir, line) {\n
    if (dir < 0 && pos.ch == 0) {\n
      if (pos.line > doc.first) return clipPos(doc, Pos(pos.line - 1));\n
      else return null;\n
    } else if (dir > 0 && pos.ch == (line || getLine(doc, pos.line)).text.length) {\n
      if (pos.line < doc.first + doc.size - 1) return Pos(pos.line + 1, 0);\n
      else return null;\n
    } else {\n
      return new Pos(pos.line, pos.ch + dir);\n
    }\n
  }\n
\n
  // SELECTION DRAWING\n
\n
  function updateSelection(cm) {\n
    cm.display.input.showSelection(cm.display.input.prepareSelection());\n
  }\n
\n
  function prepareSelection(cm, primary) {\n
    var doc = cm.doc, result = {};\n
    var curFragment = result.cursors = document.createDocumentFragment();\n
    var selFragment = result.selection = document.createDocumentFragment();\n
\n
    for (var i = 0; i < doc.sel.ranges.length; i++) {\n
      if (primary === false && i == doc.sel.primIndex) continue;\n
      var range = doc.sel.ranges[i];\n
      var collapsed = range.empty();\n
      if (collapsed || cm.options.showCursorWhenSelecting)\n
        drawSelectionCursor(cm, range.head, curFragment);\n
      if (!collapsed)\n
        drawSelectionRange(cm, range, selFragment);\n
    }\n
    return result;\n
  }\n
\n
  // Draws a cursor for the given range\n
  function drawSelectionCursor(cm, head, output) {\n
    var pos = cursorCoords(cm, head, "div", null, null, !cm.options.singleCursorHeightPerLine);\n
\n
    var cursor = output.appendChild(elt("div", "\\u00a0", "CodeMirror-cursor"));\n
    cursor.style.left = pos.left + "px";\n
    cursor.style.top = pos.top + "px";\n
    cursor.style.height = Math.max(0, pos.bottom - pos.top) * cm.options.cursorHeight + "px";\n
\n
    if (pos.other) {\n
      // Secondary cursor, shown when on a \'jump\' in bi-directional text\n
      var otherCursor = output.appendChild(elt("div", "\\u00a0", "CodeMirror-cursor CodeMirror-secondarycursor"));\n
      otherCursor.style.display = "";\n
      otherCursor.style.left = pos.other.left + "px";\n
      otherCursor.style.top = pos.other.top + "px";\n
      otherCursor.style.height = (pos.other.bottom - pos.other.top) * .85 + "px";\n
    }\n
  }\n
\n
  // Draws the given range as a highlighted selection\n
  function drawSelectionRange(cm, range, output) {\n
    var display = cm.display, doc = cm.doc;\n
    var fragment = document.createDocumentFragment();\n
    var padding = paddingH(cm.display), leftSide = padding.left;\n
    var rightSide = Math.max(display.sizerWidth, displayWidth(cm) - display.sizer.offsetLeft) - padding.right;\n
\n
    function add(left, top, width, bottom) {\n
      if (top < 0) top = 0;\n
      top = Math.round(top);\n
      bottom = Math.round(bottom);\n
      fragment.appendChild(elt("div", null, "CodeMirror-selected", "position: absolute; left: " + left +\n
                               "px; top: " + top + "px; width: " + (width == null ? rightSide - left : width) +\n
                               "px; height: " + (bottom - top) + "px"));\n
    }\n
\n
    function drawForLine(line, fromArg, toArg) {\n
      var lineObj = getLine(doc, line);\n
      var lineLen = lineObj.text.length;\n
      var start, end;\n
      function coords(ch, bias) {\n
        return charCoords(cm, Pos(line, ch), "div", lineObj, bias);\n
      }\n
\n
      iterateBidiSections(getOrder(lineObj), fromArg || 0, toArg == null ? lineLen : toArg, function(from, to, dir) {\n
        var leftPos = coords(from, "left"), rightPos, left, right;\n
        if (from == to) {\n
          rightPos = leftPos;\n
          left = right = leftPos.left;\n
        } else {\n
          rightPos = coords(to - 1, "right");\n
          if (dir == "rtl") { var tmp = leftPos; leftPos = rightPos; rightPos = tmp; }\n
          left = leftPos.left;\n
          right = rightPos.right;\n
        }\n
        if (fromArg == null && from == 0) left = leftSide;\n
        if (rightPos.top - leftPos.top > 3) { // Different lines, draw top part\n
          add(left, leftPos.top, null, leftPos.bottom);\n
          left = leftSide;\n
          if (leftPos.bottom < rightPos.top) add(left, leftPos.bottom, null, rightPos.top);\n
        }\n
        if (toArg == null && to == lineLen) right = rightSide;\n
        if (!start || leftPos.top < start.top || leftPos.top == start.top && leftPos.left < start.left)\n
          start = leftPos;\n
        if (!end || rightPos.bottom > end.bottom || rightPos.bottom == end.bottom && rightPos.right > end.right)\n
          end = rightPos;\n
        if (left < leftSide + 1) left = leftSide;\n
        add(left, rightPos.top, right - left, rightPos.bottom);\n
      });\n
      return {start: start, end: end};\n
    }\n
\n
    var sFrom = range.from(), sTo = range.to();\n
    if (sFrom.line == sTo.line) {\n
      drawForLine(sFrom.line, sFrom.ch, sTo.ch);\n
    } else {\n
      var fromLine = getLine(doc, sFrom.line), toLine = getLine(doc, sTo.line);\n
      var singleVLine = visualLine(fromLine) == visualLine(toLine);\n
      var leftEnd = drawForLine(sFrom.line, sFrom.ch, singleVLine ? fromLine.text.length + 1 : null).end;\n
      var rightStart = drawForLine(sTo.line, singleVLine ? 0 : null, sTo.ch).start;\n
      if (singleVLine) {\n
        if (leftEnd.top < rightStart.top - 2) {\n
          add(leftEnd.right, leftEnd.top, null, leftEnd.bottom);\n
          add(leftSide, rightStart.top, rightStart.left, rightStart.bottom);\n
        } else {\n
          add(leftEnd.right, leftEnd.top, rightStart.left - leftEnd.right, leftEnd.bottom);\n
        }\n
      }\n
      if (leftEnd.bottom < rightStart.top)\n
        add(leftSide, leftEnd.bottom, null, rightStart.top);\n
    }\n
\n
    output.appendChild(fragment);\n
  }\n
\n
  // Cursor-blinking\n
  function restartBlink(cm) {\n
    if (!cm.state.focused) return;\n
    var display = cm.display;\n
    clearInterval(display.blinker);\n
    var on = true;\n
    display.cursorDiv.style.visibility = "";\n
    if (cm.options.cursorBlinkRate > 0)\n
      display.blinker = setInterval(function() {\n
        display.cursorDiv.style.visibility = (on = !on) ? "" : "hidden";\n
      }, cm.options.cursorBlinkRate);\n
    else if (cm.options.cursorBlinkRate < 0)\n
      display.cursorDiv.style.visibility = "hidden";\n
  }\n
\n
  // HIGHLIGHT WORKER\n
\n
  function startWorker(cm, time) {\n
    if (cm.doc.mode.startState && cm.doc.frontier < cm.display.viewTo)\n
      cm.state.highlight.set(time, bind(highlightWorker, cm));\n
  }\n
\n
  function highlightWorker(cm) {\n
    var doc = cm.doc;\n
    if (doc.frontier < doc.first) doc.frontier = doc.first;\n
    if (doc.frontier >= cm.display.viewTo) return;\n
    var end = +new Date + cm.options.workTime;\n
    var state = copyState(doc.mode, getStateBefore(cm, doc.frontier));\n
    var changedLines = [];\n
\n
    doc.iter(doc.frontier, Math.min(doc.first + doc.size, cm.display.viewTo + 500), function(line) {\n
      if (doc.frontier >= cm.display.viewFrom) { // Visible\n
        var oldStyles = line.styles, tooLong = line.text.length > cm.options.maxHighlightLength;\n
        var highlighted = highlightLine(cm, line, tooLong ? copyState(doc.mode, state) : state, true);\n
        line.styles = highlighted.styles;\n
        var oldCls = line.styleClasses, newCls = highlighted.classes;\n
        if (newCls) line.styleClasses = newCls;\n
        else if (oldCls) line.styleClasses = null;\n
        var ischange = !oldStyles || oldStyles.length != line.styles.length ||\n
          oldCls != newCls && (!oldCls || !newCls || oldCls.bgClass != newCls.bgClass || oldCls.textClass != newCls.textClass);\n
        for (var i = 0; !ischange && i < oldStyles.length; ++i) ischange = oldStyles[i] != line.styles[i];\n
        if (ischange) changedLines.push(doc.frontier);\n
        line.stateAfter = tooLong ? state : copyState(doc.mode, state);\n
      } else {\n
        if (line.text.length <= cm.options.maxHighlightLength)\n
          processLine(cm, line.text, state);\n
        line.stateAfter = doc.frontier % 5 == 0 ? copyState(doc.mode, state) : null;\n
      }\n
      ++doc.frontier;\n
      if (+new Date > end) {\n
        startWorker(cm, cm.options.workDelay);\n
        return true;\n
      }\n
    });\n
    if (changedLines.length) runInOp(cm, function() {\n
      for (var i = 0; i < changedLines.length; i++)\n
        regLineChange(cm, changedLines[i], "text");\n
    });\n
  }\n
\n
  // Finds the line to start with when starting a parse. Tries to\n
  // find a line with a stateAfter, so that it can start with a\n
  // valid state. If that fails, it returns the line with the\n
  // smallest indentation, which tends to need the least context to\n
  // parse correctly.\n
  function findStartLine(cm, n, precise) {\n
    var minindent, minline, doc = cm.doc;\n
    var lim = precise ? -1 : n - (cm.doc.mode.innerMode ? 1000 : 100);\n
    for (var search = n; search > lim; --search) {\n
      if (search <= doc.first) return doc.first;\n
      var line = getLine(doc, search - 1);\n
      if (line.stateAfter && (!precise || search <= doc.frontier)) return search;\n
      var indented = countColumn(line.text, null, cm.options.tabSize);\n
      if (minline == null || minindent > indented) {\n
        minline = search - 1;\n
        minindent = indented;\n
      }\n
    }\n
    return minline;\n
  }\n
\n
  function getStateBefore(cm, n, precise) {\n
    var doc = cm.doc, display = cm.display;\n
    if (!doc.mode.startState) return true;\n
    var pos = findStartLine(cm, n, precise), state = pos > doc.first && getLine(doc, pos-1).stateAfter;\n
    if (!state) state = startState(doc.mode);\n
    else state = copyState(doc.mode, state);\n
    doc.iter(pos, n, function(line) {\n
      processLine(cm, line.text, state);\n
      var save = pos == n - 1 || pos % 5 == 0 || pos >= display.viewFrom && pos < display.viewTo;\n
      line.stateAfter = save ? copyState(doc.mode, state) : null;\n
      ++pos;\n
    });\n
    if (precise) doc.frontier = pos;\n
    return state;\n
  }\n
\n
  // POSITION MEASUREMENT\n
\n
  function paddingTop(display) {return display.lineSpace.offsetTop;}\n
  function paddingVert(display) {return display.mover.offsetHeight - display.lineSpace.offsetHeight;}\n
  function paddingH(display) {\n
    if (display.cachedPaddingH) return display.cachedPaddingH;\n
    var e = removeChildrenAndAdd(display.measure, elt("pre", "x"));\n
    var style = window.getComputedStyle ? window.getComputedStyle(e) : e.currentStyle;\n
    var data = {left: parseInt(style.paddingLeft), right: parseInt(style.paddingRight)};\n
    if (!isNaN(data.left) && !isNaN(data.right)) display.cachedPaddingH = data;\n
    return data;\n
  }\n
\n
  function scrollGap(cm) { return scrollerGap - cm.display.nativeBarWidth; }\n
  function displayWidth(cm) {\n
    return cm.display.scroller.clientWidth - scrollGap(cm) - cm.display.barWidth;\n
  }\n
  function displayHeight(cm) {\n
    return cm.display.scroller.clientHeight - scrollGap(cm) - cm.display.barHeight;\n
  }\n
\n
  // Ensure the lineView.wrapping.heights array is populated. This is\n
  // an array of bottom offsets for the lines that make up a drawn\n
  // line. When lineWrapping is on, there might be more than one\n
  // height.\n
  function ensureLineHeights(cm, lineView, rect) {\n
    var wrapping = cm.options.lineWrapping;\n
    var curWidth = wrapping && displayWidth(cm);\n
    if (!lineView.measure.heights || wrapping && lineView.measure.width != curWidth) {\n
      var heights = lineView.measure.heights = [];\n
      if (wrapping) {\n
        lineView.measure.width = curWidth;\n
        var rects = lineView.text.firstChild.getClientRects();\n
        for (var i = 0; i < rects.length - 1; i++) {\n
          var cur = rects[i], next = rects[i + 1];\n
          if (Math.abs(cur.bottom - next.bottom) > 2)\n
            heights.push((cur.bottom + next.top) / 2 - rect.top);\n
        }\n
      }\n
      heights.push(rect.bottom - rect.top);\n
    }\n
  }\n
\n
  // Find a line map (mapping character offsets to text nodes) and a\n
  // measurement cache for the given line number. (A line view might\n
  // contain multiple lines when collapsed ranges are present.)\n
  function mapFromLineView(lineView, line, lineN) {\n
    if (lineView.line == line)\n
      return {map: lineView.measure.map, cache: lineView.measure.cache};\n
    for (var i = 0; i < lineView.rest.length; i++)\n
      if (lineView.rest[i] == line)\n
        return {map: lineView.measure.maps[i], cache: lineView.measure.caches[i]};\n
    for (var i = 0; i < lineView.rest.length; i++)\n
      if (lineNo(lineView.rest[i]) > lineN)\n
        return {map: lineView.measure.maps[i], cache: lineView.measure.caches[i], before: true};\n
  }\n
\n
  // Render a line into the hidden node display.externalMeasured. Used\n
  // when measurement is needed for a line that\'s not in the viewport.\n
  function updateExternalMeasurement(cm, line) {\n
    line = visualLine(line);\n
    var lineN = lineNo(line);\n
    var view = cm.display.externalMeasured = new LineView(cm.doc, line, lineN);\n
    view.lineN = lineN;\n
    var built = view.built = buildLineContent(cm, view);\n
    view.text = built.pre;\n
    removeChildrenAndAdd(cm.display.lineMeasure, built.pre);\n
    return view;\n
  }\n
\n
  // Get a {top, bottom, left, right} box (in line-local coordinates)\n
  // for a given character.\n
  function measureChar(cm, line, ch, bias) {\n
    return measureCharPrepared(cm, prepareMeasureForLine(cm, line), ch, bias);\n
  }\n
\n
  // Find a line view that corresponds to the given line number.\n
  function findViewForLine(cm, lineN) {\n
    if (lineN >= cm.display.viewFrom && lineN < cm.display.viewTo)\n
      return cm.display.view[findViewIndex(cm, lineN)];\n
    var ext = cm.display.externalMeasured;\n
    if (ext && lineN >= ext.lineN && lineN < ext.lineN + ext.size)\n
      return ext;\n
  }\n
\n
  // Measurement can be split in two steps, the set-up work that\n
  // applies to the whole line, and the measurement of the actual\n
  // character. Functions like coordsChar, that need to do a lot of\n
  // measurements in a row, can thus ensure that the set-up work is\n
  // only done once.\n
  function prepareMeasureForLine(cm, line) {\n
    var lineN = lineNo(line);\n
    var view = findViewForLine(cm, lineN);\n
    if (view && !view.text) {\n
      view = null;\n
    } else if (view && view.changes) {\n
      updateLineForChanges(cm, view, lineN, getDimensions(cm));\n
      cm.curOp.forceUpdate = true;\n
    }\n
    if (!view)\n
      view = updateExternalMeasurement(cm, line);\n
\n
    var info = mapFromLineView(view, line, lineN);\n
    return {\n
      line: line, view: view, rect: null,\n
      map: info.map, cache: info.cache, before: info.before,\n
      hasHeights: false\n
    };\n
  }\n
\n
  // Given a prepared measurement object, measures the position of an\n
  // actual character (or fetches it from the cache).\n
  function measureCharPrepared(cm, prepared, ch, bias, varHeight) {\n
    if (prepared.before) ch = -1;\n
    var key = ch + (bias || ""), found;\n
    if (prepared.cache.hasOwnProperty(key)) {\n
      found = prepared.cache[key];\n
    } else {\n
      if (!prepared.rect)\n
        prepared.rect = prepared.view.text.getBoundingClientRect();\n
      if (!prepared.hasHeights) {\n
        ensureLineHeights(cm, prepared.view, prepared.rect);\n
        prepared.hasHeights = true;\n
      }\n
      found = measureCharInner(cm, prepared, ch, bias);\n
      if (!found.bogus) prepared.cache[key] = found;\n
    }\n
    return {left: found.left, right: found.right,\n
            top: varHeight ? found.rtop : found.top,\n
            bottom: varHeight ? found.rbottom : found.bottom};\n
  }\n
\n
  var nullRect = {left: 0, right: 0, top: 0, bottom: 0};\n
\n
  function nodeAndOffsetInLineMap(map, ch, bias) {\n
    var node, start, end, collapse;\n
    // First, search the line map for the text node corresponding to,\n
    // or closest to, the target character.\n
    for (var i = 0; i < map.length; i += 3) {\n
      var mStart = map[i], mEnd = map[i + 1];\n
      if (ch < mStart) {\n
        start = 0; end = 1;\n
        collapse = "left";\n
      } else if (ch < mEnd) {\n
        start = ch - mStart;\n
        end = start + 1;\n
      } else if (i == map.length - 3 || ch == mEnd && map[i + 3] > ch) {\n
        end = mEnd - mStart;\n
        start = end - 1;\n
        if (ch >= mEnd) collapse = "right";\n
      }\n
      if (start != null) {\n
        node = map[i + 2];\n
        if (mStart == mEnd && bias == (node.insertLeft ? "left" : "right"))\n
          collapse = bias;\n
        if (bias == "left" && start == 0)\n
          while (i && map[i - 2] == map[i - 3] && map[i - 1].insertLeft) {\n
            node = map[(i -= 3) + 2];\n
            collapse = "left";\n
          }\n
        if (bias == "right" && start == mEnd - mStart)\n
          while (i < map.length - 3 && map[i + 3] == map[i + 4] && !map[i + 5].insertLeft) {\n
            node = map[(i += 3) + 2];\n
            collapse = "right";\n
          }\n
        break;\n
      }\n
    }\n
    return {node: node, start: start, end: end, collapse: collapse, coverStart: mStart, coverEnd: mEnd};\n
  }\n
\n
  function measureCharInner(cm, prepared, ch, bias) {\n
    var place = nodeAndOffsetInLineMap(prepared.map, ch, bias);\n
    var node = place.node, start = place.start, end = place.end, collapse = place.collapse;\n
\n
    var rect;\n
    if (node.nodeType == 3) { // If it is a text node, use a range to retrieve the coordinates.\n
      for (var i = 0; i < 4; i++) { // Retry a maximum of 4 times when nonsense rectangles are returned\n
        while (start && isExtendingChar(prepared.line.text.charAt(place.coverStart + start))) --start;\n
        while (place.coverStart + end < place.coverEnd && isExtendingChar(prepared.line.text.charAt(place.coverStart + end))) ++end;\n
        if (ie && ie_version < 9 && start == 0 && end == place.coverEnd - place.coverStart) {\n
          rect = node.parentNode.getBoundingClientRect();\n
        } else if (ie && cm.options.lineWrapping) {\n
          var rects = range(node, start, end).getClientRects();\n
          if (rects.length)\n
            rect = rects[bias == "right" ? rects.length - 1 : 0];\n
          else\n
            rect = nullRect;\n
        } else {\n
          rect = range(node, start, end).getBoundingClientRect() || nullRect;\n
        }\n
        if (rect.left || rect.right || start == 0) break;\n
        end = start;\n
        start = start - 1;\n
        collapse = "right";\n
      }\n
      if (ie && ie_version < 11) rect = maybeUpdateRectForZooming(cm.display.measure, rect);\n
    } else { // If it is a widget, simply get the box for the whole widget.\n
      if (start > 0) collapse = bias = "right";\n
      var rects;\n
      if (cm.options.lineWrapping && (rects = node.getClientRects()).length > 1)\n
        rect = rects[bias == "right" ? rects.length - 1 : 0];\n
      else\n
        rect = node.getBoundingClientRect();\n
    }\n
    if (ie && ie_version < 9 && !start && (!rect || !rect.left && !rect.right)) {\n
      var rSpan = node.parentNode.getClientRects()[0];\n
      if (rSpan)\n
        rect = {left: rSpan.left, right: rSpan.left + charWidth(cm.display), top: rSpan.top, bottom: rSpan.bottom};\n
      else\n
        rect = nullRect;\n
    }\n
\n
    var rtop = rect.top - prepared.rect.top, rbot = rect.bottom - prepared.rect.top;\n
    var mid = (rtop + rbot) / 2;\n
    var heights = prepared.view.measure.heights;\n
    for (var i = 0; i < heights.length - 1; i++)\n
      if (mid < heights[i]) break;\n
    var top = i ? heights[i - 1] : 0, bot = heights[i];\n
    var result = {left: (collapse == "right" ? rect.right : rect.left) - prepared.rect.left,\n
                  right: (collapse == "left" ? rect.left : rect.right) - prepared.rect.left,\n
                  top: top, bottom: bot};\n
    if (!rect.left && !rect.right) result.bogus = true;\n
    if (!cm.options.singleCursorHeightPerLine) { result.rtop = rtop; result.rbottom = rbot; }\n
\n
    return result;\n
  }\n
\n
  // Work around problem with bounding client rects on ranges being\n
  // returned incorrectly when zoomed on IE10 and below.\n
  function maybeUpdateRectForZooming(measure, rect) {\n
    if (!window.screen || screen.logicalXDPI == null ||\n
        screen.logicalXDPI == screen.deviceXDPI || !hasBadZoomedRects(measure))\n
      return rect;\n
    var scaleX = screen.logicalXDPI / screen.deviceXDPI;\n
    var scaleY = screen.logicalYDPI / screen.deviceYDPI;\n
    return {left: rect.left * scaleX, right: rect.right * scaleX,\n
            top: rect.top * scaleY, bottom: rect.bottom * scaleY};\n
  }\n
\n
  function clearLineMeasurementCacheFor(lineView) {\n
    if (lineView.measure) {\n
      lineView.measure.cache = {};\n
      lineView.measure.heights = null;\n
      if (lineView.rest) for (var i = 0; i < lineView.rest.length; i++)\n
        lineView.measure.caches[i] = {};\n
    }\n
  }\n
\n
  function clearLineMeasurementCache(cm) {\n
    cm.display.externalMeasure = null;\n
    removeChildren(cm.display.lineMeasure);\n
    for (var i = 0; i < cm.display.view.length; i++)\n
      clearLineMeasurementCacheFor(cm.display.view[i]);\n
  }\n
\n
  function clearCaches(cm) {\n
    clearLineMeasurementCache(cm);\n
    cm.display.cachedCharWidth = cm.display.cachedTextHeight = cm.display.cachedPaddingH = null;\n
    if (!cm.options.lineWrapping) cm.display.maxLineChanged = true;\n
    cm.display.lineNumChars = null;\n
  }\n
\n
  function pageScrollX() { return window.pageXOffset || (document.documentElement || document.body).scrollLeft; }\n
  function pageScrollY() { return window.pageYOffset || (document.documentElement || document.body).scrollTop; }\n
\n
  // Converts a {top, bottom, left, right} box from line-local\n
  // coordinates into another coordinate system. Context may be one of\n
  // "line", "div" (display.lineDiv), "local"/null (editor), "window",\n
  // or "page".\n
  function intoCoordSystem(cm, lineObj, rect, context) {\n
    if (lineObj.widgets) for (var i = 0; i < lineObj.widgets.length; ++i) if (lineObj.widgets[i].above) {\n
      var size = widgetHeight(lineObj.widgets[i]);\n
      rect.top += size; rect.bottom += size;\n
    }\n
    if (context == "line") return rect;\n
    if (!context) context = "local";\n
    var yOff = heightAtLine(lineObj);\n
    if (context == "local") yOff += paddingTop(cm.display);\n
    else yOff -= cm.display.viewOffset;\n
    if (context == "page" || context == "window") {\n
      var lOff = cm.display.lineSpace.getBoundingClientRect();\n
      yOff += lOff.top + (context == "window" ? 0 : pageScrollY());\n
      var xOff = lOff.left + (context == "window" ? 0 : pageScrollX());\n
      rect.left += xOff; rect.right += xOff;\n
    }\n
    rect.top += yOff; rect.bottom += yOff;\n
    return rect;\n
  }\n
\n
  // Coverts a box from "div" coords to another coordinate system.\n
  // Context may be "window", "page", "div", or "local"/null.\n
  function fromCoordSystem(cm, coords, context) {\n
    if (context == "div") return coords;\n
    var left = coords.left, top = coords.top;\n
    // First move into "page" coordinate system\n
    if (context == "page") {\n
      left -= pageScrollX();\n
      top -= pageScrollY();\n
    } else if (context == "local" || !context) {\n
      var localBox = cm.display.sizer.getBoundingClientRect();\n
      left += localBox.left;\n
      top += localBox.top;\n
    }\n
\n
    var lineSpaceBox = cm.display.lineSpace.getBoundingClientRect();\n
    return {left: left - lineSpaceBox.left, top: top - lineSpaceBox.top};\n
  }\n
\n
  function charCoords(cm, pos, context, lineObj, bias) {\n
    if (!lineObj) lineObj = getLine(cm.doc, pos.line);\n
    return intoCoordSystem(cm, lineObj, measureChar(cm, lineObj, pos.ch, bias), context);\n
  }\n
\n
  // Returns a box for a given cursor position, which may have an\n
  // \'other\' property containing the position of the secondary cursor\n
  // on a bidi boundary.\n
  function cursorCoords(cm, pos, context, lineObj, preparedMeasure, varHeight) {\n
    lineObj = lineObj || getLine(cm.doc, pos.line);\n
    if (!preparedMeasure) preparedMeasure = prepareMeasureForLine(cm, lineObj);\n
    function get(ch, right) {\n
      var m = measureCharPrepared(cm, preparedMeasure, ch, right ? "right" : "left", varHeight);\n
      if (right) m.left = m.right; else m.right = m.left;\n
      return intoCoordSystem(cm, lineObj, m, context);\n
    }\n
    function getBidi(ch, partPos) {\n
      var part = order[partPos], right = part.level % 2;\n
      if (ch == bidiLeft(part) && partPos && part.level < order[partPos - 1].level) {\n
        part = order[--partPos];\n
        ch = bidiRight(part) - (part.level % 2 ? 0 : 1);\n
        right = true;\n
      } else if (ch == bidiRight(part) && partPos < order.length - 1 && part.level < order[partPos + 1].level) {\n
        part = order[++partPos];\n
        ch = bidiLeft(part) - part.level % 2;\n
        right = false;\n
      }\n
      if (right && ch == part.to && ch > part.from) return get(ch - 1);\n
      return get(ch, right);\n
    }\n
    var order = getOrder(lineObj), ch = pos.ch;\n
    if (!order) return get(ch);\n
    var partPos = getBidiPartAt(order, ch);\n
    var val = getBidi(ch, partPos);\n
    if (bidiOther != null) val.other = getBidi(ch, bidiOther);\n
    return val;\n
  }\n
\n
  // Used to cheaply estimate the coordinates for a position. Used for\n
  // intermediate scroll updates.\n
  function estimateCoords(cm, pos) {\n
    var left = 0, pos = clipPos(cm.doc, pos);\n
    if (!cm.options.lineWrapping) left = charWidth(cm.display) * pos.ch;\n
    var lineObj = getLine(cm.doc, pos.line);\n
    var top = heightAtLine(lineObj) + paddingTop(cm.display);\n
    return {left: left, right: left, top: top, bottom: top + lineObj.height};\n
  }\n
\n
  // Positions returned by coordsChar contain some extra information.\n
  // xRel is the relative x position of the input coordinates compared\n
  // to the found position (so xRel > 0 means the coordinates are to\n
  // the right of the character position, for example). When outside\n
  // is true, that means the coordinates lie outside the line\'s\n
  // vertical range.\n
  function PosWithInfo(line, ch, outside, xRel) {\n
    var pos = Pos(line, ch);\n
    pos.xRel = xRel;\n
    if (outside) pos.outside = true;\n
    return pos;\n
  }\n
\n
  // Compute the character position closest to the given coordinates.\n
  // Input must be lineSpace-local ("div" coordinate system).\n
  function coordsChar(cm, x, y) {\n
    var doc = cm.doc;\n
    y += cm.display.viewOffset;\n
    if (y < 0) return PosWithInfo(doc.first, 0, true, -1);\n
    var lineN = lineAtHeight(doc, y), last = doc.first + doc.size - 1;\n
    if (lineN > last)\n
      return PosWithInfo(doc.first + doc.size - 1, getLine(doc, last).text.length, true, 1);\n
    if (x < 0) x = 0;\n
\n
    var lineObj = getLine(doc, lineN);\n
    for (;;) {\n
      var found = coordsCharInner(cm, lineObj, lineN, x, y);\n
      var merged = collapsedSpanAtEnd(lineObj);\n
      var mergedPos = merged && merged.find(0, true);\n
      if (merged && (found.ch > mergedPos.from.ch || found.ch == mergedPos.from.ch && found.xRel > 0))\n
        lineN = lineNo(lineObj = mergedPos.to.line);\n
      else\n
        return found;\n
    }\n
  }\n
\n
  function coordsCharInner(cm, lineObj, lineNo, x, y) {\n
    var innerOff = y - heightAtLine(lineObj);\n
    var wrongLine = false, adjust = 2 * cm.display.wrapper.clientWidth;\n
    var preparedMeasure = prepareMeasureForLine(cm, lineObj);\n
\n
    function getX(ch) {\n
      var sp = cursorCoords(cm, Pos(lineNo, ch), "line", lineObj, preparedMeasure);\n
      wrongLine = true;\n
      if (innerOff > sp.bottom) return sp.left - adjust;\n
      else if (innerOff < sp.top) return sp.left + adjust;\n
      else wrongLine = false;\n
      return sp.left;\n
    }\n
\n
    var bidi = getOrder(lineObj), dist = lineObj.text.length;\n
    var from = lineLeft(lineObj), to = lineRight(lineObj);\n
    var fromX = getX(from), fromOutside = wrongLine, toX = getX(to), toOutside = wrongLine;\n
\n
    if (x > toX) return PosWithInfo(lineNo, to, toOutside, 1);\n
    // Do a binary search between these bounds.\n
    for (;;) {\n
      if (bidi ? to == from || to == moveVisually(lineObj, from, 1) : to - from <= 1) {\n
        var ch = x < fromX || x - fromX <= toX - x ? from : to;\n
        var xDiff = x - (ch == from ? fromX : toX);\n
        while (isExtendingChar(lineObj.text.charAt(ch))) ++ch;\n
        var pos = PosWithInfo(lineNo, ch, ch == from ? fromOutside : toOutside,\n
                              xDiff < -1 ? -1 : xDiff > 1 ? 1 : 0);\n
        return pos;\n
      }\n
      var step = Math.ceil(dist / 2), middle = from + step;\n
      if (bidi) {\n
        middle = from;\n
        for (var i = 0; i < step; ++i) middle = moveVisually(lineObj, middle, 1);\n
      }\n
      var middleX = getX(middle);\n
      if (middleX > x) {to = middle; toX = middleX; if (toOutside = wrongLine) toX += 1000; dist = step;}\n
      else {from = middle; fromX = middleX; fromOutside = wrongLine; dist -= step;}\n
    }\n
  }\n
\n
  var measureText;\n
  // Compute the default text height.\n
  function textHeight(display) {\n
    if (display.cachedTextHeight != null) return display.cachedTextHeight;\n
    if (measureText == null) {\n
      measureText = elt("pre");\n
      // Measure a bunch of lines, for browsers that compute\n
      // fractional heights.\n
      for (var i = 0; i < 49; ++i) {\n
        measureText.appendChild(document.createTextNode("x"));\n
        measureText.appendChild(elt("br"));\n
      }\n
      measureText.appendChild(document.createTextNode("x"));\n
    }\n
    removeChildrenAndAdd(display.measure, measureText);\n
    var height = measureText.offsetHeight / 50;\n
    if (height > 3) display.cachedTextHeight = height;\n
    removeChildren(display.measure);\n
    return height || 1;\n
  }\n
\n
  // Compute the default character width.\n
  function charWidth(display) {\n
    if (display.cachedCharWidth != null) return display.cachedCharWidth;\n
    var anchor = elt("span", "xxxxxxxxxx");\n
    var pre = elt("pre", [anchor]);\n
    removeChildrenAndAdd(display.measure, pre);\n
    var rect = anchor.getBoundingClientRect(), width = (rect.right - rect.left) / 10;\n
    if (width > 2) display.cachedCharWidth = width;\n
    return width || 10;\n
  }\n
\n
  // OPERATIONS\n
\n
  // Operations are used to wrap a series of changes to the editor\n
  // state in such a way that each change won\'t have to update the\n
  // cursor and display (which would be awkward, slow, and\n
  // error-prone). Instead, display updates are batched and then all\n
  // combined and executed at once.\n
\n
  var operationGroup = null;\n
\n
  var nextOpId = 0;\n
  // Start a new operation.\n
  function startOperation(cm) {\n
    cm.curOp = {\n
      cm: cm,\n
      viewChanged: false,      // Flag that indicates that lines might need to be redrawn\n
      startHeight: cm.doc.height, // Used to detect need to update scrollbar\n
      forceUpdate: false,      // Used to force a redraw\n
      updateInput: null,       // Whether to reset the input textarea\n
      typing: false,           // Whether this reset should be careful to leave existing text (for compositing)\n
      changeObjs: null,        // Accumulated changes, for firing change events\n
      cursorActivityHandlers: null, // Set of handlers to fire cursorActivity on\n
      cursorActivityCalled: 0, // Tracks which cursorActivity handlers have been called already\n
      selectionChanged: false, // Whether the selection needs to be redrawn\n
      updateMaxLine: false,    // Set when the widest line needs to be determined anew\n
      scrollLeft: null, scrollTop: null, // Intermediate scroll position, not pushed to DOM yet\n
      scrollToPos: null,       // Used to scroll to a specific position\n
      focus: false,\n
      id: ++nextOpId           // Unique ID\n
    };\n
    if (operationGroup) {\n
      operationGroup.ops.push(cm.curOp);\n
    } else {\n
      cm.curOp.ownsGroup = operationGroup = {\n
        ops: [cm.curOp],\n
        delayedCallbacks: []\n
      };\n
    }\n
  }\n
\n
  function fireCallbacksForOps(group) {\n
    // Calls delayed callbacks and cursorActivity handlers until no\n
    // new ones appear\n
    var callbacks = group.delayedCallbacks, i = 0;\n
    do {\n
      for (; i < callbacks.length; i++)\n
        callbacks[i].call(null);\n
      for (var j = 0; j < group.ops.length; j++) {\n
        var op = group.ops[j];\n
        if (op.cursorActivityHandlers)\n
          while (op.cursorActivityCalled < op.cursorActivityHandlers.length)\n
            op.cursorActivityHandlers[op.cursorActivityCalled++].call(null, op.cm);\n
      }\n
    } while (i < callbacks.length);\n
  }\n
\n
  // Finish an operation, updating the display and signalling delayed events\n
  function endOperation(cm) {\n
    var op = cm.curOp, group = op.ownsGroup;\n
    if (!group) return;\n
\n
    try { fireCallbacksForOps(group); }\n
    finally {\n
      operationGroup = null;\n
      for (var i = 0; i < group.ops.length; i++)\n
        group.ops[i].cm.curOp = null;\n
      endOperations(group);\n
    }\n
  }\n
\n
  // The DOM updates done when an operation finishes are batched so\n
  // that the minimum number of relayouts are required.\n
  function endOperations(group) {\n
    var ops = group.ops;\n
    for (var i = 0; i < ops.length; i++) // Read DOM\n
      endOperation_R1(ops[i]);\n
    for (var i = 0; i < ops.length; i++) // Write DOM (maybe)\n
      endOperation_W1(ops[i]);\n
    for (var i = 0; i < ops.length; i++) // Read DOM\n
      endOperation_R2(ops[i]);\n
    for (var i = 0; i < ops.length; i++) // Write DOM (maybe)\n
      endOperation_W2(ops[i]);\n
    for (var i = 0; i < ops.length; i++) // Read DOM\n
      endOperation_finish(ops[i]);\n
  }\n
\n
  function endOperation_R1(op) {\n
    var cm = op.cm, display = cm.display;\n
    maybeClipScrollbars(cm);\n
    if (op.updateMaxLine) findMaxLine(cm);\n
\n
    op.mustUpdate = op.viewChanged || op.forceUpdate || op.scrollTop != null ||\n
      op.scrollToPos && (op.scrollToPos.from.line < display.viewFrom ||\n
                         op.scrollToPos.to.line >= display.viewTo) ||\n
      display.maxLineChanged && cm.options.lineWrapping;\n
    op.update = op.mustUpdate &&\n
      new DisplayUpdate(cm, op.mustUpdate && {top: op.scrollTop, ensure: op.scrollToPos}, op.forceUpdate);\n
  }\n
\n
  function endOperation_W1(op) {\n
    op.updatedDisplay = op.mustUpdate && updateDisplayIfNeeded(op.cm, op.update);\n
  }\n
\n
  function endOperation_R2(op) {\n
    var cm = op.cm, display = cm.display;\n
    if (op.updatedDisplay) updateHeightsInViewport(cm);\n
\n
    op.barMeasure = measureForScrollbars(cm);\n
\n
    // If the max line changed since it was last measured, measure it,\n
    // and ensure the document\'s width matches it.\n
    // updateDisplay_W2 will use these properties to do the actual resizing\n
    if (display.maxLineChanged && !cm.options.lineWrapping) {\n
      op.adjustWidthTo = measureChar(cm, display.maxLine, display.maxLine.text.length).left + 3;\n
      cm.display.sizerWidth = op.adjustWidthTo;\n
      op.barMeasure.scrollWidth =\n
        Math.max(display.scroller.clientWidth, display.sizer.offsetLeft + op.adjustWidthTo + scrollGap(cm) + cm.display.barWidth);\n
      op.maxScrollLeft = Math.max(0, display.sizer.offsetLeft + op.adjustWidthTo - displayWidth(cm));\n
    }\n
\n
    if (op.updatedDisplay || op.selectionChanged)\n
      op.preparedSelection = display.input.prepareSelection();\n
  }\n
\n
  function endOperation_W2(op) {\n
    var cm = op.cm;\n
\n
    if (op.adjustWidthTo != null) {\n
      cm.display.sizer.style.minWidth = op.adjustWidthTo + "px";\n
      if (op.maxScrollLeft < cm.doc.scrollLeft)\n
        setScrollLeft(cm, Math.min(cm.display.scroller.scrollLeft, op.maxScrollLeft), true);\n
      cm.display.maxLineChanged = false;\n
    }\n
\n
    if (op.preparedSelection)\n
      cm.display.input.showSelection(op.preparedSelection);\n
    if (op.updatedDisplay)\n
      setDocumentHeight(cm, op.barMeasure);\n
    if (op.updatedDisplay || op.startHeight != cm.doc.height)\n
      updateScrollbars(cm, op.barMeasure);\n
\n
    if (op.selectionChanged) restartBlink(cm);\n
\n
    if (cm.state.focused && op.updateInput)\n
      cm.display.input.reset(op.typing);\n
    if (op.focus && op.focus == activeElt() && (!document.hasFocus || document.hasFocus()))\n
      ensureFocus(op.cm);\n
  }\n
\n
  function endOperation_finish(op) {\n
    var cm = op.cm, display = cm.display, doc = cm.doc;\n
\n
    if (op.updatedDisplay) postUpdateDisplay(cm, op.update);\n
\n
    // Abort mouse wheel delta measurement, when scrolling explicitly\n
    if (display.wheelStartX != null && (op.scrollTop != null || op.scrollLeft != null || op.scrollToPos))\n
      display.wheelStartX = display.wheelStartY = null;\n
\n
    // Propagate the scroll position to the actual DOM scroller\n
    if (op.scrollTop != null && (display.scroller.scrollTop != op.scrollTop || op.forceScroll)) {\n
      doc.scrollTop = Math.max(0, Math.min(display.scroller.scrollHeight - display.scroller.clientHeight, op.scrollTop));\n
      display.scrollbars.setScrollTop(doc.scrollTop);\n
      display.scroller.scrollTop = doc.scrollTop;\n
    }\n
    if (op.scrollLeft != null && (display.scroller.scrollLeft != op.scrollLeft || op.forceScroll)) {\n
      doc.scrollLeft = Math.max(0, Math.min(display.scroller.scrollWidth - displayWidth(cm), op.scrollLeft));\n
      display.scrollbars.setScrollLeft(doc.scrollLeft);\n
      display.scroller.scrollLeft = doc.scrollLeft;\n
      alignHorizontally(cm);\n
    }\n
    // If we need to scroll a specific position into view, do so.\n
    if (op.scrollToPos) {\n
      var coords = scrollPosIntoView(cm, clipPos(doc, op.scrollToPos.from),\n
                                     clipPos(doc, op.scrollToPos.to), op.scrollToPos.margin);\n
      if (op.scrollToPos.isCursor && cm.state.focused) maybeScrollWindow(cm, coords);\n
    }\n
\n
    // Fire events for markers that are hidden/unidden by editing or\n
    // undoing\n
    var hidden = op.maybeHiddenMarkers, unhidden = op.maybeUnhiddenMarkers;\n
    if (hidden) for (var i = 0; i < hidden.length; ++i)\n
      if (!hidden[i].lines.length) signal(hidden[i], "hide");\n
    if (unhidden) for (var i = 0; i < unhidden.length; ++i)\n
      if (unhidden[i].lines.length) signal(unhidden[i], "unhide");\n
\n
    if (display.wrapper.offsetHeight)\n
      doc.scrollTop = cm.display.scroller.scrollTop;\n
\n
    // Fire change events, and delayed event handlers\n
    if (op.changeObjs)\n
      signal(cm, "changes", cm, op.changeObjs);\n
    if (op.update)\n
      op.update.finish();\n
  }\n
\n
  // Run the given function in an operation\n
  function runInOp(cm, f) {\n
    if (cm.curOp) return f();\n
    startOperation(cm);\n
    try { return f(); }\n
    finally { endOperation(cm); }\n
  }\n
  // Wraps a function in an operation. Returns the wrapped function.\n
  function operation(cm, f) {\n
    return function() {\n
      if (cm.curOp) return f.apply(cm, arguments);\n
      startOperation(cm);\n
      try { return f.apply(cm, arguments); }\n
      finally { endOperation(cm); }\n
    };\n
  }\n
  // Used to add methods to editor and doc instances, wrapping them in\n
  // operations.\n
  function methodOp(f) {\n
    return function() {\n
      if (this.curOp) return f.apply(this, arguments);\n
      startOperation(this);\n
      try { return f.apply(this, arguments); }\n
      finally { endOperation(this); }\n
    };\n
  }\n
  function docMethodOp(f) {\n
    return function() {\n
      var cm = this.cm;\n
      if (!cm || cm.curOp) return f.apply(this, arguments);\n
      startOperation(cm);\n
      try { return f.apply(this, arguments); }\n
      finally { endOperation(cm); }\n
    };\n
  }\n
\n
  // VIEW TRACKING\n
\n
  // These objects are used to represent the visible (currently drawn)\n
  // part of the document. A LineView may correspond to multiple\n
  // logical lines, if those are connected by collapsed ranges.\n
  function LineView(doc, line, lineN) {\n
    // The starting line\n
    this.line = line;\n
    // Continuing lines, if any\n
    this.rest = visualLineContinued(line);\n
    // Number of logical lines in this visual line\n
    this.size = this.rest ? lineNo(lst(this.rest)) - lineN + 1 : 1;\n
    this.node = this.text = null;\n
    this.hidden = lineIsHidden(doc, line);\n
  }\n
\n
  // Create a range of LineView objects for the given lines.\n
  function buildViewArray(cm, from, to) {\n
    var array = [], nextPos;\n
    for (var pos = from; pos < to; pos = nextPos) {\n
      var view = new LineView(cm.doc, getLine(cm.doc, pos), pos);\n
      nextPos = pos + view.size;\n
      array.push(view);\n
    }\n
    return array;\n
  }\n
\n
  // Updates the display.view data structure for a given change to the\n
  // document. From and to are in pre-change coordinates. Lendiff is\n
  // the amount of lines added or subtracted by the change. This is\n
  // used for changes that span multiple lines, or change the way\n
  // lines are divided into visual lines. regLineChange (below)\n
  // registers single-line changes.\n
  function regChange(cm, from, to, lendiff) {\n
    if (from == null) from = cm.doc.first;\n
    if (to == null) to = cm.doc.first + cm.doc.size;\n
    if (!lendiff) lendiff = 0;\n
\n
    var display = cm.display;\n
    if (lendiff && to < display.viewTo &&\n
        (display.updateLineNumbers == null || display.updateLineNumbers > from))\n
      display.updateLineNumbers = from;\n
\n
    cm.curOp.viewChanged = true;\n
\n
    if (from >= display.viewTo) { // Change after\n
      if (sawCollapsedSpans && visualLineNo(cm.doc, from) < display.viewTo)\n
        resetView(cm);\n
    } else if (to <= display.viewFrom) { // Change before\n
      if (sawCollapsedSpans && visualLineEndNo(cm.doc, to + lendiff) > display.viewFrom) {\n
        resetView(cm);\n
      } else {\n
        display.viewFrom += lendiff;\n
        display.viewTo += lendiff;\n
      }\n
    } else if (from <= display.viewFrom && to >= display.viewTo) { // Full overlap\n
      resetView(cm);\n
    } else if (from <= display.viewFrom) { // Top overlap\n
      var cut = viewCuttingPoint(cm, to, to + lendiff, 1);\n
      if (cut) {\n
        display.view = display.view.slice(cut.index);\n
        display.viewFrom = cut.lineN;\n
        display.viewTo += lendiff;\n
      } else {\n
        resetView(cm);\n
      }\n
    } else if (to >= display.viewTo) { // Bottom overlap\n
      var cut = viewCuttingPoint(cm, from, from, -1);\n
      if (cut) {\n
        display.view = display.view.slice(0, cut.index);\n
        display.viewTo = cut.lineN;\n
      } else {\n
        resetView(cm);\n
      }\n
    } else { // Gap in the middle\n
      var cutTop = viewCuttingPoint(cm, from, from, -1);\n
      var cutBot = viewCuttingPoint(cm, to, to + lendiff, 1);\n
      if (cutTop && cutBot) {\n
        display.view = display.view.slice(0, cutTop.index)\n
          .concat(buildViewArray(cm, cutTop.lineN, cutBot.lineN))\n
          .concat(display.view.slice(cutBot.index));\n
        display.viewTo += lendiff;\n
      } else {\n
        resetView(cm);\n
      }\n
    }\n
\n
    var ext = display.externalMeasured;\n
    if (ext) {\n
      if (to < ext.lineN)\n
        ext.lineN += lendiff;\n
      else if (from < ext.lineN + ext.size)\n
        display.externalMeasured = null;\n
    }\n
  }\n
\n
  // Register a change to a single line. Type must be one of "text",\n
  // "gutter", "class", "widget"\n
  function regLineChange(cm, line, type) {\n
    cm.curOp.viewChanged = true;\n
    var display = cm.display, ext = cm.display.externalMeasured;\n
    if (ext && line >= ext.lineN && line < ext.lineN + ext.size)\n
      display.externalMeasured = null;\n
\n
    if (line < display.viewFrom || line >= display.viewTo) return;\n
    var lineView = display.view[findViewIndex(cm, line)];\n
    if (lineView.node == null) return;\n
    var arr = lineView.changes || (lineView.changes = []);\n
    if (indexOf(arr, type) == -1) arr.push(type);\n
  }\n
\n
  // Clear the view.\n
  function resetView(cm) {\n
    cm.display.viewFrom = cm.display.viewTo = cm.doc.first;\n
    cm.display.view = [];\n
    cm.display.viewOffset = 0;\n
  }\n
\n
  // Find the view element corresponding to a given line. Return null\n
  // when the line isn\'t visible.\n
  function findViewIndex(cm, n) {\n
    if (n >= cm.display.viewTo) return null;\n
    n -= cm.display.viewFrom;\n
    if (n < 0) return null;\n
    var view = cm.display.view;\n
    for (var i = 0; i < view.length; i++) {\n
      n -= view[i].size;\n
      if (n < 0) return i;\n
    }\n
  }\n
\n
  function viewCuttingPoint(cm, oldN, newN, dir) {\n
    var index = findViewIndex(cm, oldN), diff, view = cm.display.view;\n
    if (!sawCollapsedSpans || newN == cm.doc.first + cm.doc.size)\n
      return {index: index, lineN: newN};\n
    for (var i = 0, n = cm.display.viewFrom; i < index; i++)\n
      n += view[i].size;\n
    if (n != oldN) {\n
      if (dir > 0) {\n
        if (index == view.length - 1) return null;\n
        diff = (n + view[index].size) - oldN;\n
        index++;\n
      } else {\n
        diff = n - oldN;\n
      }\n
      oldN += diff; newN += diff;\n
    }\n
    while (visualLineNo(cm.doc, newN) != newN) {\n
      if (index == (dir < 0 ? 0 : view.length - 1)) return null;\n
      newN += dir * view[index - (dir < 0 ? 1 : 0)].size;\n
      index += dir;\n
    }\n
    return {index: index, lineN: newN};\n
  }\n
\n
  // Force the view to cover a given range, adding empty view element\n
  // or clipping off existing ones as needed.\n
  function adjustView(cm, from, to) {\n
    var display = cm.display, view = display.view;\n
    if (view.length == 0 || from >= display.viewTo || to <= display.viewFrom) {\n
      display.view = buildViewArray(cm, from, to);\n
      display.viewFrom = from;\n
    } else {\n
      if (display.viewFrom > from)\n
        display.view = buildViewArray(cm, from, display.viewFrom).concat(display.view);\n
      else if (display.viewFrom < from)\n
        display.view = display.view.slice(findViewIndex(cm, from));\n
      display.viewFrom = from;\n
      if (display.viewTo < to)\n
        display.view = display.view.concat(buildViewArray(cm, display.viewTo, to));\n
      else if (display.viewTo > to)\n
        display.view = display.view.slice(0, findViewIndex(cm, to));\n
    }\n
    display.viewTo = to;\n
  }\n
\n
  // Count the number of lines in the view whose DOM representation is\n
  // out of date (or nonexistent).\n
  function countDirtyView(cm) {\n
    var view = cm.display.view, dirty = 0;\n
    for (var i = 0; i < view.length; i++) {\n
      var lineView = view[i];\n
      if (!lineView.hidden && (!lineView.node || lineView.changes)) ++dirty;\n
    }\n
    return dirty;\n
  }\n
\n
  // EVENT HANDLERS\n
\n
  // Attach the necessary event handlers when initializing the editor\n
  function registerEventHandlers(cm) {\n
    var d = cm.display;\n
    on(d.scroller, "mousedown", operation(cm, onMouseDown));\n
    // Older IE\'s will not fire a second mousedown for a double click\n
    if (ie && ie_version < 11)\n
      on(d.scroller, "dblclick", operation(cm, function(e) {\n
        if (signalDOMEvent(cm, e)) return;\n
        var pos = posFromMouse(cm, e);\n
        if (!pos || clickInGutter(cm, e) || eventInWidget(cm.display, e)) return;\n
        e_preventDefault(e);\n
        var word = cm.findWordAt(pos);\n
        extendSelection(cm.doc, word.anchor, word.head);\n
      }));\n
    else\n
      on(d.scroller, "dblclick", function(e) { signalDOMEvent(cm, e) || e_preventDefault(e); });\n
    // Some browsers fire contextmenu *after* opening the menu, at\n
    // which point we can\'t mess with it anymore. Context menu is\n
    // handled in onMouseDown for these browsers.\n
    if (!captureRightClick) on(d.scroller, "contextmenu", function(e) {onContextMenu(cm, e);});\n
\n
    // Used to suppress mouse event handling when a touch happens\n
    var touchFinished, prevTouch = {end: 0};\n
    function finishTouch() {\n
      if (d.activeTouch) {\n
        touchFinished = setTimeout(function() {d.activeTouch = null;}, 1000);\n
        prevTouch = d.activeTouch;\n
        prevTouch.end = +new Date;\n
      }\n
    };\n
    function isMouseLikeTouchEvent(e) {\n
      if (e.touches.length != 1) return false;\n
      var touch = e.touches[0];\n
      return touch.radiusX <= 1 && touch.radiusY <= 1;\n
    }\n
    function farAway(touch, other) {\n
      if (other.left == null) return true;\n
      var dx = other.left - touch.left, dy = other.top - touch.top;\n
      return dx * dx + dy * dy > 20 * 20;\n
    }\n
    on(d.scroller, "touchstart", function(e) {\n
      if (!isMouseLikeTouchEvent(e)) {\n
        clearTimeout(touchFinished);\n
        var now = +new Date;\n
        d.activeTouch = {start: now, moved: false,\n
                         prev: now - prevTouch.end <= 300 ? prevTouch : null};\n
        if (e.touches.length == 1) {\n
          d.activeTouch.left = e.touches[0].pageX;\n
          d.activeTouch.top = e.touches[0].pageY;\n
        }\n
      }\n
    });\n
    on(d.scroller, "touchmove", function() {\n
      if (d.activeTouch) d.activeTouch.moved = true;\n
    });\n
    on(d.scroller, "touchend", function(e) {\n
      var touch = d.activeTouch;\n
      if (touch && !eventInWidget(d, e) && touch.left != null &&\n
          !touch.moved && new Date - touch.start < 300) {\n
        var pos = cm.coordsChar(d.activeTouch, "page"), range;\n
        if (!touch.prev || farAway(touch, touch.prev)) // Single tap\n
          range = new Range(pos, pos);\n
        else if (!touch.prev.prev || farAway(touch, touch.prev.prev)) // Double tap\n
          range = cm.findWordAt(pos);\n
        else // Triple tap\n
          range = new Range(Pos(pos.line, 0), clipPos(cm.doc, Pos(pos.line + 1, 0)));\n
        cm.setSelection(range.anchor, range.head);\n
        cm.focus();\n
        e_preventDefault(e);\n
      }\n
      finishTouch();\n
    });\n
    on(d.scroller, "touchcancel", finishTouch);\n
\n
    // Sync scrolling between fake scrollbars and real scrollable\n
    // area, ensure viewport is updated when scrolling.\n
    on(d.scroller, "scroll", function() {\n
      if (d.scroller.clientHeight) {\n
        setScrollTop(cm, d.scroller.scrollTop);\n
        setScrollLeft(cm, d.scroller.scrollLeft, true);\n
        signal(cm, "scroll", cm);\n
      }\n
    });\n
\n
    // Listen to wheel events in order to try and update the viewport on time.\n
    on(d.scroller, "mousewheel", function(e){onScrollWheel(cm, e);});\n
    on(d.scroller, "DOMMouseScroll", function(e){onScrollWheel(cm, e);});\n
\n
    // Prevent wrapper from ever scrolling\n
    on(d.wrapper, "scroll", function() { d.wrapper.scrollTop = d.wrapper.scrollLeft = 0; });\n
\n
    d.dragFunctions = {\n
      enter: function(e) {if (!signalDOMEvent(cm, e)) e_stop(e);},\n
      over: function(e) {if (!signalDOMEvent(cm, e)) { onDragOver(cm, e); e_stop(e); }},\n
      start: function(e){onDragStart(cm, e);},\n
      drop: operation(cm, onDrop),\n
      leave: function() {clearDragCursor(cm);}\n
    };\n
\n
    var inp = d.input.getField();\n
    on(inp, "keyup", function(e) { onKeyUp.call(cm, e); });\n
    on(inp, "keydown", operation(cm, onKeyDown));\n
    on(inp, "keypress", operation(cm, onKeyPress));\n
    on(inp, "focus", bind(onFocus, cm));\n
    on(inp, "blur", bind(onBlur, cm));\n
  }\n
\n
  function dragDropChanged(cm, value, old) {\n
    var wasOn = old && old != CodeMirror.Init;\n
    if (!value != !wasOn) {\n
      var funcs = cm.display.dragFunctions;\n
      var toggle = value ? on : off;\n
      toggle(cm.display.scroller, "dragstart", funcs.start);\n
      toggle(cm.display.scroller, "dragenter", funcs.enter);\n
      toggle(cm.display.scroller, "dragover", funcs.over);\n
      toggle(cm.display.scroller, "dragleave", funcs.leave);\n
      toggle(cm.display.scroller, "drop", funcs.drop);\n
    }\n
  }\n
\n
  // Called when the window resizes\n
  function onResize(cm) {\n
    var d = cm.display;\n
    if (d.lastWrapHeight == d.wrapper.clientHeight && d.lastWrapWidth == d.wrapper.clientWidth)\n
      return;\n
    // Might be a text scaling operation, clear size caches.\n
    d.cachedCharWidth = d.cachedTextHeight = d.cachedPaddingH = null;\n
    d.scrollbarsClipped = false;\n
    cm.setSize();\n
  }\n
\n
  // MOUSE EVENTS\n
\n
  // Return true when the given mouse event happened in a widget\n
  function eventInWidget(display, e) {\n
    for (var n = e_target(e); n != display.wrapper; n = n.parentNode) {\n
      if (!n || (n.nodeType == 1 && n.getAttribute("cm-ignore-events") == "true") ||\n
          (n.parentNode == display.sizer && n != display.mover))\n
        return true;\n
    }\n
  }\n
\n
  // Given a mouse event, find the corresponding position. If liberal\n
  // is false, it checks whether a gutter or scrollbar was clicked,\n
  // and returns null if it was. forRect is used by rectangular\n
  // selections, and tries to estimate a character position even for\n
  // coordinates beyond the right of the text.\n
  function posFromMouse(cm, e, liberal, forRect) {\n
    var display = cm.display;\n
    if (!liberal && e_target(e).getAttribute("cm-not-content") == "true") return null;\n
\n
    var x, y, space = display.lineSpace.getBoundingClientRect();\n
    // Fails unpredictably on IE[67] when mouse is dragged around quickly.\n
    try { x = e.clientX - space.left; y = e.clientY - space.top; }\n
    catch (e) { return null; }\n
    var coords = coordsChar(cm, x, y), line;\n
    if (forRect && coords.xRel == 1 && (line = getLine(cm.doc, coords.line).text).length == coords.ch) {\n
      var colDiff = countColumn(line, line.length, cm.options.tabSize) - line.length;\n
      coords = Pos(coords.line, Math.max(0, Math.round((x - paddingH(cm.display).left) / charWidth(cm.display)) - colDiff));\n
    }\n
    return coords;\n
  }\n
\n
  // A mouse down can be a single click, double click, triple click,\n
  // start of selection drag, start of text drag, new cursor\n
  // (ctrl-click), rectangle drag (alt-drag), or xwin\n
  // middle-click-paste. Or it might be a click on something we should\n
  // not interfere with, such as a scrollbar or widget.\n
  function onMouseDown(e) {\n
    var cm = this, display = cm.display;\n
    if (display.activeTouch && display.input.supportsTouch() || signalDOMEvent(cm, e)) return;\n
    display.shift = e.shiftKey;\n
\n
    if (eventInWidget(display, e)) {\n
      if (!webkit) {\n
        // Briefly turn off draggability, to allow widgets to do\n
        // normal dragging things.\n
        display.scroller.draggable = false;\n
        setTimeout(function(){display.scroller.draggable = true;}, 100);\n
      }\n
      return;\n
    }\n
    if (clickInGutter(cm, e)) return;\n
    var start = posFromMouse(cm, e);\n
    window.focus();\n
\n
    switch (e_button(e)) {\n
    case 1:\n
      // #3261: make sure, that we\'re not starting a second selection\n
      if (cm.state.selectingText)\n
        cm.state.selectingText(e);\n
      else if (start)\n
        leftButtonDown(cm, e, start);\n
      else if (e_target(e) == display.scroller)\n
        e_preventDefault(e);\n
      break;\n
    case 2:\n
      if (webkit) cm.state.lastMiddleDown = +new Date;\n
      if (start) extendSelection(cm.doc, start);\n
      setTimeout(function() {display.input.focus();}, 20);\n
      e_preventDefault(e);\n
      break;\n
    case 3:\n
      if (captureRightClick) onContextMenu(cm, e);\n
      else delayBlurEvent(cm);\n
      break;\n
    }\n
  }\n
\n
  var lastClick, lastDoubleClick;\n
  function leftButtonDown(cm, e, start) {\n
    if (ie) setTimeout(bind(ensureFocus, cm), 0);\n
    else cm.curOp.focus = activeElt();\n
\n
    var now = +new Date, type;\n
    if (lastDoubleClick && lastDoubleClick.time > now - 400 && cmp(lastDoubleClick.pos, start) == 0) {\n
      type = "triple";\n
    } else if (lastClick && lastClick.time > now - 400 && cmp(lastClick.pos, start) == 0) {\n
      type = "double";\n
      lastDoubleClick = {time: now, pos: start};\n
    } else {\n
      type = "single";\n
      lastClick = {time: now, pos: start};\n
    }\n
\n
    var sel = cm.doc.sel, modifier = mac ? e.metaKey : e.ctrlKey, contained;\n
    if (cm.options.dragDrop && dragAndDrop && !cm.isReadOnly() &&\n
        type == "single" && (contained = sel.contains(start)) > -1 &&\n
        (cmp((contained = sel.ranges[contained]).from(), start) < 0 || start.xRel > 0) &&\n
        (cmp(contained.to(), start) > 0 || start.xRel < 0))\n
      leftButtonStartDrag(cm, e, start, modifier);\n
    else\n
      leftButtonSelect(cm, e, start, type, modifier);\n
  }\n
\n
  // Start a text drag. When it ends, see if any dragging actually\n
  // happen, and treat as a click if it didn\'t.\n
  function leftButtonStartDrag(cm, e, start, modifier) {\n
    var display = cm.display, startTime = +new Date;\n
    var dragEnd = operation(cm, function(e2) {\n
      if (webkit) display.scroller.draggable = false;\n
      cm.state.draggingText = false;\n
      off(document, "mouseup", dragEnd);\n
      off(display.scroller, "drop", dragEnd);\n
      if (Math.abs(e.clientX - e2.clientX) + Math.abs(e.clientY - e2.clientY) < 10) {\n
        e_preventDefault(e2);\n
        if (!modifier && +new Date - 200 < startTime)\n
          extendSelection(cm.doc, start);\n
        // Work around unexplainable focus problem in IE9 (#2127) and Chrome (#3081)\n
        if (webkit || ie && ie_version == 9)\n
          setTimeout(function() {document.body.focus(); display.input.focus();}, 20);\n
        else\n
          display.input.focus();\n
      }\n
    });\n
    // Let the drag handler handle this.\n
    if (webkit) display.scroller.draggable = true;\n
    cm.state.draggingText = dragEnd;\n
    // IE\'s approach to draggable\n
    if (display.scroller.dragDrop) display.scroller.dragDrop();\n
    on(document, "mouseup", dragEnd);\n
    on(display.scroller, "drop", dragEnd);\n
  }\n
\n
  // Normal selection, as opposed to text dragging.\n
  function leftButtonSelect(cm, e, start, type, addNew) {\n
    var display = cm.display, doc = cm.doc;\n
    e_preventDefault(e);\n
\n
    var ourRange, ourIndex, startSel = doc.sel, ranges = startSel.ranges;\n
    if (addNew && !e.shiftKey) {\n
      ourIndex = doc.sel.contains(start);\n
      if (ourIndex > -1)\n
        ourRange = ranges[ourIndex];\n
      else\n
        ourRange = new Range(start, start);\n
    } else {\n
      ourRange = doc.sel.primary();\n
      ourIndex = doc.sel.primIndex;\n
    }\n
\n
    if (e.altKey) {\n
      type = "rect";\n
      if (!addNew) ourRange = new Range(start, start);\n
      start = posFromMouse(cm, e, true, true);\n
      ourIndex = -1;\n
    } else if (type == "double") {\n
      var word = cm.findWordAt(start);\n
      if (cm.display.shift || doc.extend)\n
        ourRange = extendRange(doc, ourRange, word.anchor, word.head);\n
      else\n
        ourRange = word;\n
    } else if (type == "triple") {\n
      var line = new Range(Pos(start.line, 0), clipPos(doc, Pos(start.line + 1, 0)));\n
      if (cm.display.shift || doc.extend)\n
        ourRange = extendRange(doc, ourRange, line.anchor, line.head);\n
      else\n
        ourRange = line;\n
    } else {\n
      ourRange = extendRange(doc, ourRange, start);\n
    }\n
\n
    if (!addNew) {\n
      ourIndex = 0;\n
      setSelection(doc, new Selection([ourRange], 0), sel_mouse);\n
      startSel = doc.sel;\n
    } else if (ourIndex == -1) {\n
      ourIndex = ranges.length;\n
      setSelection(doc, normalizeSelection(ranges.concat([ourRange]), ourIndex),\n
                   {scroll: false, origin: "*mouse"});\n
    } else if (ranges.length > 1 && ranges[ourIndex].empty() && type == "single" && !e.shiftKey) {\n
      setSelection(doc, normalizeSelection(ranges.slice(0, ourIndex).concat(ranges.slice(ourIndex + 1)), 0),\n
                   {scroll: false, origin: "*mouse"});\n
      startSel = doc.sel;\n
    } else {\n
      replaceOneSelection(doc, ourIndex, ourRange, sel_mouse);\n
    }\n
\n
    var lastPos = start;\n
    function extendTo(pos) {\n
      if (cmp(lastPos, pos) == 0) return;\n
      lastPos = pos;\n
\n
      if (type == "rect") {\n
        var ranges = [], tabSize = cm.options.tabSize;\n
        var startCol = countColumn(getLine(doc, start.line).text, start.ch, tabSize);\n
        var posCol = countColumn(getLine(doc, pos.line).text, pos.ch, tabSize);\n
        var left = Math.min(startCol, posCol), right = Math.max(startCol, posCol);\n
        for (var line = Math.min(start.line, pos.line), end = Math.min(cm.lastLine(), Math.max(start.line, pos.line));\n
             line <= end; line++) {\n
          var text = getLine(doc, line).text, leftPos = findColumn(text, left, tabSize);\n
          if (left == right)\n
            ranges.push(new Range(Pos(line, leftPos), Pos(line, leftPos)));\n
          else if (text.length > leftPos)\n
            ranges.push(new Range(Pos(line, leftPos), Pos(line, findColumn(text, right, tabSize))));\n
        }\n
        if (!ranges.length) ranges.push(new Range(start, start));\n
        setSelection(doc, normalizeSelection(startSel.ranges.slice(0, ourIndex).concat(ranges), ourIndex),\n
                     {origin: "*mouse", scroll: false});\n
        cm.scrollIntoView(pos);\n
      } else {\n
        var oldRange = ourRange;\n
        var anchor = oldRange.anchor, head = pos;\n
        if (type != "single") {\n
          if (type == "double")\n
            var range = cm.findWordAt(pos);\n
          else\n
            var range = new Range(Pos(pos.line, 0), clipPos(doc, Pos(pos.line + 1, 0)));\n
          if (cmp(range.anchor, anchor) > 0) {\n
            head = range.head;\n
            anchor = minPos(oldRange.from(), range.anchor);\n
          } else {\n
            head = range.anchor;\n
            anchor = maxPos(oldRange.to(), range.head);\n
          }\n
        }\n
        var ranges = startSel.ranges.slice(0);\n
        ranges[ourIndex] = new Range(clipPos(doc, anchor), head);\n
        setSelection(doc, normalizeSelection(ranges, ourIndex), sel_mouse);\n
      }\n
    }\n
\n
    var editorSize = display.wrapper.getBoundingClientRect();\n
    // Used to ensure timeout re-tries don\'t fire when another extend\n
    // happened in the meantime (clearTimeout isn\'t reliable -- at\n
    // least on Chrome, the timeouts still happen even when cleared,\n
    // if the clear happens after their scheduled firing time).\n
    var counter = 0;\n
\n
    function extend(e) {\n
      var curCount = ++counter;\n
      var cur = posFromMouse(cm, e, true, type == "rect");\n
      if (!cur) return;\n
      if (cmp(cur, lastPos) != 0) {\n
        cm.curOp.focus = activeElt();\n
        extendTo(cur);\n
        var visible = visibleLines(display, doc);\n
        if (cur.line >= visible.to || cur.line < visible.from)\n
          setTimeout(operation(cm, function(){if (counter == curCount) extend(e);}), 150);\n
      } else {\n
        var outside = e.clientY < editorSize.top ? -20 : e.clientY > editorSize.bottom ? 20 : 0;\n
        if (outside) setTimeout(operation(cm, function() {\n
          if (counter != curCount) return;\n
          display.scroller.scrollTop += outside;\n
          extend(e);\n
        }), 50);\n
      }\n
    }\n
\n
    function done(e) {\n
      cm.state.selectingText = false;\n
      counter = Infinity;\n
      e_preventDefault(e);\n
      display.input.focus();\n
      off(document, "mousemove", move);\n
      off(document, "mouseup", up);\n
      doc.history.lastSelOrigin = null;\n
    }\n
\n
    var move = operation(cm, function(e) {\n
      if (!e_button(e)) done(e);\n
      else extend(e);\n
    });\n
    var up = operation(cm, done);\n
    cm.state.selectingText = up;\n
    on(document, "mousemove", move);\n
    on(document, "mouseup", up);\n
  }\n
\n
  // Determines whether an event happened in the gutter, and fires the\n
  // handlers for the corresponding event.\n
  function gutterEvent(cm, e, type, prevent) {\n
    try { var mX = e.clientX, mY = e.clientY; }\n
    catch(e) { return false; }\n
    if (mX >= Math.floor(cm.display.gutters.getBoundingClientRect().right)) return false;\n
    if (prevent) e_preventDefault(e);\n
\n
    var display = cm.display;\n
    var lineBox = display.lineDiv.getBoundingClientRect();\n
\n
    if (mY > lineBox.bottom || !hasHandler(cm, type)) return e_defaultPrevented(e);\n
    mY -= lineBox.top - display.viewOffset;\n
\n
    for (var i = 0; i < cm.options.gutters.length; ++i) {\n
      var g = display.gutters.childNodes[i];\n
      if (g && g.getBoundingClientRect().right >= mX) {\n
        var line = lineAtHeight(cm.doc, mY);\n
        var gutter = cm.options.gutters[i];\n
        signal(cm, type, cm, line, gutter, e);\n
        return e_defaultPrevented(e);\n
      }\n
    }\n
  }\n
\n
  function clickInGutter(cm, e) {\n
    return gutterEvent(cm, e, "gutterClick", true);\n
  }\n
\n
  // Kludge to work around strange IE behavior where it\'ll sometimes\n
  // re-fire a series of drag-related events right after the drop (#1551)\n
  var lastDrop = 0;\n
\n
  function onDrop(e) {\n
    var cm = this;\n
    clearDragCursor(cm);\n
    if (signalDOMEvent(cm, e) || eventInWidget(cm.display, e))\n
      return;\n
    e_preventDefault(e);\n
    if (ie) lastDrop = +new Date;\n
    var pos = posFromMouse(cm, e, true), files = e.dataTransfer.files;\n
    if (!pos || cm.isReadOnly()) return;\n
    // Might be a file drop, in which case we simply extract the text\n
    // and insert it.\n
    if (files && files.length && window.FileReader && window.File) {\n
      var n = files.length, text = Array(n), read = 0;\n
      var loadFile = function(file, i) {\n
        if (cm.options.allowDropFileTypes &&\n
            indexOf(cm.options.allowDropFileTypes, file.type) == -1)\n
          return;\n
\n
        var reader = new FileReader;\n
        reader.onload = operation(cm, function() {\n
          var content = reader.result;\n
          if (/[\\x00-\\x08\\x0e-\\x1f]{2}/.test(content)) content = "";\n
          text[i] = content;\n
          if (++read == n) {\n
            pos = clipPos(cm.doc, pos);\n
            var change = {from: pos, to: pos,\n
                          text: cm.doc.splitLines(text.join(cm.doc.lineSeparator())),\n
                          origin: "paste"};\n
            makeChange(cm.doc, change);\n
            setSelectionReplaceHistory(cm.doc, simpleSelection(pos, changeEnd(change)));\n
          }\n
        });\n
        reader.readAsText(file);\n
      };\n
      for (var i = 0; i < n; ++i) loadFile(files[i], i);\n
    } else { // Normal drop\n
      // Don\'t do a replace if the drop happened inside of the selected text.\n
      if (cm.state.draggingText && cm.doc.sel.contains(pos) > -1) {\n
        cm.state.draggingText(e);\n
        // Ensure the editor is re-focused\n
        setTimeout(function() {cm.display.input.focus();}, 20);\n
        return;\n
      }\n
      try {\n
        var text = e.dataTransfer.getData("Text");\n
        if (text) {\n
          if (cm.state.draggingText && !(mac ? e.altKey : e.ctrlKey))\n
            var selected = cm.listSelections();\n
          setSelectionNoUndo(cm.doc, simpleSelection(pos, pos));\n
          if (selected) for (var i = 0; i < selected.length; ++i)\n
            replaceRange(cm.doc, "", selected[i].anchor, selected[i].head, "drag");\n
          cm.replaceSelection(text, "around", "paste");\n
          cm.display.input.focus();\n
        }\n
      }\n
      catch(e){}\n
    }\n
  }\n
\n
  function onDragStart(cm, e) {\n
    if (ie && (!cm.state.draggingText || +new Date - lastDrop < 100)) { e_stop(e); return; }\n
    if (signalDOMEvent(cm, e) || eventInWidget(cm.display, e)) return;\n
\n
    e.dataTransfer.setData("Text", cm.getSelection());\n
\n
    // Use dummy image instead of default browsers image.\n
    // Recent Safari (~6.0.2) have a tendency to segfault when this happens, so we don\'t do it there.\n
    if (e.dataTransfer.setDragImage && !safari) {\n
      var img = elt("img", null, null, "position: fixed; left: 0; top: 0;");\n
      img.src = "data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==";\n
      if (presto) {\n
        img.width = img.height = 1;\n
        cm.display.wrapper.appendChild(img);\n
        // Force a relayout, or Opera won\'t use our image for some obscure reason\n
        img._top = img.offsetTop;\n
      }\n
      e.dataTransfer.setDragImage(img, 0, 0);\n
      if (presto) img.parentNode.removeChild(img);\n
    }\n
  }\n
\n
  function onDragOver(cm, e) {\n
    var pos = posFromMouse(cm, e);\n
    if (!pos) return;\n
    var frag = document.createDocumentFragment();\n
    drawSelectionCursor(cm, pos, frag);\n
    if (!cm.display.dragCursor) {\n
      cm.display.dragCursor = elt("div", null, "CodeMirror-cursors CodeMirror-dragcursors");\n
      cm.display.lineSpace.insertBefore(cm.display.dragCursor, cm.display.cursorDiv);\n
    }\n
    removeChildrenAndAdd(cm.display.dragCursor, frag);\n
  }\n
\n
  function clearDragCursor(cm) {\n
    if (cm.display.dragCursor) {\n
      cm.display.lineSpace.removeChild(cm.display.dragCursor);\n
      cm.display.dragCursor = null;\n
    }\n
  }\n
\n
  // SCROLL EVENTS\n
\n
  // Sync the scrollable area and scrollbars, ensure the viewport\n
  // covers the visible area.\n
  function setScrollTop(cm, val) {\n
    if (Math.abs(cm.doc.scrollTop - val) < 2) return;\n
    cm.doc.scrollTop = val;\n
    if (!gecko) updateDisplaySimple(cm, {top: val});\n
    if (cm.display.scroller.scrollTop != val) cm.display.scroller.scrollTop = val;\n
    cm.display.scrollbars.setScrollTop(val);\n
    if (gecko) updateDisplaySimple(cm);\n
    startWorker(cm, 100);\n
  }\n
  // Sync scroller and scrollbar, ensure the gutter elements are\n
  // aligned.\n
  function setScrollLeft(cm, val, isScroller) {\n
    if (isScroller ? val == cm.doc.scrollLeft : Math.abs(cm.doc.scrollLeft - val) < 2) return;\n
    val = Math.min(val, cm.display.scroller.scrollWidth - cm.display.scroller.clientWidth);\n
    cm.doc.scrollLeft = val;\n
    alignHorizontally(cm);\n
    if (cm.display.scroller.scrollLeft != val) cm.display.scroller.scrollLeft = val;\n
    cm.display.scrollbars.setScrollLeft(val);\n
  }\n
\n
  // Since the delta values reported on mouse wheel events are\n
  // unstandardized between browsers and even browser versions, and\n
  // generally horribly unpredictable, this code starts by measuring\n
  // the scroll effect that the first few mouse wheel events have,\n
  // and, from that, detects the way it can convert deltas to pixel\n
  // offsets afterwards.\n
  //\n
  // The reason we want to know the amount a wheel event will scroll\n
  // is that it gives us a chance to update the display before the\n
  // actual scrolling happens, reducing flickering.\n
\n
  var wheelSamples = 0, wheelPixelsPerUnit = null;\n
  // Fill in a browser-detected starting value on browsers where we\n
  // know one. These don\'t have to be accurate -- the result of them\n
  // being wrong would just be a slight flicker on the first wheel\n
  // scroll (if it is large enough).\n
  if (ie) wheelPixelsPerUnit = -.53;\n
  else if (gecko) wheelPixelsPerUnit = 15;\n
  else if (chrome) wheelPixelsPerUnit = -.7;\n
  else if (safari) wheelPixelsPerUnit = -1/3;\n
\n
  var wheelEventDelta = function(e) {\n
    var dx = e.wheelDeltaX, dy = e.wheelDeltaY;\n
    if (dx == null && e.detail && e.axis == e.HORIZONTAL_AXIS) dx = e.detail;\n
    if (dy == null && e.detail && e.axis == e.VERTICAL_AXIS) dy = e.detail;\n
    else if (dy == null) dy = e.wheelDelta;\n
    return {x: dx, y: dy};\n
  };\n
  CodeMirror.wheelEventPixels = function(e) {\n
    var delta = wheelEventDelta(e);\n
    delta.x *= wheelPixelsPerUnit;\n
    delta.y *= wheelPixelsPerUnit;\n
    return delta;\n
  };\n
\n
  function onScrollWheel(cm, e) {\n
    var delta = wheelEventDelta(e), dx = delta.x, dy = delta.y;\n
\n
    var display = cm.display, scroll = display.scroller;\n
    // Quit if there\'s nothing to scroll here\n
    var canScrollX = scroll.scrollWidth > scroll.clientWidth;\n
    var canScrollY = scroll.scrollHeight > scroll.clientHeight;\n
    if (!(dx && canScrollX || dy && canScrollY)) return;\n
\n
    // Webkit browsers on OS X abort momentum scrolls when the target\n
    // of the scroll event is removed from the scrollable element.\n
    // This hack (see related code in patchDisplay) makes sure the\n
    // element is kept around.\n
    if (dy && mac && webkit) {\n
      outer: for (var cur = e.target, view = display.view; cur != scroll; cur = cur.parentNode) {\n
        for (var i = 0; i < view.length; i++) {\n
          if (view[i].node == cur) {\n
            cm.display.currentWheelTarget = cur;\n
            break outer;\n
          }\n
        }\n
      }\n
    }\n
\n
    // On some browsers, horizontal scrolling will cause redraws to\n
    // happen before the gutter has been realigned, causing it to\n
    // wriggle around in a most unseemly way. When we have an\n
    // estimated pixels/delta value, we just handle horizontal\n
    // scrolling entirely here. It\'ll be slightly off from native, but\n
    // better than glitching out.\n
    if (dx && !gecko && !presto && wheelPixelsPerUnit != null) {\n
      if (dy && canScrollY)\n
        setScrollTop(cm, Math.max(0, Math.min(scroll.scrollTop + dy * wheelPixelsPerUnit, scroll.scrollHeight - scroll.clientHeight)));\n
      setScrollLeft(cm, Math.max(0, Math.min(scroll.scrollLeft + dx * wheelPixelsPerUnit, scroll.scrollWidth - scroll.clientWidth)));\n
      // Only prevent default scrolling if vertical scrolling is\n
      // actually possible. Otherwise, it causes vertical scroll\n
      // jitter on OSX trackpads when deltaX is small and deltaY\n
      // is large (issue #3579)\n
      if (!dy || (dy && canScrollY))\n
        e_preventDefault(e);\n
      display.wheelStartX = null; // Abort measurement, if in progress\n
      return;\n
    }\n
\n
    // \'Project\' the visible viewport to cover the area that is being\n
    // scrolled into view (if we know enough to estimate it).\n
    if (dy && wheelPixelsPerUnit != null) {\n
      var pixels = dy * wheelPixelsPerUnit;\n
      var top = cm.doc.scrollTop, bot = top + display.wrapper.clientHeight;\n
      if (pixels < 0) top = Math.max(0, top + pixels - 50);\n
      else bot = Math.min(cm.doc.height, bot + pixels + 50);\n
      updateDisplaySimple(cm, {top: top, bottom: bot});\n
    }\n
\n
    if (wheelSamples < 20) {\n
      if (display.wheelStartX == null) {\n
        display.wheelStartX = scroll.scrollLeft; display.wheelStartY = scroll.scrollTop;\n
        display.wheelDX = dx; display.wheelDY = dy;\n
        setTimeout(function() {\n
          if (display.wheelStartX == null) return;\n
          var movedX = scroll.scrollLeft - display.wheelStartX;\n
          var movedY = scroll.scrollTop - display.wheelStartY;\n
          var sample = (movedY && display.wheelDY && movedY / display.wheelDY) ||\n
            (movedX && display.wheelDX && movedX / display.wheelDX);\n
          display.wheelStartX = display.wheelStartY = null;\n
          if (!sample) return;\n
          wheelPixelsPerUnit = (wheelPixelsPerUnit * wheelSamples + sample) / (wheelSamples + 1);\n
          ++wheelSamples;\n
        }, 200);\n
      } else {\n
        display.wheelDX += dx; display.wheelDY += dy;\n
      }\n
    }\n
  }\n
\n
  // KEY EVENTS\n
\n
  // Run a handler that was bound to a key.\n
  function doHandleBinding(cm, bound, dropShift) {\n
    if (typeof bound == "string") {\n
      bound = commands[bound];\n
      if (!bound) return false;\n
    }\n
    // Ensure previous input has been read, so that the handler sees a\n
    // consistent view of the document\n
    cm.display.input.ensurePolled();\n
    var prevShift = cm.display.shift, done = false;\n
    try {\n
      if (cm.isReadOnly()) cm.state.suppressEdits = true;\n
      if (dropShift) cm.display.shift = false;\n
      done = bound(cm) != Pass;\n
    } finally {\n
      cm.display.shift = prevShift;\n
      cm.state.suppressEdits = false;\n
    }\n
    return done;\n
  }\n
\n
  function lookupKeyForEditor(cm, name, handle) {\n
    for (var i = 0; i < cm.state.keyMaps.length; i++) {\n
      var result = lookupKey(name, cm.state.keyMaps[i], handle, cm);\n
      if (result) return result;\n
    }\n
    return (cm.options.extraKeys && lookupKey(name, cm.options.extraKeys, handle, cm))\n
      || lookupKey(name, cm.options.keyMap, handle, cm);\n
  }\n
\n
  var stopSeq = new Delayed;\n
  function dispatchKey(cm, name, e, handle) {\n
    var seq = cm.state.keySeq;\n
    if (seq) {\n
      if (isModifierKey(name)) return "handled";\n
      stopSeq.set(50, function() {\n
        if (cm.state.keySeq == seq) {\n
          cm.state.keySeq = null;\n
          cm.display.input.reset();\n
        }\n
      });\n
      name = seq + " " + name;\n
    }\n
    var result = lookupKeyForEditor(cm, name, handle);\n
\n
    if (result == "multi")\n
      cm.state.keySeq = name;\n
    if (result == "handled")\n
      signalLater(cm, "keyHandled", cm, name, e);\n
\n
    if (result == "handled" || result == "multi") {\n
      e_preventDefault(e);\n
      restartBlink(cm);\n
    }\n
\n
    if (seq && !result && /\\\'$/.test(name)) {\n
      e_preventDefault(e);\n
      return true;\n
    }\n
    return !!result;\n
  }\n
\n
  // Handle a key from the keydown event.\n
  function handleKeyBinding(cm, e) {\n
    var name = keyName(e, true);\n
    if (!name) return false;\n
\n
    if (e.shiftKey && !cm.state.keySeq) {\n
      // First try to resolve full name (including \'Shift-\'). Failing\n
      // that, see if there is a cursor-motion command (starting with\n
      // \'go\') bound to the keyname without \'Shift-\'.\n
      return dispatchKey(cm, "Shift-" + name, e, function(b) {return doHandleBinding(cm, b, true);})\n
          || dispatchKey(cm, name, e, function(b) {\n
               if (typeof b == "string" ? /^go[A-Z]/.test(b) : b.motion)\n
                 return doHandleBinding(cm, b);\n
             });\n
    } else {\n
      return dispatchKey(cm, name, e, function(b) { return doHandleBinding(cm, b); });\n
    }\n
  }\n
\n
  // Handle a key from the keypress event\n
  function handleCharBinding(cm, e, ch) {\n
    return dispatchKey(cm, "\'" + ch + "\'", e,\n
                       function(b) { return doHandleBinding(cm, b, true); });\n
  }\n
\n
  var lastStoppedKey = null;\n
  function onKeyDown(e) {\n
    var cm = this;\n
    cm.curOp.focus = activeElt();\n
    if (signalDOMEvent(cm, e)) return;\n
    // IE does strange things with escape.\n
    if (ie && ie_version < 11 && e.keyCode == 27) e.returnValue = false;\n
    var code = e.keyCode;\n
    cm.display.shift = code == 16 || e.shiftKey;\n
    var handled = handleKeyBinding(cm, e);\n
    if (presto) {\n
      lastStoppedKey = handled ? code : null;\n
      // Opera has no cut event... we try to at least catch the key combo\n
      if (!handled && code == 88 && !hasCopyEvent && (mac ? e.metaKey : e.ctrlKey))\n
        cm.replaceSelection("", null, "cut");\n
    }\n
\n
    // Turn mouse into crosshair when Alt is held on Mac.\n
    if (code == 18 && !/\\bCodeMirror-crosshair\\b/.test(cm.display.lineDiv.className))\n
      showCrossHair(cm);\n
  }\n
\n
  function showCrossHair(cm) {\n
    var lineDiv = cm.display.lineDiv;\n
    addClass(lineDiv, "CodeMirror-crosshair");\n
\n
    function up(e) {\n
      if (e.keyCode == 18 || !e.altKey) {\n
        rmClass(lineDiv, "CodeMirror-crosshair");\n
        off(document, "keyup", up);\n
        off(document, "mouseover", up);\n
      }\n
    }\n
    on(document, "keyup", up);\n
    on(document, "mouseover", up);\n
  }\n
\n
  function onKeyUp(e) {\n
    if (e.keyCode == 16) this.doc.sel.shift = false;\n
    signalDOMEvent(this, e);\n
  }\n
\n
  function onKeyPress(e) {\n
    var cm = this;\n
    if (eventInWidget(cm.display, e) || signalDOMEvent(cm, e) || e.ctrlKey && !e.altKey || mac && e.metaKey) return;\n
    var keyCode = e.keyCode, charCode = e.charCode;\n
    if (presto && keyCode == lastStoppedKey) {lastStoppedKey = null; e_preventDefault(e); return;}\n
    if ((presto && (!e.which || e.which < 10)) && handleKeyBinding(cm, e)) return;\n
    var ch = String.fromCharCode(charCode == null ? keyCode : charCode);\n
    if (handleCharBinding(cm, e, ch)) return;\n
    cm.display.input.onKeyPress(e);\n
  }\n
\n
  // FOCUS/BLUR EVENTS\n
\n
  function delayBlurEvent(cm) {\n
    cm.state.delayingBlurEvent = true;\n
    setTimeout(function() {\n
      if (cm.state.delayingBlurEvent) {\n
        cm.state.delayingBlurEvent = false;\n
        onBlur(cm);\n
      }\n
    }, 100);\n
  }\n
\n
  function onFocus(cm) {\n
    if (cm.state.delayingBlurEvent) cm.state.delayingBlurEvent = false;\n
\n
    if (cm.options.readOnly == "nocursor") return;\n
    if (!cm.state.focused) {\n
      signal(cm, "focus", cm);\n
      cm.state.focused = true;\n
      addClass(cm.display.wrapper, "CodeMirror-focused");\n
      // This test prevents this from firing when a context\n
      // menu is closed (since the input reset would kill the\n
      // select-all detection hack)\n
      if (!cm.curOp && cm.display.selForContextMenu != cm.doc.sel) {\n
        cm.display.input.reset();\n
        if (webkit) setTimeout(function() { cm.display.input.reset(true); }, 20); // Issue #1730\n
      }\n
      cm.display.input.receivedFocus();\n
    }\n
    restartBlink(cm);\n
  }\n
  function onBlur(cm) {\n
    if (cm.state.delayingBlurEvent) return;\n
\n
    if (cm.state.focused) {\n
      signal(cm, "blur", cm);\n
      cm.state.focused = false;\n
      rmClass(cm.display.wrapper, "CodeMirror-focused");\n
    }\n
    clearInterval(cm.display.blinker);\n
    setTimeout(function() {if (!cm.state.focused) cm.display.shift = false;}, 150);\n
  }\n
\n
  // CONTEXT MENU HANDLING\n
\n
  // To make the context menu work, we need to briefly unhide the\n
  // textarea (making it as unobtrusive as possible) to let the\n
  // right-click take effect on it.\n
  function onContextMenu(cm, e) {\n
    if (eventInWidget(cm.display, e) || contextMenuInGutter(cm, e)) return;\n
    if (signalDOMEvent(cm, e, "contextmenu")) return;\n
    cm.display.input.onContextMenu(e);\n
  }\n
\n
  function contextMenuInGutter(cm, e) {\n
    if (!hasHandler(cm, "gutterContextMenu")) return false;\n
    return gutterEvent(cm, e, "gutterContextMenu", false);\n
  }\n
\n
  // UPDATING\n
\n
  // Compute the position of the end of a change (its \'to\' property\n
  // refers to the pre-change end).\n
  var changeEnd = CodeMirror.changeEnd = function(change) {\n
    if (!change.text) return change.to;\n
    return Pos(change.from.line + change.text.length - 1,\n
               lst(change.text).length + (change.text.length == 1 ? change.from.ch : 0));\n
  };\n
\n
  // Adjust a position to refer to the post-change position of the\n
  // same text, or the end of the change if the change covers it.\n
  function adjustForChange(pos, change) {\n
    if (cmp(pos, change.from) < 0) return pos;\n
    if (cmp(pos, change.to) <= 0) return changeEnd(change);\n
\n
    var line = pos.line + change.text.length - (change.to.line - change.from.line) - 1, ch = pos.ch;\n
    if (pos.line == change.to.line) ch += changeEnd(change).ch - change.to.ch;\n
    return Pos(line, ch);\n
  }\n
\n
  function computeSelAfterChange(doc, change) {\n
    var out = [];\n
    for (var i = 0; i < doc.sel.ranges.length; i++) {\n
      var range = doc.sel.ranges[i];\n
      out.push(new Range(adjustForChange(range.anchor, change),\n
                         adjustForChange(range.head, change)));\n
    }\n
    return normalizeSelection(out, doc.sel.primIndex);\n
  }\n
\n
  function offsetPos(pos, old, nw) {\n
    if (pos.line == old.line)\n
      return Pos(nw.line, pos.ch - old.ch + nw.ch);\n
    else\n
      return Pos(nw.line + (pos.line - old.line), pos.ch);\n
  }\n
\n
  // Used by replaceSelections to allow moving the selection to the\n
  // start or around the replaced test. Hint may be "start" or "around".\n
  function computeReplacedSel(doc, changes, hint) {\n
    var out = [];\n
    var oldPrev = Pos(doc.first, 0), newPrev = oldPrev;\n
    for (var i = 0; i < changes.length; i++) {\n
      var change = changes[i];\n
      var from = offsetPos(change.from, oldPrev, newPrev);\n
      var to = offsetPos(changeEnd(change), oldPrev, newPrev);\n
      oldPrev = change.to;\n
      newPrev = to;\n
      if (hint == "around") {\n
        var range = doc.sel.ranges[i], inv = cmp(range.head, range.anchor) < 0;\n
        out[i] = new Range(inv ? to : from, inv ? from : to);\n
      } else {\n
        out[i] = new Range(from, from);\n
      }\n
    }\n
    return new Selection(out, doc.sel.primIndex);\n
  }\n
\n
  // Allow "beforeChange" event handlers to influence a change\n
  function filterChange(doc, change, update) {\n
    var obj = {\n
      canceled: false,\n
      from: change.from,\n
      to: change.to,\n
      text: change.text,\n
      origin: change.origin,\n
      cancel: function() { this.canceled = true; }\n
    };\n
    if (update) obj.update = function(from, to, text, origin) {\n
      if (from) this.from = clipPos(doc, from);\n
      if (to) this.to = clipPos(doc, to);\n
      if (text) this.text = text;\n
      if (origin !== undefined) this.origin = origin;\n
    };\n
    signal(doc, "beforeChange", doc, obj);\n
    if (doc.cm) signal(doc.cm, "beforeChange", doc.cm, obj);\n
\n
    if (obj.canceled) return null;\n
    return {from: obj.from, to: obj.to, text: obj.text, origin: obj.origin};\n
  }\n
\n
  // Apply a change to a document, and add it to the document\'s\n
  // history, and propagating it to all linked documents.\n
  function makeChange(doc, change, ignoreReadOnly) {\n
    if (doc.cm) {\n
      if (!doc.cm.curOp) return operation(doc.cm, makeChange)(doc, change, ignoreReadOnly);\n
      if (doc.cm.state.suppressEdits) return;\n
    }\n
\n
    if (hasHandler(doc, "beforeChange") || doc.cm && hasHandler(doc.cm, "beforeChange")) {\n
      change = filterChange(doc, change, true);\n
      if (!change) return;\n
    }\n
\n
    // Possibly split or suppress the update based on the presence\n
    // of read-only spans in its range.\n
    var split = sawReadOnlySpans && !ignoreReadOnly && removeReadOnlyRanges(doc, change.from, change.to);\n
    if (split) {\n
      for (var i = split.length - 1; i >= 0; --i)\n
        makeChangeInner(doc, {from: split[i].from, to: split[i].to, text: i ? [""] : change.text});\n
    } else {\n
      makeChangeInner(doc, change);\n
    }\n
  }\n
\n
  function makeChangeInner(doc, change) {\n
    if (change.text.length == 1 && change.text[0] == "" && cmp(change.from, change.to) == 0) return;\n
    var selAfter = computeSelAfterChange(doc, change);\n
    addChangeToHistory(doc, change, selAfter, doc.cm ? doc.cm.curOp.id : NaN);\n
\n
    makeChangeSingleDoc(doc, change, selAfter, stretchSpansOverChange(doc, change));\n
    var rebased = [];\n
\n
    linkedDocs(doc, function(doc, sharedHist) {\n
      if (!sharedHist && indexOf(rebased, doc.history) == -1) {\n
        rebaseHist(doc.history, change);\n
        rebased.push(doc.history);\n
      }\n
      makeChangeSingleDoc(doc, change, null, stretchSpansOverChange(doc, change));\n
    });\n
  }\n
\n
  // Revert a change stored in a document\'s history.\n
  function makeChangeFromHistory(doc, type, allowSelectionOnly) {\n
    if (doc.cm && doc.cm.state.suppressEdits) return;\n
\n
    var hist = doc.history, event, selAfter = doc.sel;\n
    var source = type == "undo" ? hist.done : hist.undone, dest = type == "undo" ? hist.undone : hist.done;\n
\n
    // Verify that there is a useable event (so that ctrl-z won\'t\n
    // needlessly clear selection events)\n
    for (var i = 0; i < source.length; i++) {\n
      event = source[i];\n
      if (allowSelectionOnly ? event.ranges && !event.equals(doc.sel) : !event.ranges)\n
        break;\n
    }\n
    if (i == source.length) return;\n
    hist.lastOrigin = hist.lastSelOrigin = null;\n
\n
    for (;;) {\n
      event = source.pop();\n
      if (event.ranges) {\n
        pushSelectionToHistory(event, dest);\n
        if (allowSelectionOnly && !event.equals(doc.sel)) {\n
          setSelection(doc, event, {clearRedo: false});\n
          return;\n
        }\n
        selAfter = event;\n
      }\n
      else break;\n
    }\n
\n
    // Build up a reverse change object to add to the opposite history\n
    // stack (redo when undoing, and vice versa).\n
    var antiChanges = [];\n
    pushSelectionToHistory(selAfter, dest);\n
    dest.push({changes: antiChanges, generation: hist.generation});\n
    hist.generation = event.generation || ++hist.maxGeneration;\n
\n
    var filter = hasHandler(doc, "beforeChange") || doc.cm && hasHandler(doc.cm, "beforeChange");\n
\n
    for (var i = event.changes.length - 1; i >= 0; --i) {\n
      var change = event.changes[i];\n
      change.origin = type;\n
      if (filter && !filterChange(doc, change, false)) {\n
        source.length = 0;\n
        return;\n
      }\n
\n
      antiChanges.push(historyChangeFromChange(doc, change));\n
\n
      var after = i ? computeSelAfterChange(doc, change) : lst(source);\n
      makeChangeSingleDoc(doc, change, after, mergeOldSpans(doc, change));\n
      if (!i && doc.cm) doc.cm.scrollIntoView({from: change.from, to: changeEnd(change)});\n
      var rebased = [];\n
\n
      // Propagate to the linked documents\n
      linkedDocs(doc, function(doc, sharedHist) {\n
        if (!sharedHist && indexOf(rebased, doc.history) == -1) {\n
          rebaseHist(doc.history, change);\n
          rebased.push(doc.history);\n
        }\n
        makeChangeSingleDoc(doc, change, null, mergeOldSpans(doc, change));\n
      });\n
    }\n
  }\n
\n
  // Sub-views need their line numbers shifted when text is added\n
  // above or below them in the parent document.\n
  function shiftDoc(doc, distance) {\n
    if (distance == 0) return;\n
    doc.first += distance;\n
    doc.sel = new Selection(map(doc.sel.ranges, function(range) {\n
      return new Range(Pos(range.anchor.line + distance, range.anchor.ch),\n
                       Pos(range.head.line + distance, range.head.ch));\n
    }), doc.sel.primIndex);\n
    if (doc.cm) {\n
      regChange(doc.cm, doc.first, doc.first - distance, distance);\n
      for (var d = doc.cm.display, l = d.viewFrom; l < d.viewTo; l++)\n
        regLineChange(doc.cm, l, "gutter");\n
    }\n
  }\n
\n
  // More lower-level change function, handling only a single document\n
  // (not linked ones).\n
  function makeChangeSingleDoc(doc, change, selAfter, spans) {\n
    if (doc.cm && !doc.cm.curOp)\n
      return operation(doc.cm, makeChangeSingleDoc)(doc, change, selAfter, spans);\n
\n
    if (change.to.line < doc.first) {\n
      shiftDoc(doc, change.text.length - 1 - (change.to.line - change.from.line));\n
      return;\n
    }\n
    if (change.from.line > doc.lastLine()) return;\n
\n
    // Clip the change to the size of this doc\n
    if (change.from.line < doc.first) {\n
      var shift = change.text.length - 1 - (doc.first - change.from.line);\n
      shiftDoc(doc, shift);\n
      change = {from: Pos(doc.first, 0), to: Pos(change.to.line + shift, change.to.ch),\n
                text: [lst(change.text)], origin: change.origin};\n
    }\n
    var last = doc.lastLine();\n
    if (change.to.line > last) {\n
      change = {from: change.from, to: Pos(last, getLine(doc, last).text.length),\n
                text: [change.text[0]], origin: change.origin};\n
    }\n
\n
    change.removed = getBetween(doc, change.from, change.to);\n
\n
    if (!selAfter) selAfter = computeSelAfterChange(doc, change);\n
    if (doc.cm) makeChangeSingleDocInEditor(doc.cm, change, spans);\n
    else updateDoc(doc, change, spans);\n
    setSelectionNoUndo(doc, selAfter, sel_dontScroll);\n
  }\n
\n
  // Handle the interaction of a change to a document with the editor\n
  // that this document is part of.\n
  function makeChangeSingleDocInEditor(cm, change, spans) {\n
    var doc = cm.doc, display = cm.display, from = change.from, to = change.to;\n
\n
    var recomputeMaxLength = false, checkWidthStart = from.line;\n
    if (!cm.options.lineWrapping) {\n
      checkWidthStart = lineNo(visualLine(getLine(doc, from.line)));\n
      doc.iter(checkWidthStart, to.line + 1, function(line) {\n
        if (line == display.maxLine) {\n
          recomputeMaxLength = true;\n
          return true;\n
        }\n
      });\n
    }\n
\n
    if (doc.sel.contains(change.from, change.to) > -1)\n
      signalCursorActivity(cm);\n
\n
    updateDoc(doc, change, spans, estimateHeight(cm));\n
\n
    if (!cm.options.lineWrapping) {\n
      doc.iter(checkWidthStart, from.line + change.text.length, function(line) {\n
        var len = lineLength(line);\n
        if (len > display.maxLineLength) {\n
          display.maxLine = line;\n
          display.maxLineLength = len;\n
          display.maxLineChanged = true;\n
          recomputeMaxLength = false;\n
        }\n
      });\n
      if (recomputeMaxLength) cm.curOp.updateMaxLine = true;\n
    }\n
\n
    // Adjust frontier, schedule worker\n
    doc.frontier = Math.min(doc.frontier, from.line);\n
    startWorker(cm, 400);\n
\n
    var lendiff = change.text.length - (to.line - from.line) - 1;\n
    // Remember that these lines changed, for updating the display\n
    if (change.full)\n
      regChange(cm);\n
    else if (from.line == to.line && change.text.length == 1 && !isWholeLineUpdate(cm.doc, change))\n
      regLineChange(cm, from.line, "text");\n
    else\n
      regChange(cm, from.line, to.line + 1, lendiff);\n
\n
    var changesHandler = hasHandler(cm, "changes"), changeHandler = hasHandler(cm, "change");\n
    if (changeHandler || changesHandler) {\n
      var obj = {\n
        from: from, to: to,\n
        text: change.text,\n
        removed: change.removed,\n
        origin: change.origin\n
      };\n
      if (changeHandler) signalLater(cm, "change", cm, obj);\n
      if (changesHandler) (cm.curOp.changeObjs || (cm.curOp.changeObjs = [])).push(obj);\n
    }\n
    cm.display.selForContextMenu = null;\n
  }\n
\n
  function replaceRange(doc, code, from, to, origin) {\n
    if (!to) to = from;\n
    if (cmp(to, from) < 0) { var tmp = to; to = from; from = tmp; }\n
    if (typeof code == "string") code = doc.splitLines(code);\n
    makeChange(doc, {from: from, to: to, text: code, origin: origin});\n
  }\n
\n
  // SCROLLING THINGS INTO VIEW\n
\n
  // If an editor sits on the top or bottom of the window, partially\n
  // scrolled out of view, this ensures that the cursor is visible.\n
  function maybeScrollWindow(cm, coords) {\n
    if (signalDOMEvent(cm, "scrollCursorIntoView")) return;\n
\n
    var display = cm.display, box = display.sizer.getBoundingClientRect(), doScroll = null;\n
    if (coords.top + box.top < 0) doScroll = true;\n
    else if (coords.bottom + box.top > (window.innerHeight || document.documentElement.clientHeight)) doScroll = false;\n
    if (doScroll != null && !phantom) {\n
      var scrollNode = elt("div", "\\u200b", null, "position: absolute; top: " +\n
                           (coords.top - display.viewOffset - paddingTop(cm.display)) + "px; height: " +\n
                           (coords.bottom - coords.top + scrollGap(cm) + display.barHeight) + "px; left: " +\n
                           coords.left + "px; width: 2px;");\n
      cm.display.lineSpace.appendChild(scrollNode);\n
      scrollNode.scrollIntoView(doScroll);\n
      cm.display.lineSpace.removeChild(scrollNode);\n
    }\n
  }\n
\n
  // Scroll a given position into view (immediately), verifying that\n
  // it actually became visible (as line heights are accurately\n
  // measured, the position of something may \'drift\' during drawing).\n
  function scrollPosIntoView(cm, pos, end, margin) {\n
    if (margin == null) margin = 0;\n
    for (var limit = 0; limit < 5; limit++) {\n
      var changed = false, coords = cursorCoords(cm, pos);\n
      var endCoords = !end || end == pos ? coords : cursorCoords(cm, end);\n
      var scrollPos = calculateScrollPos(cm, Math.min(coords.left, endCoords.left),\n
                                         Math.min(coords.top, endCoords.top) - margin,\n
                                         Math.max(coords.left, endCoords.left),\n
                                         Math.max(coords.bottom, endCoords.bottom) + margin);\n
      var startTop = cm.doc.scrollTop, startLeft = cm.doc.scrollLeft;\n
      if (scrollPos.scrollTop != null) {\n
        setScrollTop(cm, scrollPos.scrollTop);\n
        if (Math.abs(cm.doc.scrollTop - startTop) > 1) changed = true;\n
      }\n
      if (scrollPos.scrollLeft != null) {\n
        setScrollLeft(cm, scrollPos.scrollLeft);\n
        if (Math.abs(cm.doc.scrollLeft - startLeft) > 1) changed = true;\n
      }\n
      if (!changed) break;\n
    }\n
    return coords;\n
  }\n
\n
  // Scroll a given set of coordinates into view (immediately).\n
  function scrollIntoView(cm, x1, y1, x2, y2) {\n
    var scrollPos = calculateScrollPos(cm, x1, y1, x2, y2);\n
    if (scrollPos.scrollTop != null) setScrollTop(cm, scrollPos.scrollTop);\n
    if (scrollPos.scrollLeft != null) setScrollLeft(cm, scrollPos.scrollLeft);\n
  }\n
\n
  // Calculate a new scroll position needed to scroll the given\n
  // rectangle into view. Returns an object with scrollTop and\n
  // scrollLeft properties. When these are undefined, the\n
  // vertical/horizontal position does not need to be adjusted.\n
  function calculateScrollPos(cm, x1, y1, x2, y2) {\n
    var display = cm.display, snapMargin = textHeight(cm.display);\n
    if (y1 < 0) y1 = 0;\n
    var screentop = cm.curOp && cm.curOp.scrollTop != null ? cm.curOp.scrollTop : display.scroller.scrollTop;\n
    var screen = displayHeight(cm), result = {};\n
    if (y2 - y1 > screen) y2 = y1 + screen;\n
    var docBottom = cm.doc.height + paddingVert(display);\n
    var atTop = y1 < snapMargin, atBottom = y2 > docBottom - snapMargin;\n
    if (y1 < screentop) {\n
      result.scrollTop = atTop ? 0 : y1;\n
    } else if (y2 > screentop + screen) {\n
      var newTop = Math.min(y1, (atBottom ? docBottom : y2) - screen);\n
      if (newTop != screentop) result.scrollTop = newTop;\n
    }\n
\n
    var screenleft = cm.curOp && cm.curOp.scrollLeft != null ? cm.curOp.scrollLeft : display.scroller.scrollLeft;\n
    var screenw = displayWidth(cm) - (cm.options.fixedGutter ? display.gutters.offsetWidth : 0);\n
    var tooWide = x2 - x1 > screenw;\n
    if (tooWide) x2 = x1 + screenw;\n
    if (x1 < 10)\n
      result.scrollLeft = 0;\n
    else if (x1 < screenleft)\n
      result.scrollLeft = Math.max(0, x1 - (tooWide ? 0 : 10));\n
    else if (x2 > screenw + screenleft - 3)\n
      result.scrollLeft = x2 + (tooWide ? 0 : 10) - screenw;\n
    return result;\n
  }\n
\n
  // Store a relative adjustment to the scroll position in the current\n
  // operation (to be applied when the operation finishes).\n
  function addToScrollPos(cm, left, top) {\n
    if (left != null || top != null) resolveScrollToPos(cm);\n
    if (left != null)\n
      cm.curOp.scrollLeft = (cm.curOp.scrollLeft == null ? cm.doc.scrollLeft : cm.curOp.scrollLeft) + left;\n
    if (top != null)\n
      cm.curOp.scrollTop = (cm.curOp.scrollTop == null ? cm.doc.scrollTop : cm.curOp.scrollTop) + top;\n
  }\n
\n
  // Make sure that at the end of the operation the current cursor is\n
  // shown.\n
  function ensureCursorVisible(cm) {\n
    resolveScrollToPos(cm);\n
    var cur = cm.getCursor(), from = cur, to = cur;\n
    if (!cm.options.lineWrapping) {\n
      from = cur.ch ? Pos(cur.line, cur.ch - 1) : cur;\n
      to = Pos(cur.line, cur.ch + 1);\n
    }\n
    cm.curOp.scrollToPos = {from: from, to: to, margin: cm.options.cursorScrollMargin, isCursor: true};\n
  }\n
\n
  // When an operation has its scrollToPos property set, and another\n
  // scroll action is applied before the end of the operation, this\n
  // \'simulates\' scrolling that position into view in a cheap way, so\n
  // that the effect of intermediate scroll commands is not ignored.\n
  function resolveScrollToPos(cm) {\n
    var range = cm.curOp.scrollToPos;\n
    if (range) {\n
      cm.curOp.scrollToPos = null;\n
      var from = estimateCoords(cm, range.from), to = estimateCoords(cm, range.to);\n
      var sPos = calculateScrollPos(cm, Math.min(from.left, to.left),\n
                                    Math.min(from.top, to.top) - range.margin,\n
                                    Math.max(from.right, to.right),\n
                                    Math.max(from.bottom, to.bottom) + range.margin);\n
      cm.scrollTo(sPos.scrollLeft, sPos.scrollTop);\n
    }\n
  }\n
\n
  // API UTILITIES\n
\n
  // Indent the given line. The how parameter can be "smart",\n
  // "add"/null, "subtract", or "prev". When aggressive is false\n
  // (typically set to true for forced single-line indents), empty\n
  // lines are not indented, and places where the mode returns Pass\n
  // are left alone.\n
  function indentLine(cm, n, how, aggressive) {\n
    var doc = cm.doc, state;\n
    if (how == null) how = "add";\n
    if (how == "smart") {\n
      // Fall back to "prev" when the mode doesn\'t have an indentation\n
      // method.\n
      if (!doc.mode.indent) how = "prev";\n
      else state = getStateBefore(cm, n);\n
    }\n
\n
    var tabSize = cm.options.tabSize;\n
    var line = getLine(doc, n), curSpace = countColumn(line.text, null, tabSize);\n
    if (line.stateAfter) line.stateAfter = null;\n
    var curSpaceString = line.text.match(/^\\s*/)[0], indentation;\n
    if (!aggressive && !/\\S/.test(line.text)) {\n
      indentation = 0;\n
      how = "not";\n
    } else if (how == "smart") {\n
      indentation = doc.mode.indent(state, line.text.slice(curSpaceString.length), line.text);\n
      if (indentation == Pass || indentation > 150) {\n
        if (!aggressive) return;\n
        how = "prev";\n
      }\n
    }\n
    if (how == "prev") {\n
      if (n > doc.first) indentation = countColumn(getLine(doc, n-1).text, null, tabSize);\n
      else indentation = 0;\n
    } else if (how == "add") {\n
      indentation = curSpace + cm.options.indentUnit;\n
    } else if (how == "subtract") {\n
      indentation = curSpace - cm.options.indentUnit;\n
    } else if (typeof how == "number") {\n
      indentation = curSpace + how;\n
    }\n
    indentation = Math.max(0, indentation);\n
\n
    var indentString = "", pos = 0;\n
    if (cm.options.indentWithTabs)\n
      for (var i = Math.floor(indentation / tabSize); i; --i) {pos += tabSize; indentString += "\\t";}\n
    if (pos < indentation) indentString += spaceStr(indentation - pos);\n
\n
    if (indentString != curSpaceString) {\n
      replaceRange(doc, indentString, Pos(n, 0), Pos(n, curSpaceString.length), "+input");\n
      line.stateAfter = null;\n
      return true;\n
    } else {\n
      // Ensure that, if the cursor was in the whitespace at the start\n
      // of the line, it is moved to the end of that space.\n
      for (var i = 0; i < doc.sel.ranges.length; i++) {\n
        var range = doc.sel.ranges[i];\n
        if (range.head.line == n && range.head.ch < curSpaceString.length) {\n
          var pos = Pos(n, curSpaceString.length);\n
          replaceOneSelection(doc, i, new Range(pos, pos));\n
          break;\n
        }\n
      }\n
    }\n
  }\n
\n
  // Utility for applying a change to a line by handle or number,\n
  // returning the number and optionally registering the line as\n
  // changed.\n
  function changeLine(doc, handle, changeType, op) {\n
    var no = handle, line = handle;\n
    if (typeof handle == "number") line = getLine(doc, clipLine(doc, handle));\n
    else no = lineNo(handle);\n
    if (no == null) return null;\n
    if (op(line, no) && doc.cm) regLineChange(doc.cm, no, changeType);\n
    return line;\n
  }\n
\n
  // Helper for deleting text near the selection(s), used to implement\n
  // backspace, delete, and similar functionality.\n
  function deleteNearSelection(cm, compute) {\n
    var ranges = cm.doc.sel.ranges, kill = [];\n
    // Build up a set of ranges to kill first, merging overlapping\n
    // ranges.\n
    for (var i = 0; i < ranges.length; i++) {\n
      var toKill = compute(ranges[i]);\n
      while (kill.length && cmp(toKill.from, lst(kill).to) <= 0) {\n
        var replaced = kill.pop();\n
        if (cmp(replaced.from, toKill.from) < 0) {\n
          toKill.from = replaced.from;\n
          break;\n
        }\n
      }\n
      kill.push(toKill);\n
    }\n
    // Next, remove those actual ranges.\n
    runInOp(cm, function() {\n
      for (var i = kill.length - 1; i >= 0; i--)\n
        replaceRange(cm.doc, "", kill[i].from, kill[i].to, "+delete");\n
      ensureCursorVisible(cm);\n
    });\n
  }\n
\n
  // Used for horizontal relative motion. Dir is -1 or 1 (left or\n
  // right), unit can be "char", "column" (like char, but doesn\'t\n
  // cross line boundaries), "word" (across next word), or "group" (to\n
  // the start of next group of word or non-word-non-whitespace\n
  // chars). The visually param controls whether, in right-to-left\n
  // text, direction 1 means to move towards the next index in the\n
  // string, or towards the character to the right of the current\n
  // position. The resulting position will have a hitSide=true\n
  // property if it reached the end of the document.\n
  function findPosH(doc, pos, dir, unit, visually) {\n
    var line = pos.line, ch = pos.ch, origDir = dir;\n
    var lineObj = getLine(doc, line);\n
    var possible = true;\n
    function findNextLine() {\n
      var l = line + dir;\n
      if (l < doc.first || l >= doc.first + doc.size) return (possible = false);\n
      line = l;\n
      return lineObj = getLine(doc, l);\n
    }\n
    function moveOnce(boundToLine) {\n
      var next = (visually ? moveVisually : moveLogically)(lineObj, ch, dir, true);\n
      if (next == null) {\n
        if (!boundToLine && findNextLine()) {\n
          if (visually) ch = (dir < 0 ? lineRight : lineLeft)(lineObj);\n
          else ch = dir < 0 ? lineObj.text.length : 0;\n
        } else return (possible = false);\n
      } else ch = next;\n
      return true;\n
    }\n
\n
    if (unit == "char") moveOnce();\n
    else if (unit == "column") moveOnce(true);\n
    else if (unit == "word" || unit == "group") {\n
      var sawType = null, group = unit == "group";\n
      var helper = doc.cm && doc.cm.getHelper(pos, "wordChars");\n
      for (var first = true;; first = false) {\n
        if (dir < 0 && !moveOnce(!first)) break;\n
        var cur = lineObj.text.charAt(ch) || "\\n";\n
        var type = isWordChar(cur, helper) ? "w"\n
          : group && cur == "\\n" ? "n"\n
          : !group || /\\s/.test(cur) ? null\n
          : "p";\n
        if (group && !first && !type) type = "s";\n
        if (sawType && sawType != type) {\n
          if (dir < 0) {dir = 1; moveOnce();}\n
          break;\n
        }\n
\n
        if (type) sawType = type;\n
        if (dir > 0 && !moveOnce(!first)) break;\n
      }\n
    }\n
    var result = skipAtomic(doc, Pos(line, ch), pos, origDir, true);\n
    if (!possible) result.hitSide = true;\n
    return result;\n
  }\n
\n
  // For relative vertical movement. Dir may be -1 or 1. Unit can be\n
  // "page" or "line". The resulting position will have a hitSide=true\n
  // property if it reached the end of the document.\n
  function findPosV(cm, pos, dir, unit) {\n
    var doc = cm.doc, x = pos.left, y;\n
    if (unit == "page") {\n
      var pageSize = Math.min(cm.display.wrapper.clientHeight, window.innerHeight || document.documentElement.clientHeight);\n
      y = pos.top + dir * (pageSize - (dir < 0 ? 1.5 : .5) * textHeight(cm.display));\n
    } else if (unit == "line") {\n
      y = dir > 0 ? pos.bottom + 3 : pos.top - 3;\n
    }\n
    for (;;) {\n
      var target = coordsChar(cm, x, y);\n
      if (!target.outside) break;\n
      if (dir < 0 ? y <= 0 : y >= doc.height) { target.hitSide = true; break; }\n
      y += dir * 5;\n
    }\n
    return target;\n
  }\n
\n
  // EDITOR METHODS\n
\n
  // The publicly visible API. Note that methodOp(f) means\n
  // \'wrap f in an operation, performed on its `this` parameter\'.\n
\n
  // This is not the complete set of editor methods. Most of the\n
  // methods defined on the Doc type are also injected into\n
  // CodeMirror.prototype, for backwards compatibility and\n
  // convenience.\n
\n
  CodeMirror.prototype = {\n
    constructor: CodeMirror,\n
    focus: function(){window.focus(); this.display.input.focus();},\n
\n
    setOption: function(option, value) {\n
      var options = this.options, old = options[option];\n
      if (options[option] == value && option != "mode") return;\n
      options[option] = value;\n
      if (optionHandlers.hasOwnProperty(option))\n
        operation(this, optionHandlers[option])(this, value, old);\n
    },\n
\n
    getOption: function(option) {return this.options[option];},\n
    getDoc: function() {return this.doc;},\n
\n
    addKeyMap: function(map, bottom) {\n
      this.state.keyMaps[bottom ? "push" : "unshift"](getKeyMap(map));\n
    },\n
    removeKeyMap: function(map) {\n
      var maps = this.state.keyMaps;\n
      for (var i = 0; i < maps.length; ++i)\n
        if (maps[i] == map || maps[i].name == map) {\n
          maps.splice(i, 1);\n
          return true;\n
        }\n
    },\n
\n
    addOverlay: methodOp(function(spec, options) {\n
      var mode = spec.token ? spec : CodeMirror.getMode(this.options, spec);\n
      if (mode.startState) throw new Error("Overlays may not be stateful.");\n
      this.state.overlays.push({mode: mode, modeSpec: spec, opaque: options && options.opaque});\n
      this.state.modeGen++;\n
      regChange(this);\n
    }),\n
    removeOverlay: methodOp(function(spec) {\n
      var overlays = this.state.overlays;\n
      for (var i = 0; i < overlays.length; ++i) {\n
        var cur = overlays[i].modeSpec;\n
        if (cur == spec || typeof spec == "string" && cur.name == spec) {\n
          overlays.splice(i, 1);\n
          this.state.modeGen++;\n
          regChange(this);\n
          return;\n
        }\n
      }\n
    }),\n
\n
    indentLine: methodOp(function(n, dir, aggressive) {\n
      if (typeof dir != "string" && typeof dir != "number") {\n
        if (dir == null) dir = this.options.smartIndent ? "smart" : "prev";\n
        else dir = dir ? "add" : "subtract";\n
      }\n
      if (isLine(this.doc, n)) indentLine(this, n, dir, aggressive);\n
    }),\n
    indentSelection: methodOp(function(how) {\n
      var ranges = this.doc.sel.ranges, end = -1;\n
      for (var i = 0; i < ranges.length; i++) {\n
        var range = ranges[i];\n
        if (!range.empty()) {\n
          var from = range.from(), to = range.to();\n
          var start = Math.max(end, from.line);\n
          end = Math.min(this.lastLine(), to.line - (to.ch ? 0 : 1)) + 1;\n
          for (var j = start; j < end; ++j)\n
            indentLine(this, j, how);\n
          var newRanges = this.doc.sel.ranges;\n
          if (from.ch == 0 && ranges.length == newRanges.length && newRanges[i].from().ch > 0)\n
            replaceOneSelection(this.doc, i, new Range(from, newRanges[i].to()), sel_dontScroll);\n
        } else if (range.head.line > end) {\n
          indentLine(this, range.head.line, how, true);\n
          end = range.head.line;\n
          if (i == this.doc.sel.primIndex) ensureCursorVisible(this);\n
        }\n
      }\n
    }),\n
\n
    // Fetch the parser token for a given character. Useful for hacks\n
    // that want to inspect the mode state (say, for completion).\n
    getTokenAt: function(pos, precise) {\n
      return takeToken(this, pos, precise);\n
    },\n
\n
    getLineTokens: function(line, precise) {\n
      return takeToken(this, Pos(line), precise, true);\n
    },\n
\n
    getTokenTypeAt: function(pos) {\n
      pos = clipPos(this.doc, pos);\n
      var styles = getLineStyles(this, getLine(this.doc, pos.line));\n
      var before = 0, after = (styles.length - 1) / 2, ch = pos.ch;\n
      var type;\n
      if (ch == 0) type = styles[2];\n
      else for (;;) {\n
        var mid = (before + after) >> 1;\n
        if ((mid ? styles[mid * 2 - 1] : 0) >= ch) after = mid;\n
        else if (styles[mid * 2 + 1] < ch) before = mid + 1;\n
        else { type = styles[mid * 2 + 2]; break; }\n
      }\n
      var cut = type ? type.indexOf("cm-overlay ") : -1;\n
      return cut < 0 ? type : cut == 0 ? null : type.slice(0, cut - 1);\n
    },\n
\n
    getModeAt: function(pos) {\n
      var mode = this.doc.mode;\n
      if (!mode.innerMode) return mode;\n
      return CodeMirror.innerMode(mode, this.getTokenAt(pos).state).mode;\n
    },\n
\n
    getHelper: function(pos, type) {\n
      return this.getHelpers(pos, type)[0];\n
    },\n
\n
    getHelpers: function(pos, type) {\n
      var found = [];\n
      if (!helpers.hasOwnProperty(type)) return found;\n
      var help = helpers[type], mode = this.getModeAt(pos);\n
      if (typeof mode[type] == "string") {\n
        if (help[mode[type]]) found.push(help[mode[type]]);\n
      } else if (mode[type]) {\n
        for (var i = 0; i < mode[type].length; i++) {\n
          var val = help[mode[type][i]];\n
          if (val) found.push(val);\n
        }\n
      } else if (mode.helperType && help[mode.helperType]) {\n
        found.push(help[mode.helperType]);\n
      } else if (help[mode.name]) {\n
        found.push(help[mode.name]);\n
      }\n
      for (var i = 0; i < help._global.length; i++) {\n
        var cur = help._global[i];\n
        if (cur.pred(mode, this) && indexOf(found, cur.val) == -1)\n
          found.push(cur.val);\n
      }\n
      return found;\n
    },\n
\n
    getStateAfter: function(line, precise) {\n
      var doc = this.doc;\n
      line = clipLine(doc, line == null ? doc.first + doc.size - 1: line);\n
      return getStateBefore(this, line + 1, precise);\n
    },\n
\n
    cursorCoords: function(start, mode) {\n
      var pos, range = this.doc.sel.primary();\n
      if (start == null) pos = range.head;\n
      else if (typeof start == "object") pos = clipPos(this.doc, start);\n
      else pos = start ? range.from() : range.to();\n
      return cursorCoords(this, pos, mode || "page");\n
    },\n
\n
    charCoords: function(pos, mode) {\n
      return charCoords(this, clipPos(this.doc, pos), mode || "page");\n
    },\n
\n
    coordsChar: function(coords, mode) {\n
      coords = fromCoordSystem(this, coords, mode || "page");\n
      return coordsChar(this, coords.left, coords.top);\n
    },\n
\n
    lineAtHeight: function(height, mode) {\n
      height = fromCoordSystem(this, {top: height, left: 0}, mode || "page").top;\n
      return lineAtHeight(this.doc, height + this.display.viewOffset);\n
    },\n
    heightAtLine: function(line, mode) {\n
      var end = false, lineObj;\n
      if (typeof line == "number") {\n
        var last = this.doc.first + this.doc.size - 1;\n
        if (line < this.doc.first) line = this.doc.first;\n
        else if (line > last) { line = last; end = true; }\n
        lineObj = getLine(this.doc, line);\n
      } else {\n
        lineObj = line;\n
      }\n
      return intoCoordSystem(this, lineObj, {top: 0, left: 0}, mode || "page").top +\n
        (end ? this.doc.height - heightAtLine(lineObj) : 0);\n
    },\n
\n
    defaultTextHeight: function() { return textHeight(this.display); },\n
    defaultCharWidth: function() { return charWidth(this.display); },\n
\n
    setGutterMarker: methodOp(function(line, gutterID, value) {\n
      return changeLine(this.doc, line, "gutter", function(line) {\n
        var markers = line.gutterMarkers || (line.gutterMarkers = {});\n
        markers[gutterID] = value;\n
        if (!value && isEmpty(markers)) line.gutterMarkers = null;\n
        return true;\n
      });\n
    }),\n
\n
    clearGutter: methodOp(function(gutterID) {\n
      var cm = this, doc = cm.doc, i = doc.first;\n
      doc.iter(function(line) {\n
        if (line.gutterMarkers && line.gutterMarkers[gutterID]) {\n
          line.gutterMarkers[gutterID] = null;\n
          regLineChange(cm, i, "gutter");\n
          if (isEmpty(line.gutterMarkers)) line.gutterMarkers = null;\n
        }\n
        ++i;\n
      });\n
    }),\n
\n
    lineInfo: function(line) {\n
      if (typeof line == "number") {\n
        if (!isLine(this.doc, line)) return null;\n
        var n = line;\n
        line = getLine(this.doc, line);\n
        if (!line) return null;\n
      } else {\n
        var n = lineNo(line);\n
        if (n == null) return null;\n
      }\n
      return {line: n, handle: line, text: line.text, gutterMarkers: line.gutterMarkers,\n
              textClass: line.textClass, bgClass: line.bgClass, wrapClass: line.wrapClass,\n
              widgets: line.widgets};\n
    },\n
\n
    getViewport: function() { return {from: this.display.viewFrom, to: this.display.viewTo};},\n
\n
    addWidget: function(pos, node, scroll, vert, horiz) {\n
      var display = this.display;\n
      pos = cursorCoords(this, clipPos(this.doc, pos));\n
      var top = pos.bottom, left = pos.left;\n
      node.style.position = "absolute";\n
      node.setAttribute("cm-ignore-events", "true");\n
      this.display.input.setUneditable(node);\n
      display.sizer.appendChild(node);\n
      if (vert == "over") {\n
        top = pos.top;\n
      } else if (vert == "above" || vert == "near") {\n
        var vspace = Math.max(display.wrapper.clientHeight, this.doc.height),\n
        hspace = Math.max(display.sizer.clientWidth, display.lineSpace.clientWidth);\n
        // Default to positioning above (if specified and possible); otherwise default to positioning below\n
        if ((vert == \'above\' || pos.bottom + node.offsetHeight > vspace) && pos.top > node.offsetHeight)\n
          top = pos.top - node.offsetHeight;\n
        else if (pos.bottom + node.offsetHeight <= vspace)\n
          top = pos.bottom;\n
        if (left + node.offsetWidth > hspace)\n
          left = hspace - node.offsetWidth;\n
      }\n
      node.style.top = top + "px";\n
      node.style.left = node.style.right = "";\n
      if (horiz == "right") {\n
        left = display.sizer.clientWidth - node.offsetWidth;\n
        node.style.right = "0px";\n
      } else {\n
        if (horiz == "left") left = 0;\n
        else if (horiz == "middle") left = (display.sizer.clientWidth - node.offsetWidth) / 2;\n
        node.style.left = left + "px";\n
      }\n
      if (scroll)\n
        scrollIntoView(this, left, top, left + node.offsetWidth, top + node.offsetHeight);\n
    },\n
\n
    triggerOnKeyDown: methodOp(onKeyDown),\n
    triggerOnKeyPress: methodOp(onKeyPress),\n
    triggerOnKeyUp: onKeyUp,\n
\n
    execCommand: function(cmd) {\n
      if (commands.hasOwnProperty(cmd))\n
        return commands[cmd].call(null, this);\n
    },\n
\n
    triggerElectric: methodOp(function(text) { triggerElectric(this, text); }),\n
\n
    findPosH: function(from, amount, unit, visually) {\n
      var dir = 1;\n
      if (amount < 0) { dir = -1; amount = -amount; }\n
      for (var i = 0, cur = clipPos(this.doc, from); i < amount; ++i) {\n
        cur = findPosH(this.doc, cur, dir, unit, visually);\n
        if (cur.hitSide) break;\n
      }\n
      return cur;\n
    },\n
\n
    moveH: methodOp(function(dir, unit) {\n
      var cm = this;\n
      cm.extendSelectionsBy(function(range) {\n
        if (cm.display.shift || cm.doc.extend || range.empty())\n
          return findPosH(cm.doc, range.head, dir, unit, cm.options.rtlMoveVisually);\n
        else\n
          return dir < 0 ? range.from() : range.to();\n
      }, sel_move);\n
    }),\n
\n
    deleteH: methodOp(function(dir, unit) {\n
      var sel = this.doc.sel, doc = this.doc;\n
      if (sel.somethingSelected())\n
        doc.replaceSelection("", null, "+delete");\n
      else\n
        deleteNearSelection(this, function(range) {\n
          var other = findPosH(doc, range.head, dir, unit, false);\n
          return dir < 0 ? {from: other, to: range.head} : {from: range.head, to: other};\n
        });\n
    }),\n
\n
    findPosV: function(from, amount, unit, goalColumn) {\n
      var dir = 1, x = goalColumn;\n
      if (amount < 0) { dir = -1; amount = -amount; }\n
      for (var i = 0, cur = clipPos(this.doc, from); i < amount; ++i) {\n
        var coords = cursorCoords(this, cur, "div");\n
        if (x == null) x = coords.left;\n
        else coords.left = x;\n
        cur = findPosV(this, coords, dir, unit);\n
        if (cur.hitSide) break;\n
      }\n
      return cur;\n
    },\n
\n
    moveV: methodOp(function(dir, unit) {\n
      var cm = this, doc = this.doc, goals = [];\n
      var collapse = !cm.display.shift && !doc.extend && doc.sel.somethingSelected();\n
      doc.extendSelectionsBy(function(range) {\n
        if (collapse)\n
          return dir < 0 ? range.from() : range.to();\n
        var headPos = cursorCoords(cm, range.head, "div");\n
        if (range.goalColumn != null) headPos.left = range.goalColumn;\n
        goals.push(headPos.left);\n
        var pos = findPosV(cm, headPos, dir, unit);\n
        if (unit == "page" && range == doc.sel.primary())\n
          addToScrollPos(cm, null, charCoords(cm, pos, "div").top - headPos.top);\n
        return pos;\n
      }, sel_move);\n
      if (goals.length) for (var i = 0; i < doc.sel.ranges.length; i++)\n
        doc.sel.ranges[i].goalColumn = goals[i];\n
    }),\n
\n
    // Find the word at the given position (as returned by coordsChar).\n
    findWordAt: function(pos) {\n
      var doc = this.doc, line = getLine(doc, pos.line).text;\n
      var start = pos.ch, end = pos.ch;\n
      if (line) {\n
        var helper = this.getHelper(pos, "wordChars");\n
        if ((pos.xRel < 0 || end == line.length) && start) --start; else ++end;\n
        var startChar = line.charAt(start);\n
        var check = isWordChar(startChar, helper)\n
          ? function(ch) { return isWordChar(ch, helper); }\n
          : /\\s/.test(startChar) ? function(ch) {return /\\s/.test(ch);}\n
          : function(ch) {return !/\\s/.test(ch) && !isWordChar(ch);};\n
        while (start > 0 && check(line.charAt(start - 1))) --start;\n
        while (end < line.length && check(line.charAt(end))) ++end;\n
      }\n
      return new Range(Pos(pos.line, start), Pos(pos.line, end));\n
    },\n
\n
    toggleOverwrite: function(value) {\n
      if (value != null && value == this.state.overwrite) return;\n
      if (this.state.overwrite = !this.state.overwrite)\n
        addClass(this.display.cursorDiv, "CodeMirror-overwrite");\n
      else\n
        rmClass(this.display.cursorDiv, "CodeMirror-overwrite");\n
\n
      signal(this, "overwriteToggle", this, this.state.overwrite);\n
    },\n
    hasFocus: function() { return this.display.input.getField() == activeElt(); },\n
    isReadOnly: function() { return !!(this.options.readOnly || this.doc.cantEdit); },\n
\n
    scrollTo: methodOp(function(x, y) {\n
      if (x != null || y != null) resolveScrollToPos(this);\n
      if (x != null) this.curOp.scrollLeft = x;\n
      if (y != null) this.curOp.scrollTop = y;\n
    }),\n
    getScrollInfo: function() {\n
      var scroller = this.display.scroller;\n
      return {left: scroller.scrollLeft, top: scroller.scrollTop,\n
              height: scroller.scrollHeight - scrollGap(this) - this.display.barHeight,\n
              width: scroller.scrollWidth - scrollGap(this) - this.display.barWidth,\n
              clientHeight: displayHeight(this), clientWidth: displayWidth(this)};\n
    },\n
\n
    scrollIntoView: methodOp(function(range, margin) {\n
      if (range == null) {\n
        range = {from: this.doc.sel.primary().head, to: null};\n
        if (margin == null) margin = this.options.cursorScrollMargin;\n
      } else if (typeof range == "number") {\n
        range = {from: Pos(range, 0), to: null};\n
      } else if (range.from == null) {\n
        range = {from: range, to: null};\n
      }\n
      if (!range.to) range.to = range.from;\n
      range.margin = margin || 0;\n
\n
      if (range.from.line != null) {\n
        resolveScrollToPos(this);\n
        this.curOp.scrollToPos = range;\n
      } else {\n
        var sPos = calculateScrollPos(this, Math.min(range.from.left, range.to.left),\n
                                      Math.min(range.from.top, range.to.top) - range.margin,\n
                                      Math.max(range.from.right, range.to.right),\n
                                      Math.max(range.from.bottom, range.to.bottom) + range.margin);\n
        this.scrollTo(sPos.scrollLeft, sPos.scrollTop);\n
      }\n
    }),\n
\n
    setSize: methodOp(function(width, height) {\n
      var cm = this;\n
      function interpret(val) {\n
        return typeof val == "number" || /^\\d+$/.test(String(val)) ? val + "px" : val;\n
      }\n
      if (width != null) cm.display.wrapper.style.width = interpret(width);\n
      if (height != null) cm.display.wrapper.style.height = interpret(height);\n
      if (cm.options.lineWrapping) clearLineMeasurementCache(this);\n
      var lineNo = cm.display.viewFrom;\n
      cm.doc.iter(lineNo, cm.display.viewTo, function(line) {\n
        if (line.widgets) for (var i = 0; i < line.widgets.length; i++)\n
          if (line.widgets[i].noHScroll) { regLineChange(cm, lineNo, "widget"); break; }\n
        ++lineNo;\n
      });\n
      cm.curOp.forceUpdate = true;\n
      signal(cm, "refresh", this);\n
    }),\n
\n
    operation: function(f){return runInOp(this, f);},\n
\n
    refresh: methodOp(function() {\n
      var oldHeight = this.display.cachedTextHeight;\n
      regChange(this);\n
      this.curOp.forceUpdate = true;\n
      clearCaches(this);\n
      this.scrollTo(this.doc.scrollLeft, this.doc.scrollTop);\n
      updateGutterSpace(this);\n
      if (oldHeight == null || Math.abs(oldHeight - textHeight(this.display)) > .5)\n
        estimateLineHeights(this);\n
      signal(this, "refresh", this);\n
    }),\n
\n
    swapDoc: methodOp(function(doc) {\n
      var old = this.doc;\n
      old.cm = null;\n
      attachDoc(this, doc);\n
      clearCaches(this);\n
      this.display.input.reset();\n
      this.scrollTo(doc.scrollLeft, doc.scrollTop);\n
      this.curOp.forceScroll = true;\n
      signalLater(this, "swapDoc", this, old);\n
      return old;\n
    }),\n
\n
    getInputField: function(){return this.display.input.getField();},\n
    getWrapperElement: function(){return this.display.wrapper;},\n
    getScrollerElement: function(){return this.display.scroller;},\n
    getGutterElement: function(){return this.display.gutters;}\n
  };\n
  eventMixin(CodeMirror);\n
\n
  // OPTION DEFAULTS\n
\n
  // The default configuration options.\n
  var defaults = CodeMirror.defaults = {};\n
  // Functions to run when options are changed.\n
  var optionHandlers = CodeMirror.optionHandlers = {};\n
\n
  function option(name, deflt, handle, notOnInit) {\n
    CodeMirror.defaults[name] = deflt;\n
    if (handle) optionHandlers[name] =\n
      notOnInit ? function(cm, val, old) {if (old != Init) handle(cm, val, old);} : handle;\n
  }\n
\n
  // Passed to option handlers when there is no old value.\n
  var Init = CodeMirror.Init = {toString: function(){return "CodeMirror.Init";}};\n
\n
  // These two are, on init, called from the constructor because they\n
  // have to be initialized before the editor can start at all.\n
  option("value", "", function(cm, val) {\n
    cm.setValue(val);\n
  }, true);\n
  option("mode", null, function(cm, val) {\n
    cm.doc.modeOption = val;\n
    loadMode(cm);\n
  }, true);\n
\n
  option("indentUnit", 2, loadMode, true);\n
  option("indentWithTabs", false);\n
  option("smartIndent", true);\n
  option("tabSize", 4, function(cm) {\n
    resetModeState(cm);\n
    clearCaches(cm);\n
    regChange(cm);\n
  }, true);\n
  option("lineSeparator", null, function(cm, val) {\n
    cm.doc.lineSep = val;\n
    if (!val) return;\n
    var newBreaks = [], lineNo = cm.doc.first;\n
    cm.doc.iter(function(line) {\n
      for (var pos = 0;;) {\n
        var found = line.text.indexOf(val, pos);\n
        if (found == -1) break;\n
        pos = found + val.length;\n
        newBreaks.push(Pos(lineNo, found));\n
      }\n
      lineNo++;\n
    });\n
    for (var i = newBreaks.length - 1; i >= 0; i--)\n
      replaceRange(cm.doc, val, newBreaks[i], Pos(newBreaks[i].line, newBreaks[i].ch + val.length))\n
  });\n
  option("specialChars", /[\\t\\u0000-\\u0019\\u00ad\\u200b-\\u200f\\u2028\\u2029\\ufeff]/g, function(cm, val, old) {\n
    cm.state.specialChars = new RegExp(val.source + (val.test("\\t") ? "" : "|\\t"), "g");\n
    if (old != CodeMirror.Init) cm.refresh();\n
  });\n
  option("specialCharPlaceholder", defaultSpecialCharPlaceholder, function(cm) {cm.refresh();}, true);\n
  option("electricChars", true);\n
  option("inputStyle", mobile ? "contenteditable" : "textarea", function() {\n
    throw new Error("inputStyle can not (yet) be changed in a running editor"); // FIXME\n
  }, true);\n
  option("rtlMoveVisually", !windows);\n
  option("wholeLineUpdateBefore", true);\n
\n
  option("theme", "default", function(cm) {\n
    themeChanged(cm);\n
    guttersChanged(cm);\n
  }, true);\n
  option("keyMap", "default", function(cm, val, old) {\n
    var next = getKeyMap(val);\n
    var prev = old != CodeMirror.Init && getKeyMap(old);\n
    if (prev && prev.detach) prev.detach(cm, next);\n
    if (next.attach) next.attach(cm, prev || null);\n
  });\n
  option("extraKeys", null);\n
\n
  option("lineWrapping", false, wrappingChanged, true);\n
  option("gutters", [], function(cm) {\n
    setGuttersForLineNumbers(cm.options);\n
    guttersChanged(cm);\n
  }, true);\n
  option("fixedGutter", true, function(cm, val) {\n
    cm.display.gutters.style.left = val ? compensateForHScroll(cm.display) + "px" : "0";\n
    cm.refresh();\n
  }, true);\n
  option("coverGutterNextToScrollbar", false, function(cm) {updateScrollbars(cm);}, true);\n
  option("scrollbarStyle", "native", function(cm) {\n
    initScrollbars(cm);\n
    updateScrollbars(cm);\n
    cm.display.scrollbars.setScrollTop(cm.doc.scrollTop);\n
    cm.display.scrollbars.setScrollLeft(cm.doc.scrollLeft);\n
  }, true);\n
  option("lineNumbers", false, function(cm) {\n
    setGuttersForLineNumbers(cm.options);\n
    guttersChanged(cm);\n
  }, true);\n
  option("firstLineNumber", 1, guttersChanged, true);\n
  option("lineNumberFormatter", function(integer) {return integer;}, guttersChanged, true);\n
  option("showCursorWhenSelecting", false, updateSelection, true);\n
\n
  option("resetSelectionOnContextMenu", true);\n
  option("lineWiseCopyCut", true);\n
\n
  option("readOnly", false, function(cm, val) {\n
    if (val == "nocursor") {\n
      onBlur(cm);\n
      cm.display.input.blur();\n
      cm.display.disabled = true;\n
    } else {\n
      cm.display.disabled = false;\n
    }\n
    cm.display.input.readOnlyChanged(val)\n
  });\n
  option("disableInput", false, function(cm, val) {if (!val) cm.display.input.reset();}, true);\n
  option("dragDrop", true, dragDropChanged);\n
  option("allowDropFileTypes", null);\n
\n
  option("cursorBlinkRate", 530);\n
  option("cursorScrollMargin", 0);\n
  option("cursorHeight", 1, updateSelection, true);\n
  option("singleCursorHeightPerLine", true, updateSelection, true);\n
  option("workTime", 100);\n
  option("workDelay", 100);\n
  option("flattenSpans", true, resetModeState, true);\n
  option("addModeClass", false, resetModeState, true);\n
  option("pollInterval", 100);\n
  option("undoDepth", 200, function(cm, val){cm.doc.history.undoDepth = val;});\n
  option("historyEventDelay", 1250);\n
  option("viewportMargin", 10, function(cm){cm.refresh();}, true);\n
  option("maxHighlightLength", 10000, resetModeState, true);\n
  option("moveInputWithCursor", true, function(cm, val) {\n
    if (!val) cm.display.input.resetPosition();\n
  });\n
\n
  option("tabindex", null, function(cm, val) {\n
    cm.display.input.getField().tabIndex = val || "";\n
  });\n
  option("autofocus", null);\n
\n
  // MODE DEFINITION AND QUERYING\n
\n
  // Known modes, by name and by MIME\n
  var modes = CodeMirror.modes = {}, mimeModes = CodeMirror.mimeModes = {};\n
\n
  // Extra arguments are stored as the mode\'s dependencies, which is\n
  // used by (legacy) mechanisms like loadmode.js to automatically\n
  // load a mode. (Preferred mechanism is the require/define calls.)\n
  CodeMirror.defineMode = function(name, mode) {\n
    if (!CodeMirror.defaults.mode && name != "null") CodeMirror.defaults.mode = name;\n
    if (arguments.length > 2)\n
      mode.dependencies = Array.prototype.slice.call(arguments, 2);\n
    modes[name] = mode;\n
  };\n
\n
  CodeMirror.defineMIME = function(mime, spec) {\n
    mimeModes[mime] = spec;\n
  };\n
\n
  // Given a MIME type, a {name, ...options} config object, or a name\n
  // string, return a mode config object.\n
  CodeMirror.resolveMode = function(spec) {\n
    if (typeof spec == "string" && mimeModes.hasOwnProperty(spec)) {\n
      spec = mimeModes[spec];\n
    } else if (spec && typeof spec.name == "string" && mimeModes.hasOwnProperty(spec.name)) {\n
      var found = mimeModes[spec.name];\n
      if (typeof found == "string") found = {name: found};\n
      spec = createObj(found, spec);\n
      spec.name = found.name;\n
    } else if (typeof spec == "string" && /^[\\w\\-]+\\/[\\w\\-]+\\+xml$/.test(spec)) {\n
      return CodeMirror.resolveMode("application/xml");\n
    }\n
    if (typeof spec == "string") return {name: spec};\n
    else return spec || {name: "null"};\n
  };\n
\n
  // Given a mode spec (anything that resolveMode accepts), find and\n
  // initialize an actual mode object.\n
  CodeMirror.getMode = function(options, spec) {\n
    var spec = CodeMirror.resolveMode(spec);\n
    var mfactory = modes[spec.name];\n
    if (!mfactory) return CodeMirror.getMode(options, "text/plain");\n
    var modeObj = mfactory(options, spec);\n
    if (modeExtensions.hasOwnProperty(spec.name)) {\n
      var exts = modeExtensions[spec.name];\n
      for (var prop in exts) {\n
        if (!exts.hasOwnProperty(prop)) continue;\n
        if (modeObj.hasOwnProperty(prop)) modeObj["_" + prop] = modeObj[prop];\n
        modeObj[prop] = exts[prop];\n
      }\n
    }\n
    modeObj.name = spec.name;\n
    if (spec.helperType) modeObj.helperType = spec.helperType;\n
    if (spec.modeProps) for (var prop in spec.modeProps)\n
      modeObj[prop] = spec.modeProps[prop];\n
\n
    return modeObj;\n
  };\n
\n
  // Minimal default mode.\n
  CodeMirror.defineMode("null", function() {\n
    return {token: function(stream) {stream.skipToEnd();}};\n
  });\n
  CodeMirror.defineMIME("text/plain", "null");\n
\n
  // This can be used to attach properties to mode objects from\n
  // outside the actual mode definition.\n
  var modeExtensions = CodeMirror.modeExtensions = {};\n
  CodeMirror.extendMode = function(mode, properties) {\n
    var exts = modeExtensions.hasOwnProperty(mode) ? modeExtensions[mode] : (modeExtensions[mode] = {});\n
    copyObj(properties, exts);\n
  };\n
\n
  // EXTENSIONS\n
\n
  CodeMirror.defineExtension = function(name, func) {\n
    CodeMirror.prototype[name] = func;\n
  };\n
  CodeMirror.defineDocExtension = function(name, func) {\n
    Doc.prototype[name] = func;\n
  };\n
  CodeMirror.defineOption = option;\n
\n
  var initHooks = [];\n
  CodeMirror.defineInitHook = function(f) {initHooks.push(f);};\n
\n
  var helpers = CodeMirror.helpers = {};\n
  CodeMirror.registerHelper = function(type, name, value) {\n
    if (!helpers.hasOwnProperty(type)) helpers[type] = CodeMirror[type] = {_global: []};\n
    helpers[type][name] = value;\n
  };\n
  CodeMirror.registerGlobalHelper = function(type, name, predicate, value) {\n
    CodeMirror.registerHelper(type, name, value);\n
    helpers[type]._global.push({pred: predicate, val: value});\n
  };\n
\n
  // MODE STATE HANDLING\n
\n
  // Utility functions for working with state. Exported because nested\n
  // modes need to do this for their inner modes.\n
\n
  var copyState = CodeMirror.copyState = function(mode, state) {\n
    if (state === true) return state;\n
    if (mode.copyState) return mode.copyState(state);\n
    var nstate = {};\n
    for (var n in state) {\n
      var val = state[n];\n
      if (val instanceof Array) val = val.concat([]);\n
      nstate[n] = val;\n
    }\n
    return nstate;\n
  };\n
\n
  var startState = CodeMirror.startState = function(mode, a1, a2) {\n
    return mode.startState ? mode.startState(a1, a2) : true;\n
  };\n
\n
  // Given a mode and a state (for that mode), find the inner mode and\n
  // state at the position that the state refers to.\n
  CodeMirror.innerMode = function(mode, state) {\n
    while (mode.innerMode) {\n
      var info = mode.innerMode(state);\n
      if (!info || info.mode == mode) break;\n
      state = info.state;\n
      mode = info.mode;\n
    }\n
    return info || {mode: mode, state: state};\n
  };\n
\n
  // STANDARD COMMANDS\n
\n
  // Commands are parameter-less actions that can be performed on an\n
  // editor, mostly used for keybindings.\n
  var commands = CodeMirror.commands = {\n
    selectAll: function(cm) {cm.setSelection(Pos(cm.firstLine(), 0), Pos(cm.lastLine()), sel_dontScroll);},\n
    singleSelection: function(cm) {\n
      cm.setSelection(cm.getCursor("anchor"), cm.getCursor("head"), sel_dontScroll);\n
    },\n
    killLine: function(cm) {\n
      deleteNearSelection(cm, function(range) {\n
        if (range.empty()) {\n
          var len = getLine(cm.doc, range.head.line).text.length;\n
          if (range.head.ch == len && range.head.line < cm.lastLine())\n
            return {from: range.head, to: Pos(range.head.line + 1, 0)};\n
          else\n
            return {from: range.head, to: Pos(range.head.line, len)};\n
        } else {\n
          return {from: range.from(), to: range.to()};\n
        }\n
      });\n
    },\n
    deleteLine: function(cm) {\n
      deleteNearSelection(cm, function(range) {\n
        return {from: Pos(range.from().line, 0),\n
                to: clipPos(cm.doc, Pos(range.to().line + 1, 0))};\n
      });\n
    },\n
    delLineLeft: function(cm) {\n
      deleteNearSelection(cm, function(range) {\n
        return {from: Pos(range.from().line, 0), to: range.from()};\n
      });\n
    },\n
    delWrappedLineLeft: function(cm) {\n
      deleteNearSelection(cm, function(range) {\n
        var top = cm.charCoords(range.head, "div").top + 5;\n
        var leftPos = cm.coordsChar({left: 0, top: top}, "div");\n
        return {from: leftPos, to: range.from()};\n
      });\n
    },\n
    delWrappedLineRight: function(cm) {\n
      deleteNearSelection(cm, function(range) {\n
        var top = cm.charCoords(range.head, "div").top + 5;\n
        var rightPos = cm.coordsChar({left: cm.display.lineDiv.offsetWidth + 100, top: top}, "div");\n
        return {from: range.from(), to: rightPos };\n
      });\n
    },\n
    undo: function(cm) {cm.undo();},\n
    redo: function(cm) {cm.redo();},\n
    undoSelection: function(cm) {cm.undoSelection();},\n
    redoSelection: function(cm) {cm.redoSelection();},\n
    goDocStart: function(cm) {cm.extendSelection(Pos(cm.firstLine(), 0));},\n
    goDocEnd: function(cm) {cm.extendSelection(Pos(cm.lastLine()));},\n
    goLineStart: function(cm) {\n
      cm.extendSelectionsBy(function(range) { return lineStart(cm, range.head.line); },\n
                            {origin: "+move", bias: 1});\n
    },\n
    goLineStartSmart: function(cm) {\n
      cm.extendSelectionsBy(function(range) {\n
        return lineStartSmart(cm, range.head);\n
      }, {origin: "+move", bias: 1});\n
    },\n
    goLineEnd: function(cm) {\n
      cm.extendSelectionsBy(function(range) { return lineEnd(cm, range.head.line); },\n
                            {origin: "+move", bias: -1});\n
    },\n
    goLineRight: function(cm) {\n
      cm.extendSelectionsBy(function(range) {\n
        var top = cm.charCoords(range.head, "div").top + 5;\n
        return cm.coordsChar({left: cm.display.lineDiv.offsetWidth + 100, top: top}, "div");\n
      }, sel_move);\n
    },\n
    goLineLeft: function(cm) {\n
      cm.extendSelectionsBy(function(range) {\n
        var top = cm.charCoords(range.head, "div").top + 5;\n
        return cm.coordsChar({left: 0, top: top}, "div");\n
      }, sel_move);\n
    },\n
    goLineLeftSmart: function(cm) {\n
      cm.extendSelectionsBy(function(range) {\n
        var top = cm.charCoords(range.head, "div").top + 5;\n
        var pos = cm.coordsChar({left: 0, top: top}, "div");\n
        if (pos.ch < cm.getLine(pos.line).search(/\\S/)) return lineStartSmart(cm, range.head);\n
        return pos;\n
      }, sel_move);\n
    },\n
    goLineUp: function(cm) {cm.moveV(-1, "line");},\n
    goLineDown: function(cm) {cm.moveV(1, "line");},\n
    goPageUp: function(cm) {cm.moveV(-1, "page");},\n
    goPageDown: function(cm) {cm.moveV(1, "page");},\n
    goCharLeft: function(cm) {cm.moveH(-1, "char");},\n
    goCharRight: function(cm) {cm.moveH(1, "char");},\n
    goColumnLeft: function(cm) {cm.moveH(-1, "column");},\n
    goColumnRight: function(cm) {cm.moveH(1, "column");},\n
    goWordLeft: function(cm) {cm.moveH(-1, "word");},\n
    goGroupRight: function(cm) {cm.moveH(1, "group");},\n
    goGroupLeft: function(cm) {cm.moveH(-1, "group");},\n
    goWordRight: function(cm) {cm.moveH(1, "word");},\n
    delCharBefore: function(cm) {cm.deleteH(-1, "char");},\n
    delCharAfter: function(cm) {cm.deleteH(1, "char");},\n
    delWordBefore: function(cm) {cm.deleteH(-1, "word");},\n
    delWordAfter: function(cm) {cm.deleteH(1, "word");},\n
    delGroupBefore: function(cm) {cm.deleteH(-1, "group");},\n
    delGroupAfter: function(cm) {cm.deleteH(1, "group");},\n
    indentAuto: function(cm) {cm.indentSelection("smart");},\n
    indentMore: function(cm) {cm.indentSelection("add");},\n
    indentLess: function(cm) {cm.indentSelection("subtract");},\n
    insertTab: function(cm) {cm.replaceSelection("\\t");},\n
    insertSoftTab: function(cm) {\n
      var spaces = [], ranges = cm.listSelections(), tabSize = cm.options.tabSize;\n
      for (var i = 0; i < ranges.length; i++) {\n
        var pos = ranges[i].from();\n
        var col = countColumn(cm.getLine(pos.line), pos.ch, tabSize);\n
        spaces.push(new Array(tabSize - col % tabSize + 1).join(" "));\n
      }\n
      cm.replaceSelections(spaces);\n
    },\n
    defaultTab: function(cm) {\n
      if (cm.somethingSelected()) cm.indentSelection("add");\n
      else cm.execCommand("insertTab");\n
    },\n
    transposeChars: function(cm) {\n
      runInOp(cm, function() {\n
        var ranges = cm.listSelections(), newSel = [];\n
        for (var i = 0; i < ranges.length; i++) {\n
          var cur = ranges[i].head, line = getLine(cm.doc, cur.line).text;\n
          if (line) {\n
            if (cur.ch == line.length) cur = new Pos(cur.line, cur.ch - 1);\n
            if (cur.ch > 0) {\n
              cur = new Pos(cur.line, cur.ch + 1);\n
              cm.replaceRange(line.charAt(cur.ch - 1) + line.charAt(cur.ch - 2),\n
                              Pos(cur.line, cur.ch - 2), cur, "+transpose");\n
            } else if (cur.line > cm.doc.first) {\n
              var prev = getLine(cm.doc, cur.line - 1).text;\n
              if (prev)\n
                cm.replaceRange(line.charAt(0) + cm.doc.lineSeparator() +\n
                                prev.charAt(prev.length - 1),\n
                                Pos(cur.line - 1, prev.length - 1), Pos(cur.line, 1), "+transpose");\n
            }\n
          }\n
          newSel.push(new Range(cur, cur));\n
        }\n
        cm.setSelections(newSel);\n
      });\n
    },\n
    newlineAndIndent: function(cm) {\n
      runInOp(cm, function() {\n
        var len = cm.listSelections().length;\n
        for (var i = 0; i < len; i++) {\n
          var range = cm.listSelections()[i];\n
          cm.replaceRange(cm.doc.lineSeparator(), range.anchor, range.head, "+input");\n
          cm.indentLine(range.from().line + 1, null, true);\n
        }\n
        ensureCursorVisible(cm);\n
      });\n
    },\n
    toggleOverwrite: function(cm) {cm.toggleOverwrite();}\n
  };\n
\n
\n
  // STANDARD KEYMAPS\n
\n
  var keyMap = CodeMirror.keyMap = {};\n
\n
  keyMap.basic = {\n
    "Left": "goCharLeft", "Right": "goCharRight", "Up": "goLineUp", "Down": "goLineDown",\n
    "End": "goLineEnd", "Home": "goLineStartSmart", "PageUp": "goPageUp", "PageDown": "goPageDown",\n
    "Delete": "delCharAfter", "Backspace": "delCharBefore", "Shift-Backspace": "delCharBefore",\n
    "Tab": "defaultTab", "Shift-Tab": "indentAuto",\n
    "Enter": "newlineAndIndent", "Insert": "toggleOverwrite",\n
    "Esc": "singleSelection"\n
  };\n
  // Note that the save and find-related commands aren\'t defined by\n
  // default. User code or addons can define them. Unknown commands\n
  // are simply ignored.\n
  keyMap.pcDefault = {\n
    "Ctrl-A": "selectAll", "Ctrl-D": "deleteLine", "Ctrl-Z": "undo", "Shift-Ctrl-Z": "redo", "Ctrl-Y": "redo",\n
    "Ctrl-Home": "goDocStart", "Ctrl-End": "goDocEnd", "Ctrl-Up": "goLineUp", "Ctrl-Down": "goLineDown",\n
    "Ctrl-Left": "goGroupLeft", "Ctrl-Right": "goGroupRight", "Alt-Left": "goLineStart", "Alt-Right": "goLineEnd",\n
    "Ctrl-Backspace": "delGroupBefore", "Ctrl-Delete": "delGroupAfter", "Ctrl-S": "save", "Ctrl-F": "find",\n
    "Ctrl-G": "findNext", "Shift-Ctrl-G": "findPrev", "Shift-Ctrl-F": "replace", "Shift-Ctrl-R": "replaceAll",\n
    "Ctrl-[": "indentLess", "Ctrl-]": "indentMore",\n
    "Ctrl-U": "undoSelection", "Shift-Ctrl-U": "redoSelection", "Alt-U": "redoSelection",\n
    fallthrough: "basic"\n
  };\n
  // Very basic readline/emacs-style bindings, which are standard on Mac.\n
  keyMap.emacsy = {\n
    "Ctrl-F": "goCharRight", "Ctrl-B": "goCharLeft", "Ctrl-P": "goLineUp", "Ctrl-N": "goLineDown",\n
    "Alt-F": "goWordRight", "Alt-B": "goWordLeft", "Ctrl-A": "goLineStart", "Ctrl-E": "goLineEnd",\n
    "Ctrl-V": "goPageDown", "Shift-Ctrl-V": "goPageUp", "Ctrl-D": "delCharAfter", "Ctrl-H": "delCharBefore",\n
    "Alt-D": "delWordAfter", "Alt-Backspace": "delWordBefore", "Ctrl-K": "killLine", "Ctrl-T": "transposeChars"\n
  };\n
  keyMap.macDefault = {\n
    "Cmd-A": "selectAll", "Cmd-D": "deleteLine", "Cmd-Z": "undo", "Shift-Cmd-Z": "redo", "Cmd-Y": "redo",\n
    "Cmd-Home": "goDocStart", "Cmd-Up": "goDocStart", "Cmd-End": "goDocEnd", "Cmd-Down": "goDocEnd", "Alt-Left": "goGroupLeft",\n
    "Alt-Right": "goGroupRight", "Cmd-Left": "goLineLeft", "Cmd-Right": "goLineRight", "Alt-Backspace": "delGroupBefore",\n
    "Ctrl-Alt-Backspace": "delGroupAfter", "Alt-Delete": "delGroupAfter", "Cmd-S": "save", "Cmd-F": "find",\n
    "Cmd-G": "findNext", "Shift-Cmd-G": "findPrev", "Cmd-Alt-F": "replace", "Shift-Cmd-Alt-F": "replaceAll",\n
    "Cmd-[": "indentLess", "Cmd-]": "indentMore", "Cmd-Backspace": "delWrappedLineLeft", "Cmd-Delete": "delWrappedLineRight",\n
    "Cmd-U": "undoSelection", "Shift-Cmd-U": "redoSelection", "Ctrl-Up": "goDocStart", "Ctrl-Down": "goDocEnd",\n
    fallthrough: ["basic", "emacsy"]\n
  };\n
  keyMap["default"] = mac ? keyMap.macDefault : keyMap.pcDefault;\n
\n
  // KEYMAP DISPATCH\n
\n
  function normalizeKeyName(name) {\n
    var parts = name.split(/-(?!$)/), name = parts[parts.length - 1];\n
    var alt, ctrl, shift, cmd;\n
    for (var i = 0; i < parts.length - 1; i++) {\n
      var mod = parts[i];\n
      if (/^(cmd|meta|m)$/i.test(mod)) cmd = true;\n
      else if (/^a(lt)?$/i.test(mod)) alt = true;\n
      else if (/^(c|ctrl|control)$/i.test(mod)) ctrl = true;\n
      else if (/^s(hift)$/i.test(mod)) shift = true;\n
      else throw new Error("Unrecognized modifier name: " + mod);\n
    }\n
    if (alt) name = "Alt-" + name;\n
    if (ctrl) name = "Ctrl-" + name;\n
    if (cmd) name = "Cmd-" + name;\n
    if (shift) name = "Shift-" + name;\n
    return name;\n
  }\n
\n
  // This is a kludge to keep keymaps mostly working as raw objects\n
  // (backwards compatibility) while at the same time support features\n
  // like normalization and multi-stroke key bindings. It compiles a\n
  // new normalized keymap, and then updates the old object to reflect\n
  // this.\n
  CodeMirror.normalizeKeyMap = function(keymap) {\n
    var copy = {};\n
    for (var keyname in keymap) if (keymap.hasOwnProperty(keyname)) {\n
      var value = keymap[keyname];\n
      if (/^(name|fallthrough|(de|at)tach)$/.test(keyname)) continue;\n
      if (value == "...") { delete keymap[keyname]; continue; }\n
\n
      var keys = map(keyname.split(" "), normalizeKeyName);\n
      for (var i = 0; i < keys.length; i++) {\n
        var val, name;\n
        if (i == keys.length - 1) {\n
          name = keys.join(" ");\n
          val = value;\n
        } else {\n
          name = keys.slice(0, i + 1).join(" ");\n
          val = "...";\n
        }\n
        var prev = copy[name];\n
        if (!prev) copy[name] = val;\n
        else if (prev != val) throw new Error("Inconsistent bindings for " + name);\n
      }\n
      delete keymap[keyname];\n
    }\n
    for (var prop in copy) keymap[prop] = copy[prop];\n
    return keymap;\n
  };\n
\n
  var lookupKey = CodeMirror.lookupKey = function(key, map, handle, context) {\n
    map = getKeyMap(map);\n
    var found = map.call ? map.call(key, context) : map[key];\n
    if (found === false) return "nothing";\n
    if (found === "...") return "multi";\n
    if (found != null && handle(found)) return "handled";\n
\n
    if (map.fallthrough) {\n
      if (Object.prototype.toString.call(map.fallthrough) != "[object Array]")\n
        return lookupKey(key, map.fallthrough, handle, context);\n
      for (var i = 0; i < map.fallthrough.length; i++) {\n
        var result = lookupKey(key, map.fallthrough[i], handle, context);\n
        if (result) return result;\n
      }\n
    }\n
  };\n
\n
  // Modifier key presses don\'t count as \'real\' key presses for the\n
  // purpose of keymap fallthrough.\n
  var isModifierKey = CodeMirror.isModifierKey = function(value) {\n
    var name = typeof value == "string" ? value : keyNames[value.keyCode];\n
    return name == "Ctrl" || name == "Alt" || name == "Shift" || name == "Mod";\n
  };\n
\n
  // Look up the name of a key as indicated by an event object.\n
  var keyName = CodeMirror.keyName = function(event, noShift) {\n
    if (presto && event.keyCode == 34 && event["char"]) return false;\n
    var base = keyNames[event.keyCode], name = base;\n
    if (name == null || event.altGraphKey) return false;\n
    if (event.altKey && base != "Alt") name = "Alt-" + name;\n
    if ((flipCtrlCmd ? event.metaKey : event.ctrlKey) && base != "Ctrl") name = "Ctrl-" + name;\n
    if ((flipCtrlCmd ? event.ctrlKey : event.metaKey) && base != "Cmd") name = "Cmd-" + name;\n
    if (!noShift && event.shiftKey && base != "Shift") name = "Shift-" + name;\n
    return name;\n
  };\n
\n
  function getKeyMap(val) {\n
    return typeof val == "string" ? keyMap[val] : val;\n
  }\n
\n
  // FROMTEXTAREA\n
\n
  CodeMirror.fromTextArea = function(textarea, options) {\n
    options = options ? copyObj(options) : {};\n
    options.value = textarea.value;\n
    if (!options.tabindex && textarea.tabIndex)\n
      options.tabindex = textarea.tabIndex;\n
    if (!options.placeholder && textarea.placeholder)\n
      options.placeholder = textarea.placeholder;\n
    // Set autofocus to true if this textarea is focused, or if it has\n
    // autofocus and no other element is focused.\n
    if (options.autofocus == null) {\n
      var hasFocus = activeElt();\n
      options.autofocus = hasFocus == textarea ||\n
        textarea.getAttribute("autofocus") != null && hasFocus == document.body;\n
    }\n
\n
    function save() {textarea.value = cm.getValue();}\n
    if (textarea.form) {\n
      on(textarea.form, "submit", save);\n
      // Deplorable hack to make the submit method do the right thing.\n
      if (!options.leaveSubmitMethodAlone) {\n
        var form = textarea.form, realSubmit = form.submit;\n
        try {\n
          var wrappedSubmit = form.submit = function() {\n
            save();\n
            form.submit = realSubmit;\n
            form.submit();\n
            form.submit = wrappedSubmit;\n
          };\n
        } catch(e) {}\n
      }\n
    }\n
\n
    options.finishInit = function(cm) {\n
      cm.save = save;\n
      cm.getTextArea = function() { return textarea; };\n
      cm.toTextArea = function() {\n
        cm.toTextArea = isNaN; // Prevent this from being ran twice\n
        save();\n
        textarea.parentNode.removeChild(cm.getWrapperElement());\n
        textarea.style.display = "";\n
        if (textarea.form) {\n
          off(textarea.form, "submit", save);\n
          if (typeof textarea.form.submit == "function")\n
            textarea.form.submit = realSubmit;\n
        }\n
      };\n
    };\n
\n
    textarea.style.display = "none";\n
    var cm = CodeMirror(function(node) {\n
      textarea.parentNode.insertBefore(node, textarea.nextSibling);\n
    }, options);\n
    return cm;\n
  };\n
\n
  // STRING STREAM\n
\n
  // Fed to the mode parsers, provides helper functions to make\n
  // parsers more succinct.\n
\n
  var StringStream = CodeMirror.StringStream = function(string, tabSize) {\n
    this.pos = this.start = 0;\n
    this.string = string;\n
    this.tabSize = tabSize || 8;\n
    this.lastColumnPos = this.lastColumnValue = 0;\n
    this.lineStart = 0;\n
  };\n
\n
  StringStream.prototype = {\n
    eol: function() {return this.pos >= this.string.length;},\n
    sol: function() {return this.pos == this.lineStart;},\n
    peek: function() {return this.string.charAt(this.pos) || undefined;},\n
    next: function() {\n
      if (this.pos < this.string.length)\n
        return this.string.charAt(this.pos++);\n
    },\n
    eat: function(match) {\n
      var ch = this.string.charAt(this.pos);\n
      if (typeof match == "string") var ok = ch == match;\n
      else var ok = ch && (match.test ? match.test(ch) : match(ch));\n
      if (ok) {++this.pos; return ch;}\n
    },\n
    eatWhile: function(match) {\n
      var start = this.pos;\n
      while (this.eat(match)){}\n
      return this.pos > start;\n
    },\n
    eatSpace: function() {\n
      var start = this.pos;\n
      while (/[\\s\\u00a0]/.test(this.string.charAt(this.pos))) ++this.pos;\n
      return this.pos > start;\n
    },\n
    skipToEnd: function() {this.pos = this.string.length;},\n
    skipTo: function(ch) {\n
      var found = this.string.indexOf(ch, this.pos);\n
      if (found > -1) {this.pos = found; return true;}\n
    },\n
    backUp: function(n) {this.pos -= n;},\n
    column: function() {\n
      if (this.lastColumnPos < this.start) {\n
        this.lastColumnValue = countColumn(this.string, this.start, this.tabSize, this.lastColumnPos, this.lastColumnValue);\n
        this.lastColumnPos = this.start;\n
      }\n
      return this.lastColumnValue - (this.lineStart ? countColumn(this.string, this.lineStart, this.tabSize) : 0);\n
    },\n
    indentation: function() {\n
      return countColumn(this.string, null, this.tabSize) -\n
        (this.lineStart ? countColumn(this.string, this.lineStart, this.tabSize) : 0);\n
    },\n
    match: function(pattern, consume, caseInsensitive) {\n
      if (typeof pattern == "string") {\n
        var cased = function(str) {return caseInsensitive ? str.toLowerCase() : str;};\n
        var substr = this.string.substr(this.pos, pattern.length);\n
        if (cased(substr) == cased(pattern)) {\n
          if (consume !== false) this.pos += pattern.length;\n
          return true;\n
        }\n
      } else {\n
        var match = this.string.slice(this.pos).match(pattern);\n
        if (match && match.index > 0) return null;\n
        if (match && consume !== false) this.pos += match[0].length;\n
        return match;\n
      }\n
    },\n
    current: function(){return this.string.slice(this.start, this.pos);},\n
    hideFirstChars: function(n, inner) {\n
      this.lineStart += n;\n
      try { return inner(); }\n
      finally { this.lineStart -= n; }\n
    }\n
  };\n
\n
  // TEXTMARKERS\n
\n
  // Created with markText and setBookmark methods. A TextMarker is a\n
  // handle that can be used to clear or find a marked position in the\n
  // document. Line objects hold arrays (markedSpans) containing\n
  // {from, to, marker} object pointing to such marker objects, and\n
  // indicating that such a marker is present on that line. Multiple\n
  // lines may point to the same marker when it spans across lines.\n
  // The spans will have null for their from/to properties when the\n
  // marker continues beyond the start/end of the line. Markers have\n
  // links back to the lines they currently touch.\n
\n
  var nextMarkerId = 0;\n
\n
  var TextMarker = CodeMirror.TextMarker = function(doc, type) {\n
    this.lines = [];\n
    this.type = type;\n
    this.doc = doc;\n
    this.id = ++nextMarkerId;\n
  };\n
  eventMixin(TextMarker);\n
\n
  // Clear the marker.\n
  TextMarker.prototype.clear = function() {\n
    if (this.explicitlyCleared) return;\n
    var cm = this.doc.cm, withOp = cm && !cm.curOp;\n
    if (withOp) startOperation(cm);\n
    if (hasHandler(this, "clear")) {\n
      var found = this.find();\n
      if (found) signalLater(this, "clear", found.from, found.to);\n
    }\n
    var min = null, max = null;\n
    for (var i = 0; i < this.lines.length; ++i) {\n
      var line = this.lines[i];\n
      var span = getMarkedSpanFor(line.markedSpans, this);\n
      if (cm && !this.collapsed) regLineChange(cm, lineNo(line), "text");\n
      else if (cm) {\n
        if (span.to != null) max = lineNo(line);\n
        if (span.from != null) min = lineNo(line);\n
      }\n
      line.markedSpans = removeMarkedSpan(line.markedSpans, span);\n
      if (span.from == null && this.collapsed && !lineIsHidden(this.doc, line) && cm)\n
        updateLineHeight(line, textHeight(cm.display));\n
    }\n
    if (cm && this.collapsed && !cm.options.lineWrapping) for (var i = 0; i < this.lines.length; ++i) {\n
      var visual = visualLine(this.lines[i]), len = lineLength(visual);\n
      if (len > cm.display.maxLineLength) {\n
        cm.display.maxLine = visual;\n
        cm.display.maxLineLength = len;\n
        cm.display.maxLineChanged = true;\n
      }\n
    }\n
\n
    if (min != null && cm && this.collapsed) regChange(cm, min, max + 1);\n
    this.lines.length = 0;\n
    this.explicitlyCleared = true;\n
    if (this.atomic && this.doc.cantEdit) {\n
      this.doc.cantEdit = false;\n
      if (cm) reCheckSelection(cm.doc);\n
    }\n
    if (cm) signalLater(cm, "markerCleared", cm, this);\n
    if (withOp) endOperation(cm);\n
    if (this.parent) this.parent.clear();\n
  };\n
\n
  // Find the position of the marker in the document. Returns a {from,\n
  // to} object by default. Side can be passed to get a specific side\n
  // -- 0 (both), -1 (left), or 1 (right). When lineObj is true, the\n
  // Pos objects returned contain a line object, rather than a line\n
  // number (used to prevent looking up the same line twice).\n
  TextMarker.prototype.find = function(side, lineObj) {\n
    if (side == null && this.type == "bookmark") side = 1;\n
    var from, to;\n
    for (var i = 0; i < this.lines.length; ++i) {\n
      var line = this.lines[i];\n
      var span = getMarkedSpanFor(line.markedSpans, this);\n
      if (span.from != null) {\n
        from = Pos(lineObj ? line : lineNo(line), span.from);\n
        if (side == -1) return from;\n
      }\n
      if (span.to != null) {\n
        to = Pos(lineObj ? line : lineNo(line), span.to);\n
        if (side == 1) return to;\n
      }\n
    }\n
    return from && {from: from, to: to};\n
  };\n
\n
  // Signals that the marker\'s widget changed, and surrounding layout\n
  // should be recomputed.\n
  TextMarker.prototype.changed = function() {\n
    var pos = this.find(-1, true), widget = this, cm = this.doc.cm;\n
    if (!pos || !cm) return;\n
    runInOp(cm, function() {\n
      var line = pos.line, lineN = lineNo(pos.line);\n
      var view = findViewForLine(cm, lineN);\n
      if (view) {\n
        clearLineMeasurementCacheFor(view);\n
        cm.curOp.selectionChanged = cm.curOp.forceUpdate = true;\n
      }\n
      cm.curOp.updateMaxLine = true;\n
      if (!lineIsHidden(widget.doc, line) && widget.height != null) {\n
        var oldHeight = widget.height;\n
        widget.height = null;\n
        var dHeight = widgetHeight(widget) - oldHeight;\n
        if (dHeight)\n
          updateLineHeight(line, line.height + dHeight);\n
      }\n
    });\n
  };\n
\n
  TextMarker.prototype.attachLine = function(line) {\n
    if (!this.lines.length && this.doc.cm) {\n
      var op = this.doc.cm.curOp;\n
      if (!op.maybeHiddenMarkers || indexOf(op.maybeHiddenMarkers, this) == -1)\n
        (op.maybeUnhiddenMarkers || (op.maybeUnhiddenMarkers = [])).push(this);\n
    }\n
    this.lines.push(line);\n
  };\n
  TextMarker.prototype.detachLine = function(line) {\n
    this.lines.splice(indexOf(this.lines, line), 1);\n
    if (!this.lines.length && this.doc.cm) {\n
      var op = this.doc.cm.curOp;\n
      (op.maybeHiddenMarkers || (op.maybeHiddenMarkers = [])).push(this);\n
    }\n
  };\n
\n
  // Collapsed markers have unique ids, in order to be able to order\n
  // them, which is needed for uniquely determining an outer marker\n
  // when they overlap (they may nest, but not partially overlap).\n
  var nextMarkerId = 0;\n
\n
  // Create a marker, wire it up to the right lines, and\n
  function markText(doc, from, to, options, type) {\n
    // Shared markers (across linked documents) are handled separately\n
    // (markTextShared will call out to this again, once per\n
    // document).\n
    if (options && options.shared) return markTextShared(doc, from, to, options, type);\n
    // Ensure we are in an operation.\n
    if (doc.cm && !doc.cm.curOp) return operation(doc.cm, markText)(doc, from, to, options, type);\n
\n
    var marker = new TextMarker(doc, type), diff = cmp(from, to);\n
    if (options) copyObj(options, marker, false);\n
    // Don\'t connect empty markers unless clearWhenEmpty is false\n
    if (diff > 0 || diff == 0 && marker.clearWhenEmpty !== false)\n
      return marker;\n
    if (marker.replacedWith) {\n
      // Showing up as a widget implies collapsed (widget replaces text)\n
      marker.collapsed = true;\n
      marker.widgetNode = elt("span", [marker.replacedWith], "CodeMirror-widget");\n
      if (!options.handleMouseEvents) marker.widgetNode.setAttribute("cm-ignore-events", "true");\n
      if (options.insertLeft) marker.widgetNode.insertLeft = true;\n
    }\n
    if (marker.collapsed) {\n
      if (conflictingCollapsedRange(doc, from.line, from, to, marker) ||\n
          from.line != to.line && conflictingCollapsedRange(doc, to.line, from, to, marker))\n
        throw new Error("Inserting collapsed marker partially overlapping an existing one");\n
      sawCollapsedSpans = true;\n
    }\n
\n
    if (marker.addToHistory)\n
      addChangeToHistory(doc, {from: from, to: to, origin: "markText"}, doc.sel, NaN);\n
\n
    var curLine = from.line, cm = doc.cm, updateMaxLine;\n
    doc.iter(curLine, to.line + 1, function(line) {\n
      if (cm && marker.collapsed && !cm.options.lineWrapping && visualLine(line) == cm.display.maxLine)\n
        updateMaxLine = true;\n
      if (marker.collapsed && curLine != from.line) updateLineHeight(line, 0);\n
      addMarkedSpan(line, new MarkedSpan(marker,\n
                                         curLine == from.line ? from.ch : null,\n
                                         curLine == to.line ? to.ch : null));\n
      ++curLine;\n
    });\n
    // lineIsHidden depends on the presence of the spans, so needs a second pass\n
    if (marker.collapsed) doc.iter(from.line, to.line + 1, function(line) {\n
      if (lineIsHidden(doc, line)) updateLineHeight(line, 0);\n
    });\n
\n
    if (marker.clearOnEnter) on(marker, "beforeCursorEnter", function() { marker.clear(); });\n
\n
    if (marker.readOnly) {\n
      sawReadOnlySpans = true;\n
      if (doc.history.done.length || doc.history.undone.length)\n
        doc.clearHistory();\n
    }\n
    if (marker.collapsed) {\n
      marker.id = ++nextMarkerId;\n
      marker.atomic = true;\n
    }\n
    if (cm) {\n
      // Sync editor state\n
      if (updateMaxLine) cm.curOp.updateMaxLine = true;\n
      if (marker.collapsed)\n
        regChange(cm, from.line, to.line + 1);\n
      else if (marker.className || marker.title || marker.startStyle || marker.endStyle || marker.css)\n
        for (var i = from.line; i <= to.line; i++) regLineChange(cm, i, "text");\n
      if (marker.atomic) reCheckSelection(cm.doc);\n
      signalLater(cm, "markerAdded", cm, marker);\n
    }\n
    return marker;\n
  }\n
\n
  // SHARED TEXTMARKERS\n
\n
  // A shared marker spans multiple linked documents. It is\n
  // implemented as a meta-marker-object controlling multiple normal\n
  // markers.\n
  var SharedTextMarker = CodeMirror.SharedTextMarker = function(markers, primary) {\n
    this.markers = markers;\n
    this.primary = primary;\n
    for (var i = 0; i < markers.length; ++i)\n
      markers[i].parent = this;\n
  };\n
  eventMixin(SharedTextMarker);\n
\n
  SharedTextMarker.prototype.clear = function() {\n
    if (this.explicitlyCleared) return;\n
    this.explicitlyCleared = true;\n
    for (var i = 0; i < this.markers.length; ++i)\n
      this.markers[i].clear();\n
    signalLater(this, "clear");\n
  };\n
  SharedTextMarker.prototype.find = function(side, lineObj) {\n
    return this.primary.find(side, lineObj);\n
  };\n
\n
  function markTextShared(doc, from, to, options, type) {\n
    options = copyObj(options);\n
    options.shared = false;\n
    var markers = [markText(doc, from, to, options, type)], primary = markers[0];\n
    var widget = options.widgetNode;\n
    linkedDocs(doc, function(doc) {\n
      if (widget) options.widgetNode = widget.cloneNode(true);\n
      markers.push(markText(doc, clipPos(doc, from), clipPos(doc, to), options, type));\n
      for (var i = 0; i < doc.linked.length; ++i)\n
        if (doc.linked[i].isParent) return;\n
      primary = lst(markers);\n
    });\n
    return new SharedTextMarker(markers, primary);\n
  }\n
\n
  function findSharedMarkers(doc) {\n
    return doc.findMarks(Pos(doc.first, 0), doc.clipPos(Pos(doc.lastLine())),\n
                         function(m) { return m.parent; });\n
  }\n
\n
  function copySharedMarkers(doc, markers) {\n
    for (var i = 0; i < markers.length; i++) {\n
      var marker = markers[i], pos = marker.find();\n
      var mFrom = doc.clipPos(pos.from), mTo = doc.clipPos(pos.to);\n
      if (cmp(mFrom, mTo)) {\n
        var subMark = markText(doc, mFrom, mTo, marker.primary, marker.primary.type);\n
        marker.markers.push(subMark);\n
        subMark.parent = marker;\n
      }\n
    }\n
  }\n
\n
  function detachSharedMarkers(markers) {\n
    for (var i = 0; i < markers.length; i++) {\n
      var marker = markers[i], linked = [marker.primary.doc];;\n
      linkedDocs(marker.primary.doc, function(d) { linked.push(d); });\n
      for (var j = 0; j < marker.markers.length; j++) {\n
        var subMarker = marker.markers[j];\n
        if (indexOf(linked, subMarker.doc) == -1) {\n
          subMarker.parent = null;\n
          marker.markers.splice(j--, 1);\n
        }\n
      }\n
    }\n
  }\n
\n
  // TEXTMARKER SPANS\n
\n
  function MarkedSpan(marker, from, to) {\n
    this.marker = marker;\n
    this.from = from; this.to = to;\n
  }\n
\n
  // Search an array of spans for a span matching the given marker.\n
  function getMarkedSpanFor(spans, marker) {\n
    if (spans) for (var i = 0; i < spans.length; ++i) {\n
      var span = spans[i];\n
      if (span.marker == marker) return span;\n
    }\n
  }\n
  // Remove a span from an array, returning undefined if no spans are\n
  // left (we don\'t store arrays for lines without spans).\n
  function removeMarkedSpan(spans, span) {\n
    for (var r, i = 0; i < spans.length; ++i)\n
      if (spans[i] != span) (r || (r = [])).push(spans[i]);\n
    return r;\n
  }\n
  // Add a span to a line.\n
  function addMarkedSpan(line, span) {\n
    line.markedSpans = line.markedSpans ? line.markedSpans.concat([span]) : [span];\n
    span.marker.attachLine(line);\n
  }\n
\n
  // Used for the algorithm that adjusts markers for a change in the\n
  // document. These functions cut an array of spans at a given\n
  // character position, returning an array of remaining chunks (or\n
  // undefined if nothing remains).\n
  function markedSpansBefore(old, startCh, isInsert) {\n
    if (old) for (var i = 0, nw; i < old.length; ++i) {\n
      var span = old[i], marker = span.marker;\n
      var startsBefore = span.from == null || (marker.inclusiveLeft ? span.from <= startCh : span.from < startCh);\n
      if (startsBefore || span.from == startCh && marker.type == "bookmark" && (!isInsert || !span.marker.insertLeft)) {\n
        var endsAfter = span.to == null || (marker.inclusiveRight ? span.to >= startCh : span.to > startCh);\n
        (nw || (nw = [])).push(new MarkedSpan(marker, span.from, endsAfter ? null : span.to));\n
      }\n
    }\n
    return nw;\n
  }\n
  function markedSpansAfter(old, endCh, isInsert) {\n
    if (old) for (var i = 0, nw; i < old.length; ++i) {\n
      var span = old[i], marker = span.marker;\n
      var endsAfter = span.to == null || (marker.inclusiveRight ? span.to >= endCh : span.to > endCh);\n
      if (endsAfter || span.from == endCh && marker.type == "bookmark" && (!isInsert || span.marker.insertLeft)) {\n
        var startsBefore = span.from == null || (marker.inclusiveLeft ? span.from <= endCh : span.from < endCh);\n
        (nw || (nw = [])).push(new MarkedSpan(marker, startsBefore ? null : span.from - endCh,\n
                                              span.to == null ? null : span.to - endCh));\n
      }\n
    }\n
    return nw;\n
  }\n
\n
  // Given a change object, compute the new set of marker spans that\n
  // cover the line in which the change took place. Removes spans\n
  // entirely within the change, reconnects spans belonging to the\n
  // same marker that appear on both sides of the change, and cuts off\n
  // spans partially within the change. Returns an array of span\n
  // arrays with one element for each line in (after) the change.\n
  function stretchSpansOverChange(doc, change) {\n
    if (change.full) return null;\n
    var oldFirst = isLine(doc, change.from.line) && getLine(doc, change.from.line).markedSpans;\n
    var oldLast = isLine(doc, change.to.line) && getLine(doc, change.to.line).markedSpans;\n
    if (!oldFirst && !oldLast) return null;\n
\n
    var startCh = change.from.ch, endCh = change.to.ch, isInsert = cmp(change.from, change.to) == 0;\n
    // Get the spans that \'stick out\' on both sides\n
    var first = markedSpansBefore(oldFirst, startCh, isInsert);\n
    var last = markedSpansAfter(oldLast, endCh, isInsert);\n
\n
    // Next, merge those two ends\n
    var sameLine = change.text.length == 1, offset = lst(change.text).length + (sameLine ? startCh : 0);\n
    if (first) {\n
      // Fix up .to properties of first\n
      for (var i = 0; i < first.length; ++i) {\n
        var span = first[i];\n
        if (span.to == null) {\n
          var found = getMarkedSpanFor(last, span.marker);\n
          if (!found) span.to = startCh;\n
          else if (sameLine) span.to = found.to == null ? null : found.to + offset;\n
        }\n
      }\n
    }\n
    if (last) {\n
      // Fix up .from in last (or move them into first in case of sameLine)\n
      for (var i = 0; i < last.length; ++i) {\n
        var span = last[i];\n
        if (span.to != null) span.to += offset;\n
        if (span.from == null) {\n
          var found = getMarkedSpanFor(first, span.marker);\n
          if (!found) {\n
            span.from = offset;\n
            if (sameLine) (first || (first = [])).push(span);\n
          }\n
        } else {\n
          span.from += offset;\n
          if (sameLine) (first || (first = [])).push(span);\n
        }\n
      }\n
    }\n
    // Make sure we didn\'t create any zero-length spans\n
    if (first) first = clearEmptySpans(first);\n
    if (last && last != first) last = clearEmptySpans(last);\n
\n
    var newMarkers = [first];\n
    if (!sameLine) {\n
      // Fill gap with whole-line-spans\n
      var gap = change.text.length - 2, gapMarkers;\n
      if (gap > 0 && first)\n
        for (var i = 0; i < first.length; ++i)\n
          if (first[i].to == null)\n
            (gapMarkers || (gapMarkers = [])).push(new MarkedSpan(first[i].marker, null, null));\n
      for (var i = 0; i < gap; ++i)\n
        newMarkers.push(gapMarkers);\n
      newMarkers.push(last);\n
    }\n
    return newMarkers;\n
  }\n
\n
  // Remove spans that are empty and don\'t have a clearWhenEmpty\n
  // option of false.\n
  function clearEmptySpans(spans) {\n
    for (var i = 0; i < spans.length; ++i) {\n
      var span = spans[i];\n
      if (span.from != null && span.from == span.to && span.marker.clearWhenEmpty !== false)\n
        spans.splice(i--, 1);\n
    }\n
    if (!spans.length) return null;\n
    return spans;\n
  }\n
\n
  // Used for un/re-doing changes from the history. Combines the\n
  // result of computing the existing spans with the set of spans that\n
  // existed in the history (so that deleting around a span and then\n
  // undoing brings back the span).\n
  function mergeOldSpans(doc, change) {\n
    var old = getOldSpans(doc, change);\n
    var stretched = stretchSpansOverChange(doc, change);\n
    if (!old) return stretched;\n
    if (!stretched) return old;\n
\n
    for (var i = 0; i < old.length; ++i) {\n
      var oldCur = old[i], stretchCur = stretched[i];\n
      if (oldCur && stretchCur) {\n
        spans: for (var j = 0; j < stretchCur.length; ++j) {\n
          var span = stretchCur[j];\n
          for (var k = 0; k < oldCur.length; ++k)\n
            if (oldCur[k].marker == span.marker) continue spans;\n
          oldCur.push(span);\n
        }\n
      } else if (stretchCur) {\n
        old[i] = stretchCur;\n
      }\n
    }\n
    return old;\n
  }\n
\n
  // Used to \'clip\' out readOnly ranges when making a change.\n
  function removeReadOnlyRanges(doc, from, to) {\n
    var markers = null;\n
    doc.iter(from.line, to.line + 1, function(line) {\n
      if (line.markedSpans) for (var i = 0; i < line.markedSpans.length; ++i) {\n
        var mark = line.markedSpans[i].marker;\n
        if (mark.readOnly && (!markers || indexOf(markers, mark) == -1))\n
          (markers || (markers = [])).push(mark);\n
      }\n
    });\n
    if (!markers) return null;\n
    var parts = [{from: from, to: to}];\n
    for (var i = 0; i < markers.length; ++i) {\n
      var mk = markers[i], m = mk.find(0);\n
      for (var j = 0; j < parts.length; ++j) {\n
        var p = parts[j];\n
        if (cmp(p.to, m.from) < 0 || cmp(p.from, m.to) > 0) continue;\n
        var newParts = [j, 1], dfrom = cmp(p.from, m.from), dto = cmp(p.to, m.to);\n
        if (dfrom < 0 || !mk.inclusiveLeft && !dfrom)\n
          newParts.push({from: p.from, to: m.from});\n
        if (dto > 0 || !mk.inclusiveRight && !dto)\n
          newParts.push({from: m.to, to: p.to});\n
        parts.splice.apply(parts, newParts);\n
        j += newParts.length - 1;\n
      }\n
    }\n
    return parts;\n
  }\n
\n
  // Connect or disconnect spans from a line.\n
  function detachMarkedSpans(line) {\n
    var spans = line.markedSpans;\n
    if (!spans) return;\n
    for (var i = 0; i < spans.length; ++i)\n
      spans[i].marker.detachLine(line);\n
    line.markedSpans = null;\n
  }\n
  function attachMarkedSpans(line, spans) {\n
    if (!spans) return;\n
    for (var i = 0; i < spans.length; ++i)\n
      spans[i].marker.attachLine(line);\n
    line.markedSpans = spans;\n
  }\n
\n
  // Helpers used when computing which overlapping collapsed span\n
  // counts as the larger one.\n
  function extraLeft(marker) { return marker.inclusiveLeft ? -1 : 0; }\n
  function extraRight(marker) { return marker.inclusiveRight ? 1 : 0; }\n
\n
  // Returns a number indicating which of two overlapping collapsed\n
  // spans is larger (and thus includes the other). Falls back to\n
  // comparing ids when the spans cover exactly the same range.\n
  function compareCollapsedMarkers(a, b) {\n
    var lenDiff = a.lines.length - b.lines.length;\n
    if (lenDiff != 0) return lenDiff;\n
    var aPos = a.find(), bPos = b.find();\n
    var fromCmp = cmp(aPos.from, bPos.from) || extraLeft(a) - extraLeft(b);\n
    if (fromCmp) return -fromCmp;\n
    var toCmp = cmp(aPos.to, bPos.to) || extraRight(a) - extraRight(b);\n
    if (toCmp) return toCmp;\n
    return b.id - a.id;\n
  }\n
\n
  // Find out whether a line ends or starts in a collapsed span. If\n
  // so, return the marker for that span.\n
  function collapsedSpanAtSide(line, start) {\n
    var sps = sawCollapsedSpans && line.markedSpans, found;\n
    if (sps) for (var sp, i = 0; i < sps.length; ++i) {\n
      sp = sps[i];\n
      if (sp.marker.collapsed && (start ? sp.from : sp.to) == null &&\n
          (!found || compareCollapsedMarkers(found, sp.marker) < 0))\n
        found = sp.marker;\n
    }\n
    return found;\n
  }\n
  function collapsedSpanAtStart(line) { return collapsedSpanAtSide(line, true); }\n
  function collapsedSpanAtEnd(line) { return collapsedSpanAtSide(line, false); }\n
\n
  // Test whether there exists a collapsed span that partially\n
  // overlaps (covers the start or end, but not both) of a new span.\n
  // Such overlap is not allowed.\n
  function conflictingCollapsedRange(doc, lineNo, from, to, marker) {\n
    var line = getLine(doc, lineNo);\n
    var sps = sawCollapsedSpans && line.markedSpans;\n
    if (sps) for (var i = 0; i < sps.length; ++i) {\n
      var sp = sps[i];\n
      if (!sp.marker.collapsed) continue;\n
      var found = sp.marker.find(0);\n
      var fromCmp = cmp(found.from, from) || extraLeft(sp.marker) - extraLeft(marker);\n
      var toCmp = cmp(found.to, to) || extraRight(sp.marker) - extraRight(marker);\n
      if (fromCmp >= 0 && toCmp <= 0 || fromCmp <= 0 && toCmp >= 0) continue;\n
      if (fromCmp <= 0 && (cmp(found.to, from) > 0 || (sp.marker.inclusiveRight && marker.inclusiveLeft)) ||\n
          fromCmp >= 0 && (cmp(found.from, to) < 0 || (sp.marker.inclusiveLeft && marker.inclusiveRight)))\n
        return true;\n
    }\n
  }\n
\n
  // A visual line is a line as drawn on the screen. Folding, for\n
  // example, can cause multiple logical lines to appear on the same\n
  // visual line. This finds the start of the visual line that the\n
  // given line is part of (usually that is the line itself).\n
  function visualLine(line) {\n
    var merged;\n
    while (merged = collapsedSpanAtStart(line))\n
      line = merged.find(-1, true).line;\n
    return line;\n
  }\n
\n
  // Returns an array of logical lines that continue the visual line\n
  // started by the argument, or undefined if there are no such lines.\n
  function visualLineContinued(line) {\n
    var merged, lines;\n
    while (merged = collapsedSpanAtEnd(line)) {\n
      line = merged.find(1, true).line;\n
      (lines || (lines = [])).push(line);\n
    }\n
    return lines;\n
  }\n
\n
  // Get the line number of the start of the visual line that the\n
  // given line number is part of.\n
  function visualLineNo(doc, lineN) {\n
    var line = getLine(doc, lineN), vis = visualLine(line);\n
    if (line == vis) return lineN;\n
    return lineNo(vis);\n
  }\n
  // Get the line number of the start of the next visual line after\n
  // the given line.\n
  function visualLineEndNo(doc, lineN) {\n
    if (lineN > doc.lastLine()) return lineN;\n
    var line = getLine(doc, lineN), merged;\n
    if (!lineIsHidden(doc, line)) return lineN;\n
    while (merged = collapsedSpanAtEnd(line))\n
      line = merged.find(1, true).line;\n
    return lineNo(line) + 1;\n
  }\n
\n
  // Compute whether a line is hidden. Lines count as hidden when they\n
  // are part of a visual line that starts with another line, or when\n
  // they are entirely covered by collapsed, non-widget span.\n
  function lineIsHidden(doc, line) {\n
    var sps = sawCollapsedSpans && line.markedSpans;\n
    if (sps) for (var sp, i = 0; i < sps.length; ++i) {\n
      sp = sps[i];\n
      if (!sp.marker.collapsed) continue;\n
      if (sp.from == null) return true;\n
      if (sp.marker.widgetNode) continue;\n
      if (sp.from == 0 && sp.marker.inclusiveLeft && lineIsHiddenInner(doc, line, sp))\n
        return true;\n
    }\n
  }\n
  function lineIsHiddenInner(doc, line, span) {\n
    if (span.to == null) {\n
      var end = span.marker.find(1, true);\n
      return lineIsHiddenInner(doc, end.line, getMarkedSpanFor(end.line.markedSpans, span.marker));\n
    }\n
    if (span.marker.inclusiveRight && span.to == line.text.length)\n
      return true;\n
    for (var sp, i = 0; i < line.markedSpans.length; ++i) {\n
      sp = line.markedSpans[i];\n
      if (sp.marker.collapsed && !sp.marker.widgetNode && sp.from == span.to &&\n
          (sp.to == null || sp.to != span.from) &&\n
          (sp.marker.inclusiveLeft || span.marker.inclusiveRight) &&\n
          lineIsHiddenInner(doc, line, sp)) return true;\n
    }\n
  }\n
\n
  // LINE WIDGETS\n
\n
  // Line widgets are block elements displayed above or below a line.\n
\n
  var LineWidget = CodeMirror.LineWidget = function(doc, node, options) {\n
    if (options) for (var opt in options) if (options.hasOwnProperty(opt))\n
      this[opt] = options[opt];\n
    this.doc = doc;\n
    this.node = node;\n
  };\n
  eventMixin(LineWidget);\n
\n
  function adjustScrollWhenAboveVisible(cm, line, diff) {\n
    if (heightAtLine(line) < ((cm.curOp && cm.curOp.scrollTop) || cm.doc.scrollTop))\n
      addToScrollPos(cm, null, diff);\n
  }\n
\n
  LineWidget.prototype.clear = function() {\n
    var cm = this.doc.cm, ws = this.line.widgets, line = this.line, no = lineNo(line);\n
    if (no == null || !ws) return;\n
    for (var i = 0; i < ws.length; ++i) if (ws[i] == this) ws.splice(i--, 1);\n
    if (!ws.length) line.widgets = null;\n
    var height = widgetHeight(this);\n
    updateLineHeight(line, Math.max(0, line.height - height));\n
    if (cm) runInOp(cm, function() {\n
      adjustScrollWhenAboveVisible(cm, line, -height);\n
      regLineChange(cm, no, "widget");\n
    });\n
  };\n
  LineWidget.prototype.changed = function() {\n
    var oldH = this.height, cm = this.doc.cm, line = this.line;\n
    this.height = null;\n
    var diff = widgetHeight(this) - oldH;\n
    if (!diff) return;\n
    updateLineHeight(line, line.height + diff);\n
    if (cm) runInOp(cm, function() {\n
      cm.curOp.forceUpdate = true;\n
      adjustScrollWhenAboveVisible(cm, line, diff);\n
    });\n
  };\n
\n
  function widgetHeight(widget) {\n
    if (widget.height != null) return widget.height;\n
    var cm = widget.doc.cm;\n
    if (!cm) return 0;\n
    if (!contains(document.body, widget.node)) {\n
      var parentStyle = "position: relative;";\n
      if (widget.coverGutter)\n
        parentStyle += "margin-left: -" + cm.display.gutters.offsetWidth + "px;";\n
      if (widget.noHScroll)\n
        parentStyle += "width: " + cm.display.wrapper.clientWidth + "px;";\n
      removeChildrenAndAdd(cm.display.measure, elt("div", [widget.node], null, parentStyle));\n
    }\n
    return widget.height = widget.node.parentNode.offsetHeight;\n
  }\n
\n
  function addLineWidget(doc, handle, node, options) {\n
    var widget = new LineWidget(doc, node, options);\n
    var cm = doc.cm;\n
    if (cm && widget.noHScroll) cm.display.alignWidgets = true;\n
    changeLine(doc, handle, "widget", function(line) {\n
      var widgets = line.widgets || (line.widgets = []);\n
      if (widget.insertAt == null) widgets.push(widget);\n
      else widgets.splice(Math.min(widgets.length - 1, Math.max(0, widget.insertAt)), 0, widget);\n
      widget.line = line;\n
      if (cm && !lineIsHidden(doc, line)) {\n
        var aboveVisible = heightAtLine(line) < doc.scrollTop;\n
        updateLineHeight(line, line.height + widgetHeight(widget));\n
        if (aboveVisible) addToScrollPos(cm, null, widget.height);\n
        cm.curOp.forceUpdate = true;\n
      }\n
      return true;\n
    });\n
    return widget;\n
  }\n
\n
  // LINE DATA STRUCTURE\n
\n
  // Line objects. These hold state related to a line, including\n
  // highlighting info (the styles array).\n
  var Line = CodeMirror.Line = function(text, markedSpans, estimateHeight) {\n
    this.text = text;\n
    attachMarkedSpans(this, markedSpans);\n
    this.height = estimateHeight ? estimateHeight(this) : 1;\n
  };\n
  eventMixin(Line);\n
  Line.prototype.lineNo = function() { return lineNo(this); };\n
\n
  // Change the content (text, markers) of a line. Automatically\n
  // invalidates cached information and tries to re-estimate the\n
  // line\'s height.\n
  function updateLine(line, text, markedSpans, estimateHeight) {\n
    line.text = text;\n
    if (line.stateAfter) line.stateAfter = null;\n
    if (line.styles) line.styles = null;\n
    if (line.order != null) line.order = null;\n
    detachMarkedSpans(line);\n
    attachMarkedSpans(line, markedSpans);\n
    var estHeight = estimateHeight ? estimateHeight(line) : 1;\n
    if (estHeight != line.height) updateLineHeight(line, estHeight);\n
  }\n
\n
  // Detach a line from the document tree and its markers.\n
  function cleanUpLine(line) {\n
    line.parent = null;\n
    detachMarkedSpans(line);\n
  }\n
\n
  function extractLineClasses(type, output) {\n
    if (type) for (;;) {\n
      var lineClass = type.match(/(?:^|\\s+)line-(background-)?(\\S+)/);\n
      if (!lineClass) break;\n
      type = type.slice(0, lineClass.index) + type.slice(lineClass.index + lineClass[0].length);\n
      var prop = lineClass[1] ? "bgClass" : "textClass";\n
      if (output[prop] == null)\n
        output[prop] = lineClass[2];\n
      else if (!(new RegExp("(?:^|\\s)" + lineClass[2] + "(?:$|\\s)")).test(output[prop]))\n
        output[prop] += " " + lineClass[2];\n
    }\n
    return type;\n
  }\n
\n
  function callBlankLine(mode, state) {\n
    if (mode.blankLine) return mode.blankLine(state);\n
    if (!mode.innerMode) return;\n
    var inner = CodeMirror.innerMode(mode, state);\n
    if (inner.mode.blankLine) return inner.mode.blankLine(inner.state);\n
  }\n
\n
  function readToken(mode, stream, state, inner) {\n
    for (var i = 0; i < 10; i++) {\n
      if (inner) inner[0] = CodeMirror.innerMode(mode, state).mode;\n
      var style = mode.token(stream, state);\n
      if (stream.pos > stream.start) return style;\n
    }\n
    throw new Error("Mode " + mode.name + " failed to advance stream.");\n
  }\n
\n
  // Utility for getTokenAt and getLineTokens\n
  function takeToken(cm, pos, precise, asArray) {\n
    function getObj(copy) {\n
      return {start: stream.start, end: stream.pos,\n
              string: stream.current(),\n
              type: style || null,\n
              state: copy ? copyState(doc.mode, state) : state};\n
    }\n
\n
    var doc = cm.doc, mode = doc.mode, style;\n
    pos = clipPos(doc, pos);\n
    var line = getLine(doc, pos.line), state = getStateBefore(cm, pos.line, precise);\n
    var stream = new StringStream(line.text, cm.options.tabSize), tokens;\n
    if (asArray) tokens = [];\n
    while ((asArray || stream.pos < pos.ch) && !stream.eol()) {\n
      stream.start = stream.pos;\n
      style = readToken(mode, stream, state);\n
      if (asArray) tokens.push(getObj(true));\n
    }\n
    return asArray ? tokens : getObj();\n
  }\n
\n
  // Run the given mode\'s parser over a line, calling f for each token.\n
  function runMode(cm, text, mode, state, f, lineClasses, forceToEnd) {\n
    var flattenSpans = mode.flattenSpans;\n
    if (flattenSpans == null) flattenSpans = cm.options.flattenSpans;\n
    var curStart = 0, curStyle = null;\n
    var stream = new StringStream(text, cm.options.tabSize), style;\n
    var inner = cm.options.addModeClass && [null];\n
    if (text == "") extractLineClasses(callBlankLine(mode, state), lineClasses);\n
    while (!stream.eol()) {\n
      if (stream.pos > cm.options.maxHighlightLength) {\n
        flattenSpans = false;\n
        if (forceToEnd) processLine(cm, text, state, stream.pos);\n
        stream.pos = text.length;\n
        style = null;\n
      } else {\n
        style = extractLineClasses(readToken(mode, stream, state, inner), lineClasses);\n
      }\n
      if (inner) {\n
        var mName = inner[0].name;\n
        if (mName) style = "m-" + (style ? mName + " " + style : mName);\n
      }\n
      if (!flattenSpans || curStyle != style) {\n
        while (curStart < stream.start) {\n
          curStart = Math.min(stream.start, curStart + 50000);\n
          f(curStart, curStyle);\n
        }\n
        curStyle = style;\n
      }\n
      stream.start = stream.pos;\n
    }\n
    while (curStart < stream.pos) {\n
      // Webkit seems to refuse to render text nodes longer than 57444 characters\n
      var pos = Math.min(stream.pos, curStart + 50000);\n
      f(pos, curStyle);\n
      curStart = pos;\n
    }\n
  }\n
\n
  // Compute a style array (an array starting with a mode generation\n
  // -- for invalidation -- followed by pairs of end positions and\n
  // style strings), which is used to highlight the tokens on the\n
  // line.\n
  function highlightLine(cm, line, state, forceToEnd) {\n
    // A styles array always starts with a number identifying the\n
    // mode/overlays that it is based on (for easy invalidation).\n
    var st = [cm.state.modeGen], lineClasses = {};\n
    // Compute the base array of styles\n
    runMode(cm, line.text, cm.doc.mode, state, function(end, style) {\n
      st.push(end, style);\n
    }, lineClasses, forceToEnd);\n
\n
    // Run overlays, adjust style array.\n
    for (var o = 0; o < cm.state.overlays.length; ++o) {\n
      var overlay = cm.state.overlays[o], i = 1, at = 0;\n
      runMode(cm, line.text, overlay.mode, true, function(end, style) {\n
        var start = i;\n
        // Ensure there\'s a token end at the current position, and that i points at it\n
        while (at < end) {\n
          var i_end = st[i];\n
          if (i_end > end)\n
            st.splice(i, 1, end, st[i+1], i_end);\n
          i += 2;\n
          at = Math.min(end, i_end);\n
        }\n
        if (!style) return;\n
        if (overlay.opaque) {\n
          st.splice(start, i - start, end, "cm-overlay " + style);\n
          i = start + 2;\n
        } else {\n
          for (; start < i; start += 2) {\n
            var cur = st[start+1];\n
            st[start+1] = (cur ? cur + " " : "") + "cm-overlay " + style;\n
          }\n
        }\n
      }, lineClasses);\n
    }\n
\n
    return {styles: st, classes: lineClasses.bgClass || lineClasses.textClass ? lineClasses : null};\n
  }\n
\n
  function getLineStyles(cm, line, updateFrontier) {\n
    if (!line.styles || line.styles[0] != cm.state.modeGen) {\n
      var state = getStateBefore(cm, lineNo(line));\n
      var result = highlightLine(cm, line, line.text.length > cm.options.maxHighlightLength ? copyState(cm.doc.mode, state) : state);\n
      line.stateAfter = state;\n
      line.styles = result.styles;\n
      if (result.classes) line.styleClasses = result.classes;\n
      else if (line.styleClasses) line.styleClasses = null;\n
      if (updateFrontier === cm.doc.frontier) cm.doc.frontier++;\n
    }\n
    return line.styles;\n
  }\n
\n
  // Lightweight form of highlight -- proceed over this line and\n
  // update state, but don\'t save a style array. Used for lines that\n
  // aren\'t currently visible.\n
  function processLine(cm, text, state, startAt) {\n
    var mode = cm.doc.mode;\n
    var stream = new StringStream(text, cm.options.tabSize);\n
    stream.start = stream.pos = startAt || 0;\n
    if (text == "") callBlankLine(mode, state);\n
    while (!stream.eol()) {\n
      readToken(mode, stream, state);\n
      stream.start = stream.pos;\n
    }\n
  }\n
\n
  // Convert a style as returned by a mode (either null, or a string\n
  // containing one or more styles) to a CSS style. This is cached,\n
  // and also looks for line-wide styles.\n
  var styleToClassCache = {}, styleToClassCacheWithMode = {};\n
  function interpretTokenStyle(style, options) {\n
    if (!style || /^\\s*$/.test(style)) return null;\n
    var cache = options.addModeClass ? styleToClassCacheWithMode : styleToClassCache;\n
    return cache[style] ||\n
      (cache[style] = style.replace(/\\S+/g, "cm-$&"));\n
  }\n
\n
  // Render the DOM representation of the text of a line. Also builds\n
  // up a \'line map\', which points at the DOM nodes that represent\n
  // specific stretches of text, and is used by the measuring code.\n
  // The returned object contains the DOM node, this map, and\n
  // information about line-wide styles that were set by the mode.\n
  function buildLineContent(cm, lineView) {\n
    // The padding-right forces the element to have a \'border\', which\n
    // is needed on Webkit to be able to get line-level bounding\n
    // rectangles for it (in measureChar).\n
    var content = elt("span", null, null, webkit ? "padding-right: .1px" : null);\n
    var builder = {pre: elt("pre", [content], "CodeMirror-line"), content: content,\n
                   col: 0, pos: 0, cm: cm,\n
                   splitSpaces: (ie || webkit) && cm.getOption("lineWrapping")};\n
    lineView.measure = {};\n
\n
    // Iterate over the logical lines that make up this visual line.\n
    for (var i = 0; i <= (lineView.rest ? lineView.rest.length : 0); i++) {\n
      var line = i ? lineView.rest[i - 1] : lineView.line, order;\n
      builder.pos = 0;\n
      builder.addToken = buildToken;\n
      // Optionally wire in some hacks into the token-rendering\n
      // algorithm, to deal with browser quirks.\n
      if (hasBadBidiRects(cm.display.measure) && (order = getOrder(line)))\n
        builder.addToken = buildTokenBadBidi(builder.addToken, order);\n
      builder.map = [];\n
      var allowFrontierUpdate = lineView != cm.display.externalMeasured && lineNo(line);\n
      insertLineContent(line, builder, getLineStyles(cm, line, allowFrontierUpdate));\n
      if (line.styleClasses) {\n
        if (line.styleClasses.bgClass)\n
          builder.bgClass = joinClasses(line.styleClasses.bgClass, builder.bgClass || "");\n
        if (line.styleClasses.textClass)\n
          builder.textClass = joinClasses(line.styleClasses.textClass, builder.textClass || "");\n
      }\n
\n
      // Ensure at least a single node is present, for measuring.\n
      if (builder.map.length == 0)\n
        builder.map.push(0, 0, builder.content.appendChild(zeroWidthElement(cm.display.measure)));\n
\n
      // Store the map and a cache object for the current logical line\n
      if (i == 0) {\n
        lineView.measure.map = builder.map;\n
        lineView.measure.cache = {};\n
      } else {\n
        (lineView.measure.maps || (lineView.measure.maps = [])).push(builder.map);\n
        (lineView.measure.caches || (lineView.measure.caches = [])).push({});\n
      }\n
    }\n
\n
    // See issue #2901\n
    if (webkit && /\\bcm-tab\\b/.test(builder.content.lastChild.className))\n
      builder.content.className = "cm-tab-wrap-hack";\n
\n
    signal(cm, "renderLine", cm, lineView.line, builder.pre);\n
    if (builder.pre.className)\n
      builder.textClass = joinClasses(builder.pre.className, builder.textClass || "");\n
\n
    return builder;\n
  }\n
\n
  function defaultSpecialCharPlaceholder(ch) {\n
    var token = elt("span", "\\u2022", "cm-invalidchar");\n
    token.title = "\\\\u" + ch.charCodeAt(0).toString(16);\n
    token.setAttribute("aria-label", token.title);\n
    return token;\n
  }\n
\n
  // Build up the DOM representation for a single token, and add it to\n
  // the line map. Takes care to render special characters separately.\n
  function buildToken(builder, text, style, startStyle, endStyle, title, css) {\n
    if (!text) return;\n
    var displayText = builder.splitSpaces ? text.replace(/ {3,}/g, splitSpaces) : text;\n
    var special = builder.cm.state.specialChars, mustWrap = false;\n
    if (!special.test(text)) {\n
      builder.col += text.length;\n
      var content = document.createTextNode(displayText);\n
      builder.map.push(builder.pos, builder.pos + text.length, content);\n
      if (ie && ie_version < 9) mustWrap = true;\n
      builder.pos += text.length;\n
    } else {\n
      var content = document.createDocumentFragment(), pos = 0;\n
      while (true) {\n
        special.lastIndex = pos;\n
        var m = special.exec(text);\n
        var skipped = m ? m.index - pos : text.length - pos;\n
        if (skipped) {\n
          var txt = document.createTextNode(displayText.slice(pos, pos + skipped));\n
          if (ie && ie_version < 9) content.appendChild(elt("span", [txt]));\n
          else content.appendChild(txt);\n
          builder.map.push(builder.pos, builder.pos + skipped, txt);\n
          builder.col += skipped;\n
          builder.pos += skipped;\n
        }\n
        if (!m) break;\n
        pos += skipped + 1;\n
        if (m[0] == "\\t") {\n
          var tabSize = builder.cm.options.tabSize, tabWidth = tabSize - builder.col % tabSize;\n
          var txt = content.appendChild(elt("span", spaceStr(tabWidth), "cm-tab"));\n
          txt.setAttribute("role", "presentation");\n
          txt.setAttribute("cm-text", "\\t");\n
          builder.col += tabWidth;\n
        } else if (m[0] == "\\r" || m[0] == "\\n") {\n
          var txt = content.appendChild(elt("span", m[0] == "\\r" ? "\\u240d" : "\\u2424", "cm-invalidchar"));\n
          txt.setAttribute("cm-text", m[0]);\n
          builder.col += 1;\n
        } else {\n
          var txt = builder.cm.options.specialCharPlaceholder(m[0]);\n
          txt.setAttribute("cm-text", m[0]);\n
          if (ie && ie_version < 9) content.appendChild(elt("span", [txt]));\n
          else content.appendChild(txt);\n
          builder.col += 1;\n
        }\n
        builder.map.push(builder.pos, builder.pos + 1, txt);\n
        builder.pos++;\n
      }\n
    }\n
    if (style || startStyle || endStyle || mustWrap || css) {\n
      var fullStyle = style || "";\n
      if (startStyle) fullStyle += startStyle;\n
      if (endStyle) fullStyle += endStyle;\n
      var token = elt("span", [content], fullStyle, css);\n
      if (title) token.title = title;\n
      return builder.content.appendChild(token);\n
    }\n
    builder.content.appendChild(content);\n
  }\n
\n
  function splitSpaces(old) {\n
    var out = " ";\n
    for (var i = 0; i < old.length - 2; ++i) out += i % 2 ? " " : "\\u00a0";\n
    out += " ";\n
    return out;\n
  }\n
\n
  // Work around nonsense dimensions being reported for stretches of\n
  // right-to-left text.\n
  function buildTokenBadBidi(inner, order) {\n
    return function(builder, text, style, startStyle, endStyle, title, css) {\n
      style = style ? style + " cm-force-border" : "cm-force-border";\n
      var start = builder.pos, end = start + text.length;\n
      for (;;) {\n
        // Find the part that overlaps with the start of this text\n
        for (var i = 0; i < order.length; i++) {\n
          var part = order[i];\n
          if (part.to > start && part.from <= start) break;\n
        }\n
        if (part.to >= end) return inner(builder, text, style, startStyle, endStyle, title, css);\n
        inner(builder, text.slice(0, part.to - start), style, startStyle, null, title, css);\n
        startStyle = null;\n
        text = text.slice(part.to - start);\n
        start = part.to;\n
      }\n
    };\n
  }\n
\n
  function buildCollapsedSpan(builder, size, marker, ignoreWidget) {\n
    var widget = !ignoreWidget && marker.widgetNode;\n
    if (widget) builder.map.push(builder.pos, builder.pos + size, widget);\n
    if (!ignoreWidget && builder.cm.display.input.needsContentAttribute) {\n
      if (!widget)\n
        widget = builder.content.appendChild(document.createElement("span"));\n
      widget.setAttribute("cm-marker", marker.id);\n
    }\n
    if (widget) {\n
      builder.cm.display.input.setUneditable(widget);\n
      builder.content.appendChild(widget);\n
    }\n
    builder.pos += size;\n
  }\n
\n
  // Outputs a number of spans to make up a line, taking highlighting\n
  // and marked text into account.\n
  function insertLineContent(line, builder, styles) {\n
    var spans = line.markedSpans, allText = line.text, at = 0;\n
    if (!spans) {\n
      for (var i = 1; i < styles.length; i+=2)\n
        builder.addToken(builder, allText.slice(at, at = styles[i]), interpretTokenStyle(styles[i+1], builder.cm.options));\n
      return;\n
    }\n
\n
    var len = allText.length, pos = 0, i = 1, text = "", style, css;\n
    var nextChange = 0, spanStyle, spanEndStyle, spanStartStyle, title, collapsed;\n
    for (;;) {\n
      if (nextChange == pos) { // Update current marker set\n
        spanStyle = spanEndStyle = spanStartStyle = title = css = "";\n
        collapsed = null; nextChange = Infinity;\n
        var foundBookmarks = [], endStyles\n
        for (var j = 0; j < spans.length; ++j) {\n
          var sp = spans[j], m = sp.marker;\n
          if (m.type == "bookmark" && sp.from == pos && m.widgetNode) {\n
            foundBookmarks.push(m);\n
          } else if (sp.from <= pos && (sp.to == null || sp.to > pos || m.collapsed && sp.to == pos && sp.from == pos)) {\n
            if (sp.to != null && sp.to != pos && nextChange > sp.to) {\n
              nextChange = sp.to;\n
              spanEndStyle = "";\n
            }\n
            if (m.className) spanStyle += " " + m.className;\n
            if (m.css) css = (css ? css + ";" : "") + m.css;\n
            if (m.startStyle && sp.from == pos) spanStartStyle += " " + m.startStyle;\n
            if (m.endStyle && sp.to == nextChange) (endStyles || (endStyles = [])).push(m.endStyle, sp.to)\n
            if (m.title && !title) title = m.title;\n
            if (m.collapsed && (!collapsed || compareCollapsedMarkers(collapsed.marker, m) < 0))\n
              collapsed = sp;\n
          } else if (sp.from > pos && nextChange > sp.from) {\n
            nextChange = sp.from;\n
          }\n
        }\n
        if (endStyles) for (var j = 0; j < endStyles.length; j += 2)\n
          if (endStyles[j + 1] == nextChange) spanEndStyle += " " + endStyles[j]\n
\n
        if (collapsed && (collapsed.from || 0) == pos) {\n
          buildCollapsedSpan(builder, (collapsed.to == null ? len + 1 : collapsed.to) - pos,\n
                             collapsed.marker, collapsed.from == null);\n
          if (collapsed.to == null) return;\n
          if (collapsed.to == pos) collapsed = false;\n
        }\n
        if (!collapsed && foundBookmarks.length) for (var j = 0; j < foundBookmarks.length; ++j)\n
          buildCollapsedSpan(builder, 0, foundBookmarks[j]);\n
      }\n
      if (pos >= len) break;\n
\n
      var upto = Math.min(len, nextChange);\n
      while (true) {\n
        if (text) {\n
          var end = pos + text.length;\n
          if (!collapsed) {\n
            var tokenText = end > upto ? text.slice(0, upto - pos) : text;\n
            builder.addToken(builder, tokenText, style ? style + spanStyle : spanStyle,\n
                             spanStartStyle, pos + tokenText.length == nextChange ? spanEndStyle : "", title, css);\n
          }\n
          if (end >= upto) {text = text.slice(upto - pos); pos = upto; break;}\n
          pos = end;\n
          spanStartStyle = "";\n
        }\n
        text = allText.slice(at, at = styles[i++]);\n
        style = interpretTokenStyle(styles[i++], builder.cm.options);\n
      }\n
    }\n
  }\n
\n
  // DOCUMENT DATA STRUCTURE\n
\n
  // By default, updates that start and end at the beginning of a line\n
  // are treated specially, in order to make the association of line\n
  // widgets and marker elements with the text behave more intuitive.\n
  function isWholeLineUpdate(doc, change) {\n
    return change.from.ch == 0 && change.to.ch == 0 && lst(change.text) == "" &&\n
      (!doc.cm || doc.cm.options.wholeLineUpdateBefore);\n
  }\n
\n
  // Perform a change on the document data structure.\n
  function updateDoc(doc, change, markedSpans, estimateHeight) {\n
    function spansFor(n) {return markedSpans ? markedSpans[n] : null;}\n
    function update(line, text, spans) {\n
      updateLine(line, text, spans, estimateHeight);\n
      signalLater(line, "change", line, change);\n
    }\n
    function linesFor(start, end) {\n
      for (var i = start, result = []; i < end; ++i)\n
        result.push(new Line(text[i], spansFor(i), estimateHeight));\n
      return result;\n
    }\n
\n
    var from = change.from, to = change.to, text = change.text;\n
    var firstLine = getLine(doc, from.line), lastLine = getLine(doc, to.line);\n
    var lastText = lst(text), lastSpans = spansFor(text.length - 1), nlines = to.line - from.line;\n
\n
    // Adjust the line structure\n
    if (change.full) {\n
      doc.insert(0, linesFor(0, text.length));\n
      doc.remove(text.length, doc.size - text.length);\n
    } else if (isWholeLineUpdate(doc, change)) {\n
      // This is a whole-line replace. Treated specially to make\n
      // sure line objects move the way they are supposed to.\n
      var added = linesFor(0, text.length - 1);\n
      update(lastLine, lastLine.text, lastSpans);\n
      if (nlines) doc.remove(from.line, nlines);\n
      if (added.length) doc.insert(from.line, added);\n
    } else if (firstLine == lastLine) {\n
      if (text.length == 1) {\n
        update(firstLine, firstLine.text.slice(0, from.ch) + lastText + firstLine.text.slice(to.ch), lastSpans);\n
      } else {\n
        var added = linesFor(1, text.length - 1);\n
        added.push(new Line(lastText + firstLine.text.slice(to.ch), lastSpans, estimateHeight));\n
        update(firstLine, firstLine.text.slice(0, from.ch) + text[0], spansFor(0));\n
        doc.insert(from.line + 1, added);\n
      }\n
    } else if (text.length == 1) {\n
      update(firstLine, firstLine.text.slice(0, from.ch) + text[0] + lastLine.text.slice(to.ch), spansFor(0));\n
      doc.remove(from.line + 1, nlines);\n
    } else {\n
      update(firstLine, firstLine.text.slice(0, from.ch) + text[0], spansFor(0));\n
      update(lastLine, lastText + lastLine.text.slice(to.ch), lastSpans);\n
      var added = linesFor(1, text.length - 1);\n
      if (nlines > 1) doc.remove(from.line + 1, nlines - 1);\n
      doc.insert(from.line + 1, added);\n
    }\n
\n
    signalLater(doc, "change", doc, change);\n
  }\n
\n
  // The document is represented as a BTree consisting of leaves, with\n
  // chunk of lines in them, and branches, with up to ten leaves or\n
  // other branch nodes below them. The top node is always a branch\n
  // node, and is the document object itself (meaning it has\n
  // additional methods and properties).\n
  //\n
  // All nodes have parent links. The tree is used both to go from\n
  // line numbers to line objects, and to go from objects to numbers.\n
  // It also indexes by height, and is used to convert between height\n
  // and line object, and to find the total height of the document.\n
  //\n
  // See also http://marijnhaverbeke.nl/blog/codemirror-line-tree.html\n
\n
  function LeafChunk(lines) {\n
    this.lines = lines;\n
    this.parent = null;\n
    for (var i = 0, height = 0; i < lines.length; ++i) {\n
      lines[i].parent = this;\n
      height += lines[i].height;\n
    }\n
    this.height = height;\n
  }\n
\n
  LeafChunk.prototype = {\n
    chunkSize: function() { return this.lines.length; },\n
    // Remove the n lines at offset \'at\'.\n
    removeInner: function(at, n) {\n
      for (var i = at, e = at + n; i < e; ++i) {\n
        var line = this.lines[i];\n
        this.height -= line.height;\n
        cleanUpLine(line);\n
        signalLater(line, "delete");\n
      }\n
      this.lines.splice(at, n);\n
    },\n
    // Helper used to collapse a small branch into a single leaf.\n
    collapse: function(lines) {\n
      lines.push.apply(lines, this.lines);\n
    },\n
    // Insert the given array of lines at offset \'at\', count them as\n
    // having the given height.\n
    insertInner: function(at, lines, height) {\n
      this.height += height;\n
      this.lines = this.lines.slice(0, at).concat(lines).concat(this.lines.slice(at));\n
      for (var i = 0; i < lines.length; ++i) lines[i].parent = this;\n
    },\n
    // Used to iterate over a part of the tree.\n
    iterN: function(at, n, op) {\n
      for (var e = at + n; at < e; ++at)\n
        if (op(this.lines[at])) return true;\n
    }\n
  };\n
\n
  function BranchChunk(children) {\n
    this.children = children;\n
    var size = 0, height = 0;\n
    for (var i = 0; i < children.length; ++i) {\n
      var ch = children[i];\n
      size += ch.chunkSize(); height += ch.height;\n
      ch.parent = this;\n
    }\n
    this.size = size;\n
    this.height = height;\n
    this.parent = null;\n
  }\n
\n
  BranchChunk.prototype = {\n
    chunkSize: function() { return this.size; },\n
    removeInner: function(at, n) {\n
      this.size -= n;\n
      for (var i = 0; i < this.children.length; ++i) {\n
        var child = this.children[i], sz = child.chunkSize();\n
        if (at < sz) {\n
          var rm = Math.min(n, sz - at), oldHeight = child.height;\n
          child.removeInner(at, rm);\n
          this.height -= oldHeight - child.height;\n
          if (sz == rm) { this.children.splice(i--, 1); child.parent = null; }\n
          if ((n -= rm) == 0) break;\n
          at = 0;\n
        } else at -= sz;\n
      }\n
      // If the result is smaller than 25 lines, ensure that it is a\n
      // single leaf node.\n
      if (this.size - n < 25 &&\n
          (this.children.length > 1 || !(this.children[0] instanceof LeafChunk))) {\n
        var lines = [];\n
        this.collapse(lines);\n
        this.children = [new LeafChunk(lines)];\n
        this.children[0].parent = this;\n
      }\n
    },\n
    collapse: function(lines) {\n
      for (var i = 0; i < this.children.length; ++i) this.children[i].collapse(lines);\n
    },\n
    insertInner: function(at, lines, height) {\n
      this.size += lines.length;\n
      this.height += height;\n
      for (var i = 0; i < this.children.length; ++i) {\n
        var child = this.children[i], sz = child.chunkSize();\n
        if (at <= sz) {\n
          child.insertInner(at, lines, height);\n
          if (child.lines && child.lines.length > 50) {\n
            while (child.lines.length > 50) {\n
              var spilled = child.lines.splice(child.lines.length - 25, 25);\n
              var newleaf = new LeafChunk(spilled);\n
              child.height -= newleaf.height;\n
              this.children.splice(i + 1, 0, newleaf);\n
              newleaf.parent = this;\n
            }\n
            this.maybeSpill();\n
          }\n
          break;\n
        }\n
        at -= sz;\n
      }\n
    },\n
    // When a node has grown, check whether it should be split.\n
    maybeSpill: function() {\n
      if (this.children.length <= 10) return;\n
      var me = this;\n
      do {\n
        var spilled = me.children.splice(me.children.length - 5, 5);\n
        var sibling = new BranchChunk(spilled);\n
        if (!me.parent) { // Become the parent node\n
          var copy = new BranchChunk(me.children);\n
          copy.parent = me;\n
          me.children = [copy, sibling];\n
          me = copy;\n
        } else {\n
          me.size -= sibling.size;\n
          me.height -= sibling.height;\n
          var myIndex = indexOf(me.parent.children, me);\n
          me.parent.children.splice(myIndex + 1, 0, sibling);\n
        }\n
        sibling.parent = me.parent;\n
      } while (me.children.length > 10);\n
      me.parent.maybeSpill();\n
    },\n
    iterN: function(at, n, op) {\n
      for (var i = 0; i < this.children.length; ++i) {\n
        var child = this.children[i], sz = child.chunkSize();\n
        if (at < sz) {\n
          var used = Math.min(n, sz - at);\n
          if (child.iterN(at, used, op)) return true;\n
          if ((n -= used) == 0) break;\n
          at = 0;\n
        } else at -= sz;\n
      }\n
    }\n
  };\n
\n
  var nextDocId = 0;\n
  var Doc = CodeMirror.Doc = function(text, mode, firstLine, lineSep) {\n
    if (!(this instanceof Doc)) return new Doc(text, mode, firstLine, lineSep);\n
    if (firstLine == null) firstLine = 0;\n
\n
    BranchChunk.call(this, [new LeafChunk([new Line("", null)])]);\n
    this.first = firstLine;\n
    this.scrollTop = this.scrollLeft = 0;\n
    this.cantEdit = false;\n
    this.cleanGeneration = 1;\n
    this.frontier = firstLine;\n
    var start = Pos(firstLine, 0);\n
    this.sel = simpleSelection(start);\n
    this.history = new History(null);\n
    this.id = ++nextDocId;\n
    this.modeOption = mode;\n
    this.lineSep = lineSep;\n
    this.extend = false;\n
\n
    if (typeof text == "string") text = this.splitLines(text);\n
    updateDoc(this, {from: start, to: start, text: text});\n
    setSelection(this, simpleSelection(start), sel_dontScroll);\n
  };\n
\n
  Doc.prototype = createObj(BranchChunk.prototype, {\n
    constructor: Doc,\n
    // Iterate over the document. Supports two forms -- with only one\n
    // argument, it calls that for each line in the document. With\n
    // three, it iterates over the range given by the first two (with\n
    // the second being non-inclusive).\n
    iter: function(from, to, op) {\n
      if (op) this.iterN(from - this.first, to - from, op);\n
      else this.iterN(this.first, this.first + this.size, from);\n
    },\n
\n
    // Non-public interface for adding and removing lines.\n
    insert: function(at, lines) {\n
      var height = 0;\n
      for (var i = 0; i < lines.length; ++i) height += lines[i].height;\n
      this.insertInner(at - this.first, lines, height);\n
    },\n
    remove: function(at, n) { this.removeInner(at - this.first, n); },\n
\n
    // From here, the methods are part of the public interface. Most\n
    // are also available from CodeMirror (editor) instances.\n
\n
    getValue: function(lineSep) {\n
      var lines = getLines(this, this.first, this.first + this.size);\n
      if (lineSep === false) return lines;\n
      return lines.join(lineSep || this.lineSeparator());\n
    },\n
    setValue: docMethodOp(function(code) {\n
      var top = Pos(this.first, 0), last = this.first + this.size - 1;\n
      makeChange(this, {from: top, to: Pos(last, getLine(this, last).text.length),\n
                        text: this.splitLines(code), origin: "setValue", full: true}, true);\n
      setSelection(this, simpleSelection(top));\n
    }),\n
    replaceRange: function(code, from, to, origin) {\n
      from = clipPos(this, from);\n
      to = to ? clipPos(this, to) : from;\n
      replaceRange(this, code, from, to, origin);\n
    },\n
    getRange: function(from, to, lineSep) {\n
      var lines = getBetween(this, clipPos(this, from), clipPos(this, to));\n
      if (lineSep === false) return lines;\n
      return lines.join(lineSep || this.lineSeparator());\n
    },\n
\n
    getLine: function(line) {var l = this.getLineHandle(line); return l && l.text;},\n
\n
    getLineHandle: function(line) {if (isLine(this, line)) return getLine(this, line);},\n
    getLineNumber: function(line) {return lineNo(line);},\n
\n
    getLineHandleVisualStart: function(line) {\n
      if (typeof line == "number") line = getLine(this, line);\n
      return visualLine(line);\n
    },\n
\n
    lineCount: function() {return this.size;},\n
    firstLine: function() {return this.first;},\n
    lastLine: function() {return this.first + this.size - 1;},\n
\n
    clipPos: function(pos) {return clipPos(this, pos);},\n
\n
    getCursor: function(start) {\n
      var range = this.sel.primary(), pos;\n
      if (start == null || start == "head") pos = range.head;\n
      else if (start == "anchor") pos = range.anchor;\n
      else if (start == "end" || start == "to" || start === false) pos = range.to();\n
      else pos = range.from();\n
      return pos;\n
    },\n
    listSelections: function() { return this.sel.ranges; },\n
    somethingSelected: function() {return this.sel.somethingSelected();},\n
\n
    setCursor: docMethodOp(function(line, ch, options) {\n
      setSimpleSelection(this, clipPos(this, typeof line == "number" ? Pos(line, ch || 0) : line), null, options);\n
    }),\n
    setSelection: docMethodOp(function(anchor, head, options) {\n
      setSimpleSelection(this, clipPos(this, anchor), clipPos(this, head || anchor), options);\n
    }),\n
    extendSelection: docMethodOp(function(head, other, options) {\n
      extendSelection(this, clipPos(this, head), other && clipPos(this, other), options);\n
    }),\n
    extendSelections: docMethodOp(function(heads, options) {\n
      extendSelections(this, clipPosArray(this, heads), options);\n
    }),\n
    extendSelectionsBy: docMethodOp(function(f, options) {\n
      var heads = map(this.sel.ranges, f);\n
      extendSelections(this, clipPosArray(this, heads), options);\n
    }),\n
    setSelections: docMethodOp(function(ranges, primary, options) {\n
      if (!ranges.length) return;\n
      for (var i = 0, out = []; i < ranges.length; i++)\n
        out[i] = new Range(clipPos(this, ranges[i].anchor),\n
                           clipPos(this, ranges[i].head));\n
      if (primary == null) primary = Math.min(ranges.length - 1, this.sel.primIndex);\n
      setSelection(this, normalizeSelection(out, primary), options);\n
    }),\n
    addSelection: docMethodOp(function(anchor, head, options) {\n
      var ranges = this.sel.ranges.slice(0);\n
      ranges.push(new Range(clipPos(this, anchor), clipPos(this, head || anchor)));\n
      setSelection(this, normalizeSelection(ranges, ranges.length - 1), options);\n
    }),\n
\n
    getSelection: function(lineSep) {\n
      var ranges = this.sel.ranges, lines;\n
      for (var i = 0; i < ranges.length; i++) {\n
        var sel = getBetween(this, ranges[i].from(), ranges[i].to());\n
        lines = lines ? lines.concat(sel) : sel;\n
      }\n
      if (lineSep === false) return lines;\n
      else return lines.join(lineSep || this.lineSeparator());\n
    },\n
    getSelections: function(lineSep) {\n
      var parts = [], ranges = this.sel.ranges;\n
      for (var i = 0; i < ranges.length; i++) {\n
        var sel = getBetween(this, ranges[i].from(), ranges[i].to());\n
        if (lineSep !== false) sel = sel.join(lineSep || this.lineSeparator());\n
        parts[i] = sel;\n
      }\n
      return parts;\n
    },\n
    replaceSelection: function(code, collapse, origin) {\n
      var dup = [];\n
      for (var i = 0; i < this.sel.ranges.length; i++)\n
        dup[i] = code;\n
      this.replaceSelections(dup, collapse, origin || "+input");\n
    },\n
    replaceSelections: docMethodOp(function(code, collapse, origin) {\n
      var changes = [], sel = this.sel;\n
      for (var i = 0; i < sel.ranges.length; i++) {\n
        var range = sel.ranges[i];\n
        changes[i] = {from: range.from(), to: range.to(), text: this.splitLines(code[i]), origin: origin};\n
      }\n
      var newSel = collapse && collapse != "end" && computeReplacedSel(this, changes, collapse);\n
      for (var i = changes.length - 1; i >= 0; i--)\n
        makeChange(this, changes[i]);\n
      if (newSel) setSelectionReplaceHistory(this, newSel);\n
      else if (this.cm) ensureCursorVisible(this.cm);\n
    }),\n
    undo: docMethodOp(function() {makeChangeFromHistory(this, "undo");}),\n
    redo: docMethodOp(function() {makeChangeFromHistory(this, "redo");}),\n
    undoSelection: docMethodOp(function() {makeChangeFromHistory(this, "undo", true);}),\n
    redoSelection: docMethodOp(function() {makeChangeFromHistory(this, "redo", true);}),\n
\n
    setExtending: function(val) {this.extend = val;},\n
    getExtending: function() {return this.extend;},\n
\n
    historySize: function() {\n
      var hist = this.history, done = 0, undone = 0;\n
      for (var i = 0; i < hist.done.length; i++) if (!hist.done[i].ranges) ++done;\n
      for (var i = 0; i < hist.undone.length; i++) if (!hist.undone[i].ranges) ++undone;\n
      return {undo: done, redo: undone};\n
    },\n
    clearHistory: function() {this.history = new History(this.history.maxGeneration);},\n
\n
    markClean: function() {\n
      this.cleanGeneration = this.changeGeneration(true);\n
    },\n
    changeGeneration: function(forceSplit) {\n
      if (forceSplit)\n
        this.history.lastOp = this.history.lastSelOp = this.history.lastOrigin = null;\n
      return this.history.generation;\n
    },\n
    isClean: function (gen) {\n
      return this.history.generation == (gen || this.cleanGeneration);\n
    },\n
\n
    getHistory: function() {\n
      return {done: copyHistoryArray(this.history.done),\n
              undone: copyHistoryArray(this.history.undone)};\n
    },\n
    setHistory: function(histData) {\n
      var hist = this.history = new History(this.history.maxGeneration);\n
      hist.done = copyHistoryArray(histData.done.slice(0), null, true);\n
      hist.undone = copyHistoryArray(histData.undone.slice(0), null, true);\n
    },\n
\n
    addLineClass: docMethodOp(function(handle, where, cls) {\n
      return changeLine(this, handle, where == "gutter" ? "gutter" : "class", function(line) {\n
        var prop = where == "text" ? "textClass"\n
                 : where == "background" ? "bgClass"\n
                 : where == "gutter" ? "gutterClass" : "wrapClass";\n
        if (!line[prop]) line[prop] = cls;\n
        else if (classTest(cls).test(line[prop])) return false;\n
        else line[prop] += " " + cls;\n
        return true;\n
      });\n
    }),\n
    removeLineClass: docMethodOp(function(handle, where, cls) {\n
      return changeLine(this, handle, where == "gutter" ? "gutter" : "class", function(line) {\n
        var prop = where == "text" ? "textClass"\n
                 : where == "background" ? "bgClass"\n
                 : where == "gutter" ? "gutterClass" : "wrapClass";\n
        var cur = line[prop];\n
        if (!cur) return false;\n
        else if (cls == null) line[prop] = null;\n
        else {\n
          var found = cur.match(classTest(cls));\n
          if (!found) return false;\n
          var end = found.index + found[0].length;\n
          line[prop] = cur.slice(0, found.index) + (!found.index || end == cur.length ? "" : " ") + cur.slice(end) || null;\n
        }\n
        return true;\n
      });\n
    }),\n
\n
    addLineWidget: docMethodOp(function(handle, node, options) {\n
      return addLineWidget(this, handle, node, options);\n
    }),\n
    removeLineWidget: function(widget) { widget.clear(); },\n
\n
    markText: function(from, to, options) {\n
      return markText(this, clipPos(this, from), clipPos(this, to), options, options && options.type || "range");\n
    },\n
    setBookmark: function(pos, options) {\n
      var realOpts = {replacedWith: options && (options.nodeType == null ? options.widget : options),\n
                      insertLeft: options && options.insertLeft,\n
                      clearWhenEmpty: false, shared: options && options.shared,\n
                      handleMouseEvents: options && options.handleMouseEvents};\n
      pos = clipPos(this, pos);\n
      return markText(this, pos, pos, realOpts, "bookmark");\n
    },\n
    findMarksAt: function(pos) {\n
      pos = clipPos(this, pos);\n
      var markers = [], spans = getLine(this, pos.line).markedSpans;\n
      if (spans) for (var i = 0; i < spans.length; ++i) {\n
        var span = spans[i];\n
        if ((span.from == null || span.from <= pos.ch) &&\n
            (span.to == null || span.to >= pos.ch))\n
          markers.push(span.marker.parent || span.marker);\n
      }\n
      return markers;\n
    },\n
    findMarks: function(from, to, filter) {\n
      from = clipPos(this, from); to = clipPos(this, to);\n
      var found = [], lineNo = from.line;\n
      this.iter(from.line, to.line + 1, function(line) {\n
        var spans = line.markedSpans;\n
        if (spans) for (var i = 0; i < spans.length; i++) {\n
          var span = spans[i];\n
          if (!(lineNo == from.line && from.ch > span.to ||\n
                span.from == null && lineNo != from.line||\n
                lineNo == to.line && span.from > to.ch) &&\n
              (!filter || filter(span.marker)))\n
            found.push(span.marker.parent || span.marker);\n
        }\n
        ++lineNo;\n
      });\n
      return found;\n
    },\n
    getAllMarks: function() {\n
      var markers = [];\n
      this.iter(function(line) {\n
        var sps = line.markedSpans;\n
        if (sps) for (var i = 0; i < sps.length; ++i)\n
          if (sps[i].from != null) markers.push(sps[i].marker);\n
      });\n
      return markers;\n
    },\n
\n
    posFromIndex: function(off) {\n
      var ch, lineNo = this.first;\n
      this.iter(function(line) {\n
        var sz = line.text.length + 1;\n
        if (sz > off) { ch = off; return true; }\n
        off -= sz;\n
        ++lineNo;\n
      });\n
      return clipPos(this, Pos(lineNo, ch));\n
    },\n
    indexFromPos: function (coords) {\n
      coords = clipPos(this, coords);\n
      var index = coords.ch;\n
      if (coords.line < this.first || coords.ch < 0) return 0;\n
      this.iter(this.first, coords.line, function (line) {\n
        index += line.text.length + 1;\n
      });\n
      return index;\n
    },\n
\n
    copy: function(copyHistory) {\n
      var doc = new Doc(getLines(this, this.first, this.first + this.size),\n
                        this.modeOption, this.first, this.lineSep);\n
      doc.scrollTop = this.scrollTop; doc.scrollLeft = this.scrollLeft;\n
      doc.sel = this.sel;\n
      doc.extend = false;\n
      if (copyHistory) {\n
        doc.history.undoDepth = this.history.undoDepth;\n
        doc.setHistory(this.getHistory());\n
      }\n
      return doc;\n
    },\n
\n
    linkedDoc: function(options) {\n
      if (!options) options = {};\n
      var from = this.first, to = this.first + this.size;\n
      if (options.from != null && options.from > from) from = options.from;\n
      if (options.to != null && options.to < to) to = options.to;\n
      var copy = new Doc(getLines(this, from, to), options.mode || this.modeOption, from, this.lineSep);\n
      if (options.sharedHist) copy.history = this.history;\n
      (this.linked || (this.linked = [])).push({doc: copy, sharedHist: options.sharedHist});\n
      copy.linked = [{doc: this, isParent: true, sharedHist: options.sharedHist}];\n
      copySharedMarkers(copy, findSharedMarkers(this));\n
      return copy;\n
    },\n
    unlinkDoc: function(other) {\n
      if (other instanceof CodeMirror) other = other.doc;\n
      if (this.linked) for (var i = 0; i < this.linked.length; ++i) {\n
        var link = this.linked[i];\n
        if (link.doc != other) continue;\n
        this.linked.splice(i, 1);\n
        other.unlinkDoc(this);\n
        detachSharedMarkers(findSharedMarkers(this));\n
        break;\n
      }\n
      // If the histories were shared, split them again\n
      if (other.history == this.history) {\n
        var splitIds = [other.id];\n
        linkedDocs(other, function(doc) {splitIds.push(doc.id);}, true);\n
        other.history = new History(null);\n
        other.history.done = copyHistoryArray(this.history.done, splitIds);\n
        other.history.undone = copyHistoryArray(this.history.undone, splitIds);\n
      }\n
    },\n
    iterLinkedDocs: function(f) {linkedDocs(this, f);},\n
\n
    getMode: function() {return this.mode;},\n
    getEditor: function() {return this.cm;},\n
\n
    splitLines: function(str) {\n
      if (this.lineSep) return str.split(this.lineSep);\n
      return splitLinesAuto(str);\n
    },\n
    lineSeparator: function() { return this.lineSep || "\\n"; }\n
  });\n
\n
  // Public alias.\n
  Doc.prototype.eachLine = Doc.prototype.iter;\n
\n
  // Set up methods on CodeMirror\'s prototype to redirect to the editor\'s document.\n
  var dontDelegate = "iter insert remove copy getEditor constructor".split(" ");\n
  for (var prop in Doc.prototype) if (Doc.prototype.hasOwnProperty(prop) && indexOf(dontDelegate, prop) < 0)\n
    CodeMirror.prototype[prop] = (function(method) {\n
      return function() {return method.apply(this.doc, arguments);};\n
    })(Doc.prototype[prop]);\n
\n
  eventMixin(Doc);\n
\n
  // Call f for all linked documents.\n
  function linkedDocs(doc, f, sharedHistOnly) {\n
    function propagate(doc, skip, sharedHist) {\n
      if (doc.linked) for (var i = 0; i < doc.linked.length; ++i) {\n
        var rel = doc.linked[i];\n
        if (rel.doc == skip) continue;\n
        var shared = sharedHist && rel.sharedHist;\n
        if (sharedHistOnly && !shared) continue;\n
        f(rel.doc, shared);\n
        propagate(rel.doc, doc, shared);\n
      }\n
    }\n
    propagate(doc, null, true);\n
  }\n
\n
  // Attach a document to an editor.\n
  function attachDoc(cm, doc) {\n
    if (doc.cm) throw new Error("This document is already in use.");\n
    cm.doc = doc;\n
    doc.cm = cm;\n
    estimateLineHeights(cm);\n
    loadMode(cm);\n
    if (!cm.options.lineWrapping) findMaxLine(cm);\n
    cm.options.mode = doc.modeOption;\n
    regChange(cm);\n
  }\n
\n
  // LINE UTILITIES\n
\n
  // Find the line object corresponding to the given line number.\n
  function getLine(doc, n) {\n
    n -= doc.first;\n
    if (n < 0 || n >= doc.size) throw new Error("There is no line " + (n + doc.first) + " in the document.");\n
    for (var chunk = doc; !chunk.lines;) {\n
      for (var i = 0;; ++i) {\n
        var child = chunk.children[i], sz = child.chunkSize();\n
        if (n < sz) { chunk = child; break; }\n
        n -= sz;\n
      }\n
    }\n
    return chunk.lines[n];\n
  }\n
\n
  // Get the part of a document between two positions, as an array of\n
  // strings.\n
  function getBetween(doc, start, end) {\n
    var out = [], n = start.line;\n
    doc.iter(start.line, end.line + 1, function(line) {\n
      var text = line.text;\n
      if (n == end.line) text = text.slice(0, end.ch);\n
      if (n == start.line) text = text.slice(start.ch);\n
      out.push(text);\n
      ++n;\n
    });\n
    return out;\n
  }\n
  // Get the lines between from and to, as array of strings.\n
  function getLines(doc, from, to) {\n
    var out = [];\n
    doc.iter(from, to, function(line) { out.push(line.text); });\n
    return out;\n
  }\n
\n
  // Update the height of a line, propagating the height change\n
  // upwards to parent nodes.\n
  function updateLineHeight(line, height) {\n
    var diff = height - line.height;\n
    if (diff) for (var n = line; n; n = n.parent) n.height += diff;\n
  }\n
\n
  // Given a line object, find its line number by walking up through\n
  // its parent links.\n
  function lineNo(line) {\n
    if (line.parent == null) return null;\n
    var cur = line.parent, no = indexOf(cur.lines, line);\n
    for (var chunk = cur.parent; chunk; cur = chunk, chunk = chunk.parent) {\n
      for (var i = 0;; ++i) {\n
        if (chunk.children[i] == cur) break;\n
        no += chunk.children[i].chunkSize();\n
      }\n
    }\n
    return no + cur.first;\n
  }\n
\n
  // Find the line at the given vertical position, using the height\n
  // information in the document tree.\n
  function lineAtHeight(chunk, h) {\n
    var n = chunk.first;\n
    outer: do {\n
      for (var i = 0; i < chunk.children.length; ++i) {\n
        var child = chunk.children[i], ch = child.height;\n
        if (h < ch) { chunk = child; continue outer; }\n
        h -= ch;\n
        n += child.chunkSize();\n
      }\n
      return n;\n
    } while (!chunk.lines);\n
    for (var i = 0; i < chunk.lines.length; ++i) {\n
      var line = chunk.lines[i], lh = line.height;\n
      if (h < lh) break;\n
      h -= lh;\n
    }\n
    return n + i;\n
  }\n
\n
\n
  // Find the height above the given line.\n
  function heightAtLine(lineObj) {\n
    lineObj = visualLine(lineObj);\n
\n
    var h = 0, chunk = lineObj.parent;\n
    for (var i = 0; i < chunk.lines.length; ++i) {\n
      var line = chunk.lines[i];\n
      if (line == lineObj) break;\n
      else h += line.height;\n
    }\n
    for (var p = chunk.parent; p; chunk = p, p = chunk.parent) {\n
      for (var i = 0; i < p.children.length; ++i) {\n
        var cur = p.children[i];\n
        if (cur == chunk) break;\n
        else h += cur.height;\n
      }\n
    }\n
    return h;\n
  }\n
\n
  // Get the bidi ordering for the given line (and cache it). Returns\n
  // false for lines that are fully left-to-right, and an array of\n
  // BidiSpan objects otherwise.\n
  function getOrder(line) {\n
    var order = line.order;\n
    if (order == null) order = line.order = bidiOrdering(line.text);\n
    return order;\n
  }\n
\n
  // HISTORY\n
\n
  function History(startGen) {\n
    // Arrays of change events and selections. Doing something adds an\n
    // event to done and clears undo. Undoing moves events from done\n
    // to undone, redoing moves them in the other direction.\n
    this.done = []; this.undone = [];\n
    this.undoDepth = Infinity;\n
    // Used to track when changes can be merged into a single undo\n
    // event\n
    this.lastModTime = this.lastSelTime = 0;\n
    this.lastOp = this.lastSelOp = null;\n
    this.lastOrigin = this.lastSelOrigin = null;\n
    // Used by the isClean() method\n
    this.generation = this.maxGeneration = startGen || 1;\n
  }\n
\n
  // Create a history change event from an updateDoc-style change\n
  // object.\n
  function historyChangeFromChange(doc, change) {\n
    var histChange = {from: copyPos(change.from), to: changeEnd(change), text: getBetween(doc, change.from, change.to)};\n
    attachLocalSpans(doc, histChange, change.from.line, change.to.line + 1);\n
    linkedDocs(doc, function(doc) {attachLocalSpans(doc, histChange, change.from.line, change.to.line + 1);}, true);\n
    return histChange;\n
  }\n
\n
  // Pop all selection events off the end of a history array. Stop at\n
  // a change event.\n
  function clearSelectionEvents(array) {\n
    while (array.length) {\n
      var last = lst(array);\n
      if (last.ranges) array.pop();\n
      else break;\n
    }\n
  }\n
\n
  // Find the top change event in the history. Pop off selection\n
  // events that are in the way.\n
  function lastChangeEvent(hist, force) {\n
    if (force) {\n
      clearSelectionEvents(hist.done);\n
      return lst(hist.done);\n
    } else if (hist.done.length && !lst(hist.done).ranges) {\n
      return lst(hist.done);\n
    } else if (hist.done.length > 1 && !hist.done[hist.done.length - 2].ranges) {\n
      hist.done.pop();\n
      return lst(hist.done);\n
    }\n
  }\n
\n
  // Register a change in the history. Merges changes that are within\n
  // a single operation, ore are close together with an origin that\n
  // allows merging (starting with "+") into a single event.\n
  function addChangeToHistory(doc, change, selAfter, opId) {\n
    var hist = doc.history;\n
    hist.undone.length = 0;\n
    var time = +new Date, cur;\n
\n
    if ((hist.lastOp == opId ||\n
         hist.lastOrigin == change.origin && change.origin &&\n
         ((change.origin.charAt(0) == "+" && doc.cm && hist.lastModTime > time - doc.cm.options.historyEventDelay) ||\n
          change.origin.charAt(0) == "*")) &&\n
        (cur = lastChangeEvent(hist, hist.lastOp == opId))) {\n
      // Merge this change into the last event\n
      var last = lst(cur.changes);\n
      if (cmp(change.from, change.to) == 0 && cmp(change.from, last.to) == 0) {\n
        // Optimized case for simple insertion -- don\'t want to add\n
        // new changesets for every character typed\n
        last.to = changeEnd(change);\n
      } else {\n
        // Add new sub-event\n
        cur.changes.push(historyChangeFromChange(doc, change));\n
      }\n
    } else {\n
      // Can not be merged, start a new event.\n
      var before = lst(hist.done);\n
      if (!before || !before.ranges)\n
        pushSelectionToHistory(doc.sel, hist.done);\n
      cur = {changes: [historyChangeFromChange(doc, change)],\n
             generation: hist.generation};\n
      hist.done.push(cur);\n
      while (hist.done.length > hist.undoDepth) {\n
        hist.done.shift();\n
        if (!hist.done[0].ranges) hist.done.shift();\n
      }\n
    }\n
    hist.done.push(selAfter);\n
    hist.generation = ++hist.maxGeneration;\n
    hist.lastModTime = hist.lastSelTime = time;\n
    hist.lastOp = hist.lastSelOp = opId;\n
    hist.lastOrigin = hist.lastSelOrigin = change.origin;\n
\n
    if (!last) signal(doc, "historyAdded");\n
  }\n
\n
  function selectionEventCanBeMerged(doc, origin, prev, sel) {\n
    var ch = origin.charAt(0);\n
    return ch == "*" ||\n
      ch == "+" &&\n
      prev.ranges.length == sel.ranges.length &&\n
      prev.somethingSelected() == sel.somethingSelected() &&\n
      new Date - doc.history.lastSelTime <= (doc.cm ? doc.cm.options.historyEventDelay : 500);\n
  }\n
\n
  // Called whenever the selection changes, sets the new selection as\n
  // the pending selection in the history, and pushes the old pending\n
  // selection into the \'done\' array when it was significantly\n
  // different (in number of selected ranges, emptiness, or time).\n
  function addSelectionToHistory(doc, sel, opId, options) {\n
    var hist = doc.history, origin = options && options.origin;\n
\n
    // A new event is started when the previous origin does not match\n
    // the current, or the origins don\'t allow matching. Origins\n
    // starting with * are always merged, those starting with + are\n
    // merged when similar and close together in time.\n
    if (opId == hist.lastSelOp ||\n
        (origin && hist.lastSelOrigin == origin &&\n
         (hist.lastModTime == hist.lastSelTime && hist.lastOrigin == origin ||\n
          selectionEventCanBeMerged(doc, origin, lst(hist.done), sel))))\n
      hist.done[hist.done.length - 1] = sel;\n
    else\n
      pushSelectionToHistory(sel, hist.done);\n
\n
    hist.lastSelTime = +new Date;\n
    hist.lastSelOrigin = origin;\n
    hist.lastSelOp = opId;\n
    if (options && options.clearRedo !== false)\n
      clearSelectionEvents(hist.undone);\n
  }\n
\n
  function pushSelectionToHistory(sel, dest) {\n
    var top = lst(dest);\n
    if (!(top && top.ranges && top.equals(sel)))\n
      dest.push(sel);\n
  }\n
\n
  // Used to store marked span information in the history.\n
  function attachLocalSpans(doc, change, from, to) {\n
    var existing = change["spans_" + doc.id], n = 0;\n
    doc.iter(Math.max(doc.first, from), Math.min(doc.first + doc.size, to), function(line) {\n
      if (line.markedSpans)\n
        (existing || (existing = change["spans_" + doc.id] = {}))[n] = line.markedSpans;\n
      ++n;\n
    });\n
  }\n
\n
  // When un/re-doing restores text containing marked spans, those\n
  // that have been explicitly cleared should not be restored.\n
  function removeClearedSpans(spans) {\n
    if (!spans) return null;\n
    for (var i = 0, out; i < spans.length; ++i) {\n
      if (spans[i].marker.explicitlyCleared) { if (!out) out = spans.slice(0, i); }\n
      else if (out) out.push(spans[i]);\n
    }\n
    return !out ? spans : out.length ? out : null;\n
  }\n
\n
  // Retrieve and filter the old marked spans stored in a change event.\n
  function getOldSpans(doc, change) {\n
    var found = change["spans_" + doc.id];\n
    if (!found) return null;\n
    for (var i = 0, nw = []; i < change.text.length; ++i)\n
      nw.push(removeClearedSpans(found[i]));\n
    return nw;\n
  }\n
\n
  // Used both to provide a JSON-safe object in .getHistory, and, when\n
  // detaching a document, to split the history in two\n
  function copyHistoryArray(events, newGroup, instantiateSel) {\n
    for (var i = 0, copy = []; i < events.length; ++i) {\n
      var event = events[i];\n
      if (event.ranges) {\n
        copy.push(instantiateSel ? Selection.prototype.deepCopy.call(event) : event);\n
        continue;\n
      }\n
      var changes = event.changes, newChanges = [];\n
      copy.push({changes: newChanges});\n
      for (var j = 0; j < changes.length; ++j) {\n
        var change = changes[j], m;\n
        newChanges.push({from: change.from, to: change.to, text: change.text});\n
        if (newGroup) for (var prop in change) if (m = prop.match(/^spans_(\\d+)$/)) {\n
          if (indexOf(newGroup, Number(m[1])) > -1) {\n
            lst(newChanges)[prop] = change[prop];\n
            delete change[prop];\n
          }\n
        }\n
      }\n
    }\n
    return copy;\n
  }\n
\n
  // Rebasing/resetting history to deal with externally-sourced changes\n
\n
  function rebaseHistSelSingle(pos, from, to, diff) {\n
    if (to < pos.line) {\n
      pos.line += diff;\n
    } else if (from < pos.line) {\n
      pos.line = from;\n
      pos.ch = 0;\n
    }\n
  }\n
\n
  // Tries to rebase an array of history events given a change in the\n
  // document. If the change touches the same lines as the event, the\n
  // event, and everything \'behind\' it, is discarded. If the change is\n
  // before the event, the event\'s positions are updated. Uses a\n
  // copy-on-write scheme for the positions, to avoid having to\n
  // reallocate them all on every rebase, but also avoid problems with\n
  // shared position objects being unsafely updated.\n
  function rebaseHistArray(array, from, to, diff) {\n
    for (var i = 0; i < array.length; ++i) {\n
      var sub = array[i], ok = true;\n
      if (sub.ranges) {\n
        if (!sub.copied) { sub = array[i] = sub.deepCopy(); sub.copied = true; }\n
        for (var j = 0; j < sub.ranges.length; j++) {\n
          rebaseHistSelSingle(sub.ranges[j].anchor, from, to, diff);\n
          rebaseHistSelSingle(sub.ranges[j].head, from, to, diff);\n
        }\n
        continue;\n
      }\n
      for (var j = 0; j < sub.changes.length; ++j) {\n
        var cur = sub.changes[j];\n
        if (to < cur.from.line) {\n
          cur.from = Pos(cur.from.line + diff, cur.from.ch);\n
          cur.to = Pos(cur.to.line + diff, cur.to.ch);\n
        } else if (from <= cur.to.line) {\n
          ok = false;\n
          break;\n
        }\n
      }\n
      if (!ok) {\n
        array.splice(0, i + 1);\n
        i = 0;\n
      }\n
    }\n
  }\n
\n
  function rebaseHist(hist, change) {\n
    var from = change.from.line, to = change.to.line, diff = change.text.length - (to - from) - 1;\n
    rebaseHistArray(hist.done, from, to, diff);\n
    rebaseHistArray(hist.undone, from, to, diff);\n
  }\n
\n
  // EVENT UTILITIES\n
\n
  // Due to the fact that we still support jurassic IE versions, some\n
  // compatibility wrappers are needed.\n
\n
  var e_preventDefault = CodeMirror.e_preventDefault = function(e) {\n
    if (e.preventDefault) e.preventDefault();\n
    else e.returnValue = false;\n
  };\n
  var e_stopPropagation = CodeMirror.e_stopPropagation = function(e) {\n
    if (e.stopPropagation) e.stopPropagation();\n
    else e.cancelBubble = true;\n
  };\n
  function e_defaultPrevented(e) {\n
    return e.defaultPrevented != null ? e.defaultPrevented : e.returnValue == false;\n
  }\n
  var e_stop = CodeMirror.e_stop = function(e) {e_preventDefault(e); e_stopPropagation(e);};\n
\n
  function e_target(e) {return e.target || e.srcElement;}\n
  function e_button(e) {\n
    var b = e.which;\n
    if (b == null) {\n
      if (e.button & 1) b = 1;\n
      else if (e.button & 2) b = 3;\n
      else if (e.button & 4) b = 2;\n
    }\n
    if (mac && e.ctrlKey && b == 1) b = 3;\n
    return b;\n
  }\n
\n
  // EVENT HANDLING\n
\n
  // Lightweight event framework. on/off also work on DOM nodes,\n
  // registering native DOM handlers.\n
\n
  var on = CodeMirror.on = function(emitter, type, f) {\n
    if (emitter.addEventListener)\n
      emitter.addEventListener(type, f, false);\n
    else if (emitter.attachEvent)\n
      emitter.attachEvent("on" + type, f);\n
    else {\n
      var map = emitter._handlers || (emitter._handlers = {});\n
      var arr = map[type] || (map[type] = []);\n
      arr.push(f);\n
    }\n
  };\n
\n
  var noHandlers = []\n
  function getHandlers(emitter, type, copy) {\n
    var arr = emitter._handlers && emitter._handlers[type]\n
    if (copy) return arr && arr.length > 0 ? arr.slice() : noHandlers\n
    else return arr || noHandlers\n
  }\n
\n
  var off = CodeMirror.off = function(emitter, type, f) {\n
    if (emitter.removeEventListener)\n
      emitter.removeEventListener(type, f, false);\n
    else if (emitter.detachEvent)\n
      emitter.detachEvent("on" + type, f);\n
    else {\n
      var handlers = getHandlers(emitter, type, false)\n
      for (var i = 0; i < handlers.length; ++i)\n
        if (handlers[i] == f) { handlers.splice(i, 1); break; }\n
    }\n
  };\n
\n
  var signal = CodeMirror.signal = function(emitter, type /*, values...*/) {\n
    var handlers = getHandlers(emitter, type, true)\n
    if (!handlers.length) return;\n
    var args = Array.prototype.slice.call(arguments, 2);\n
    for (var i = 0; i < handlers.length; ++i) handlers[i].apply(null, args);\n
  };\n
\n
  var orphanDelayedCallbacks = null;\n
\n
  // Often, we want to signal events at a point where we are in the\n
  // middle of some work, but don\'t want the handler to start calling\n
  // other methods on the editor, which might be in an inconsistent\n
  // state or simply not expect any other events to happen.\n
  // signalLater looks whether there are any handlers, and schedules\n
  // them to be executed when the last operation ends, or, if no\n
  // operation is active, when a timeout fires.\n
  function signalLater(emitter, type /*, values...*/) {\n
    var arr = getHandlers(emitter, type, false)\n
    if (!arr.length) return;\n
    var args = Array.prototype.slice.call(arguments, 2), list;\n
    if (operationGroup) {\n
      list = operationGroup.delayedCallbacks;\n
    } else if (orphanDelayedCallbacks) {\n
      list = orphanDelayedCallbacks;\n
    } else {\n
      list = orphanDelayedCallbacks = [];\n
      setTimeout(fireOrphanDelayed, 0);\n
    }\n
    function bnd(f) {return function(){f.apply(null, args);};};\n
    for (var i = 0; i < arr.length; ++i)\n
      list.push(bnd(arr[i]));\n
  }\n
\n
  function fireOrphanDelayed() {\n
    var delayed = orphanDelayedCallbacks;\n
    orphanDelayedCallbacks = null;\n
    for (var i = 0; i < delayed.length; ++i) delayed[i]();\n
  }\n
\n
  // The DOM events that CodeMirror handles can be overridden by\n
  // registering a (non-DOM) handler on the editor for the event name,\n
  // and preventDefault-ing the event in that handler.\n
  function signalDOMEvent(cm, e, override) {\n
    if (typeof e == "string")\n
      e = {type: e, preventDefault: function() { this.defaultPrevented = true; }};\n
    signal(cm, override || e.type, cm, e);\n
    return e_defaultPrevented(e) || e.codemirrorIgnore;\n
  }\n
\n
  function signalCursorActivity(cm) {\n
    var arr = cm._handlers && cm._handlers.cursorActivity;\n
    if (!arr) return;\n
    var set = cm.curOp.cursorActivityHandlers || (cm.curOp.cursorActivityHandlers = []);\n
    for (var i = 0; i < arr.length; ++i) if (indexOf(set, arr[i]) == -1)\n
      set.push(arr[i]);\n
  }\n
\n
  function hasHandler(emitter, type) {\n
    return getHandlers(emitter, type).length > 0\n
  }\n
\n
  // Add on and off methods to a constructor\'s prototype, to make\n
  // registering events on such objects more convenient.\n
  function eventMixin(ctor) {\n
    ctor.prototype.on = function(type, f) {on(this, type, f);};\n
    ctor.prototype.off = function(type, f) {off(this, type, f);};\n
  }\n
\n
  // MISC UTILITIES\n
\n
  // Number of pixels added to scroller and sizer to hide scrollbar\n
  var scrollerGap = 30;\n
\n
  // Returned or thrown by various protocols to signal \'I\'m not\n
  // handling this\'.\n
  var Pass = CodeMirror.Pass = {toString: function(){return "CodeMirror.Pass";}};\n
\n
  // Reused option objects for setSelection & friends\n
  var sel_dontScroll = {scroll: false}, sel_mouse = {origin: "*mouse"}, sel_move = {origin: "+move"};\n
\n
  function Delayed() {this.id = null;}\n
  Delayed.prototype.set = function(ms, f) {\n
    clearTimeout(this.id);\n
    this.id = setTimeout(f, ms);\n
  };\n
\n
  // Counts the column offset in a string, taking tabs into account.\n
  // Used mostly to find indentation.\n
  var countColumn = CodeMirror.countColumn = function(string, end, tabSize, startIndex, startValue) {\n
    if (end == null) {\n
      end = string.search(/[^\\s\\u00a0]/);\n
      if (end == -1) end = string.length;\n
    }\n
    for (var i = startIndex || 0, n = startValue || 0;;) {\n
      var nextTab = string.indexOf("\\t", i);\n
      if (nextTab < 0 || nextTab >= end)\n
        return n + (end - i);\n
      n += nextTab - i;\n
      n += tabSize - (n % tabSize);\n
      i = nextTab + 1;\n
    }\n
  };\n
\n
  // The inverse of countColumn -- find the offset that corresponds to\n
  // a particular column.\n
  var findColumn = CodeMirror.findColumn = function(string, goal, tabSize) {\n
    for (var pos = 0, col = 0;;) {\n
      var nextTab = string.indexOf("\\t", pos);\n
      if (nextTab == -1) nextTab = string.length;\n
      var skipped = nextTab - pos;\n
      if (nextTab == string.length || col + skipped >= goal)\n
        return pos + Math.min(skipped, goal - col);\n
      col += nextTab - pos;\n
      col += tabSize - (col % tabSize);\n
      pos = nextTab + 1;\n
      if (col >= goal) return pos;\n
    }\n
  }\n
\n
  var spaceStrs = [""];\n
  function spaceStr(n) {\n
    while (spaceStrs.length <= n)\n
      spaceStrs.push(lst(spaceStrs) + " ");\n
    return spaceStrs[n];\n
  }\n
\n
  function lst(arr) { return arr[arr.length-1]; }\n
\n
  var selectInput = function(node) { node.select(); };\n
  if (ios) // Mobile Safari apparently has a bug where select() is broken.\n
    selectInput = function(node) { node.selectionStart = 0; node.selectionEnd = node.value.length; };\n
  else if (ie) // Suppress mysterious IE10 errors\n
    selectInput = function(node) { try { node.select(); } catch(_e) {} };\n
\n
  function indexOf(array, elt) {\n
    for (var i = 0; i < array.length; ++i)\n
      if (array[i] == elt) return i;\n
    return -1;\n
  }\n
  function map(array, f) {\n
    var out = [];\n
    for (var i = 0; i < array.length; i++) out[i] = f(array[i], i);\n
    return out;\n
  }\n
\n
  function nothing() {}\n
\n
  function createObj(base, props) {\n
    var inst;\n
    if (Object.create) {\n
      inst = Object.create(base);\n
    } else {\n
      nothing.prototype = base;\n
      inst = new nothing();\n
    }\n
    if (props) copyObj(props, inst);\n
    return inst;\n
  };\n
\n
  function copyObj(obj, target, overwrite) {\n
    if (!target) target = {};\n
    for (var prop in obj)\n
      if (obj.hasOwnProperty(prop) && (overwrite !== false || !target.hasOwnProperty(prop)))\n
        target[prop] = obj[prop];\n
    return target;\n
  }\n
\n
  function bind(f) {\n
    var args = Array.prototype.slice.call(arguments, 1);\n
    return function(){return f.apply(null, args);};\n
  }\n
\n
  var nonASCIISingleCaseWordChar = /[\\u00df\\u0587\\u0590-\\u05f4\\u0600-\\u06ff\\u3040-\\u309f\\u30a0-\\u30ff\\u3400-\\u4db5\\u4e00-\\u9fcc\\uac00-\\ud7af]/;\n
  var isWordCharBasic = CodeMirror.isWordChar = function(ch) {\n
    return /\\w/.test(ch) || ch > "\\x80" &&\n
      (ch.toUpperCase() != ch.toLowerCase() || nonASCIISingleCaseWordChar.test(ch));\n
  };\n
  function isWordChar(ch, helper) {\n
    if (!helper) return isWordCharBasic(ch);\n
    if (helper.source.indexOf("\\\\w") > -1 && isWordCharBasic(ch)) return true;\n
    return helper.test(ch);\n
  }\n
\n
  function isEmpty(obj) {\n
    for (var n in obj) if (obj.hasOwnProperty(n) && obj[n]) return false;\n
    return true;\n
  }\n
\n
  // Extending unicode characters. A series of a non-extending char +\n
  // any number of extending chars is treated as a single unit as far\n
  // as editing and measuring is concerned. This is not fully correct,\n
  // since some scripts/fonts/browsers also treat other configurations\n
  // of code points as a group.\n
  var extendingChars = /[\\u0300-\\u036f\\u0483-\\u0489\\u0591-\\u05bd\\u05bf\\u05c1\\u05c2\\u05c4\\u05c5\\u05c7\\u0610-\\u061a\\u064b-\\u065e\\u0670\\u06d6-\\u06dc\\u06de-\\u06e4\\u06e7\\u06e8\\u06ea-\\u06ed\\u0711\\u0730-\\u074a\\u07a6-\\u07b0\\u07eb-\\u07f3\\u0816-\\u0819\\u081b-\\u0823\\u0825-\\u0827\\u0829-\\u082d\\u0900-\\u0902\\u093c\\u0941-\\u0948\\u094d\\u0951-\\u0955\\u0962\\u0963\\u0981\\u09bc\\u09be\\u09c1-\\u09c4\\u09cd\\u09d7\\u09e2\\u09e3\\u0a01\\u0a02\\u0a3c\\u0a41\\u0a42\\u0a47\\u0a48\\u0a4b-\\u0a4d\\u0a51\\u0a70\\u0a71\\u0a75\\u0a81\\u0a82\\u0abc\\u0ac1-\\u0ac5\\u0ac7\\u0ac8\\u0acd\\u0ae2\\u0ae3\\u0b01\\u0b3c\\u0b3e\\u0b3f\\u0b41-\\u0b44\\u0b4d\\u0b56\\u0b57\\u0b62\\u0b63\\u0b82\\u0bbe\\u0bc0\\u0bcd\\u0bd7\\u0c3e-\\u0c40\\u0c46-\\u0c48\\u0c4a-\\u0c4d\\u0c55\\u0c56\\u0c62\\u0c63\\u0cbc\\u0cbf\\u0cc2\\u0cc6\\u0ccc\\u0ccd\\u0cd5\\u0cd6\\u0ce2\\u0ce3\\u0d3e\\u0d41-\\u0d44\\u0d4d\\u0d57\\u0d62\\u0d63\\u0dca\\u0dcf\\u0dd2-\\u0dd4\\u0dd6\\u0ddf\\u0e31\\u0e34-\\u0e3a\\u0e47-\\u0e4e\\u0eb1\\u0eb4-\\u0eb9\\u0ebb\\u0ebc\\u0ec8-\\u0ecd\\u0f18\\u0f19\\u0f35\\u0f37\\u0f39\\u0f71-\\u0f7e\\u0f80-\\u0f84\\u0f86\\u0f87\\u0f90-\\u0f97\\u0f99-\\u0fbc\\u0fc6\\u102d-\\u1030\\u1032-\\u1037\\u1039\\u103a\\u103d\\u103e\\u1058\\u1059\\u105e-\\u1060\\u1071-\\u1074\\u1082\\u1085\\u1086\\u108d\\u109d\\u135f\\u1712-\\u1714\\u1732-\\u1734\\u1752\\u1753\\u1772\\u1773\\u17b7-\\u17bd\\u17c6\\u17c9-\\u17d3\\u17dd\\u180b-\\u180d\\u18a9\\u1920-\\u1922\\u1927\\u1928\\u1932\\u1939-\\u193b\\u1a17\\u1a18\\u1a56\\u1a58-\\u1a5e\\u1a60\\u1a62\\u1a65-\\u1a6c\\u1a73-\\u1a7c\\u1a7f\\u1b00-\\u1b03\\u1b34\\u1b36-\\u1b3a\\u1b3c\\u1b42\\u1b6b-\\u1b73\\u1b80\\u1b81\\u1ba2-\\u1ba5\\u1ba8\\u1ba9\\u1c2c-\\u1c33\\u1c36\\u1c37\\u1cd0-\\u1cd2\\u1cd4-\\u1ce0\\u1ce2-\\u1ce8\\u1ced\\u1dc0-\\u1de6\\u1dfd-\\u1dff\\u200c\\u200d\\u20d0-\\u20f0\\u2cef-\\u2cf1\\u2de0-\\u2dff\\u302a-\\u302f\\u3099\\u309a\\ua66f-\\ua672\\ua67c\\ua67d\\ua6f0\\ua6f1\\ua802\\ua806\\ua80b\\ua825\\ua826\\ua8c4\\ua8e0-\\ua8f1\\ua926-\\ua92d\\ua947-\\ua951\\ua980-\\ua982\\ua9b3\\ua9b6-\\ua9b9\\ua9bc\\uaa29-\\uaa2e\\uaa31\\uaa32\\uaa35\\uaa36\\uaa43\\uaa4c\\uaab0\\uaab2-\\uaab4\\uaab7\\uaab8\\uaabe\\uaabf\\uaac1\\uabe5\\uabe8\\uabed\\udc00-\\udfff\\ufb1e\\ufe00-\\ufe0f\\ufe20-\\ufe26\\uff9e\\uff9f]/;\n
  function isExtendingChar(ch) { return ch.charCodeAt(0) >= 768 && extendingChars.test(ch); }\n
\n
  // DOM UTILITIES\n
\n
  function elt(tag, content, className, style) {\n
    var e = document.createElement(tag);\n
    if (className) e.className = className;\n
    if (style) e.style.cssText = style;\n
    if (typeof content == "string") e.appendChild(document.createTextNode(content));\n
    else if (content) for (var i = 0; i < content.length; ++i) e.appendChild(content[i]);\n
    return e;\n
  }\n
\n
  var range;\n
  if (document.createRange) range = function(node, start, end, endNode) {\n
    var r = document.createRange();\n
    r.setEnd(endNode || node, end);\n
    r.setStart(node, start);\n
    return r;\n
  };\n
  else range = function(node, start, end) {\n
    var r = document.body.createTextRange();\n
    try { r.moveToElementText(node.parentNode); }\n
    catch(e) { return r; }\n
    r.collapse(true);\n
    r.moveEnd("character", end);\n
    r.moveStart("character", start);\n
    return r;\n
  };\n
\n
  function removeChildren(e) {\n
    for (var count = e.childNodes.length; count > 0; --count)\n
      e.removeChild(e.firstChild);\n
    return e;\n
  }\n
\n
  function removeChildrenAndAdd(parent, e) {\n
    return removeChildren(parent).appendChild(e);\n
  }\n
\n
  var contains = CodeMirror.contains = function(parent, child) {\n
    if (child.nodeType == 3) // Android browser always returns false when child is a textnode\n
      child = child.parentNode;\n
    if (parent.contains)\n
      return parent.contains(child);\n
    do {\n
      if (child.nodeType == 11) child = child.host;\n
      if (child == parent) return true;\n
    } while (child = child.parentNode);\n
  };\n
\n
  function activeElt() {\n
    var activeElement = document.activeElement;\n
    while (activeElement && activeElement.root && activeElement.root.activeElement)\n
      activeElement = activeElement.root.activeElement;\n
    return activeElement;\n
  }\n
  // Older versions of IE throws unspecified error when touching\n
  // document.activeElement in some cases (during loading, in iframe)\n
  if (ie && ie_version < 11) activeElt = function() {\n
    try { return document.activeElement; }\n
    catch(e) { return document.body; }\n
  };\n
\n
  function classTest(cls) { return new RegExp("(^|\\\\s)" + cls + "(?:$|\\\\s)\\\\s*"); }\n
  var rmClass = CodeMirror.rmClass = function(node, cls) {\n
    var current = node.className;\n
    var match = classTest(cls).exec(current);\n
    if (match) {\n
      var after = current.slice(match.index + match[0].length);\n
      node.className = current.slice(0, match.index) + (after ? match[1] + after : "");\n
    }\n
  };\n
  var addClass = CodeMirror.addClass = function(node, cls) {\n
    var current = node.className;\n
    if (!classTest(cls).test(current)) node.className += (current ? " " : "") + cls;\n
  };\n
  function joinClasses(a, b) {\n
    var as = a.split(" ");\n
    for (var i = 0; i < as.length; i++)\n
      if (as[i] && !classTest(as[i]).test(b)) b += " " + as[i];\n
    return b;\n
  }\n
\n
  // WINDOW-WIDE EVENTS\n
\n
  // These must be handled carefully, because naively registering a\n
  // handler for each editor will cause the editors to never be\n
  // garbage collected.\n
\n
  function forEachCodeMirror(f) {\n
    if (!document.body.getElementsByClassName) return;\n
    var byClass = document.body.getElementsByClassName("CodeMirror");\n
    for (var i = 0; i < byClass.length; i++) {\n
      var cm = byClass[i].CodeMirror;\n
      if (cm) f(cm);\n
    }\n
  }\n
\n
  var globalsRegistered = false;\n
  function ensureGlobalHandlers() {\n
    if (globalsRegistered) return;\n
    registerGlobalHandlers();\n
    globalsRegistered = true;\n
  }\n
  function registerGlobalHandlers() {\n
    // When the window resizes, we need to refresh active editors.\n
    var resizeTimer;\n
    on(window, "resize", function() {\n
      if (resizeTimer == null) resizeTimer = setTimeout(function() {\n
        resizeTimer = null;\n
        forEachCodeMirror(onResize);\n
      }, 100);\n
    });\n
    // When the window loses focus, we want to show the editor as blurred\n
    on(window, "blur", function() {\n
      forEachCodeMirror(onBlur);\n
    });\n
  }\n
\n
  // FEATURE DETECTION\n
\n
  // Detect drag-and-drop\n
  var dragAndDrop = function() {\n
    // There is *some* kind of drag-and-drop support in IE6-8, but I\n
    // couldn\'t get it to work yet.\n
    if (ie && ie_version < 9) return false;\n
    var div = elt(\'div\');\n
    return "draggable" in div || "dragDrop" in div;\n
  }();\n
\n
  var zwspSupported;\n
  function zeroWidthElement(measure) {\n
    if (zwspSupported == null) {\n
      var test = elt("span", "\\u200b");\n
      removeChildrenAndAdd(measure, elt("span", [test, document.createTextNode("x")]));\n
      if (measure.firstChild.offsetHeight != 0)\n
        zwspSupported = test.offsetWidth <= 1 && test.offsetHeight > 2 && !(ie && ie_version < 8);\n
    }\n
    var node = zwspSupported ? elt("span", "\\u200b") :\n
      elt("span", "\\u00a0", null, "display: inline-block; width: 1px; margin-right: -1px");\n
    node.setAttribute("cm-text", "");\n
    return node;\n
  }\n
\n
  // Feature-detect IE\'s crummy client rect reporting for bidi text\n
  var badBidiRects;\n
  function hasBadBidiRects(measure) {\n
    if (badBidiRects != null) return badBidiRects;\n
    var txt = removeChildrenAndAdd(measure, document.createTextNode("A\\u062eA"));\n
    var r0 = range(txt, 0, 1).getBoundingClientRect();\n
    if (!r0 || r0.left == r0.right) return false; // Safari returns null in some cases (#2780)\n
    var r1 = range(txt, 1, 2).getBoundingClientRect();\n
    return badBidiRects = (r1.right - r0.right < 3);\n
  }\n
\n
  // See if "".split is the broken IE version, if so, provide an\n
  // alternative way to split lines.\n
  var splitLinesAuto = CodeMirror.splitLines = "\\n\\nb".split(/\\n/).length != 3 ? function(string) {\n
    var pos = 0, result = [], l = string.length;\n
    while (pos <= l) {\n
      var nl = string.indexOf("\\n", pos);\n
      if (nl == -1) nl = string.length;\n
      var line = string.slice(pos, string.charAt(nl - 1) == "\\r" ? nl - 1 : nl);\n
      var rt = line.indexOf("\\r");\n
      if (rt != -1) {\n
        result.push(line.slice(0, rt));\n
        pos += rt + 1;\n
      } else {\n
        result.push(line);\n
        pos = nl + 1;\n
      }\n
    }\n
    return result;\n
  } : function(string){return string.split(/\\r\\n?|\\n/);};\n
\n
  var hasSelection = window.getSelection ? function(te) {\n
    try { return te.selectionStart != te.selectionEnd; }\n
    catch(e) { return false; }\n
  } : function(te) {\n
    try {var range = te.ownerDocument.selection.createRange();}\n
    catch(e) {}\n
    if (!range || range.parentElement() != te) return false;\n
    return range.compareEndPoints("StartToEnd", range) != 0;\n
  };\n
\n
  var hasCopyEvent = (function() {\n
    var e = elt("div");\n
    if ("oncopy" in e) return true;\n
    e.setAttribute("oncopy", "return;");\n
    return typeof e.oncopy == "function";\n
  })();\n
\n
  var badZoomedRects = null;\n
  function hasBadZoomedRects(measure) {\n
    if (badZoomedRects != null) return badZoomedRects;\n
    var node = removeChildrenAndAdd(measure, elt("span", "x"));\n
    var normal = node.getBoundingClientRect();\n
    var fromRange = range(node, 0, 1).getBoundingClientRect();\n
    return badZoomedRects = Math.abs(normal.left - fromRange.left) > 1;\n
  }\n
\n
  // KEY NAMES\n
\n
  var keyNames = CodeMirror.keyNames = {\n
    3: "Enter", 8: "Backspace", 9: "Tab", 13: "Enter", 16: "Shift", 17: "Ctrl", 18: "Alt",\n
    19: "Pause", 20: "CapsLock", 27: "Esc", 32: "Space", 33: "PageUp", 34: "PageDown", 35: "End",\n
    36: "Home", 37: "Left", 38: "Up", 39: "Right", 40: "Down", 44: "PrintScrn", 45: "Insert",\n
    46: "Delete", 59: ";", 61: "=", 91: "Mod", 92: "Mod", 93: "Mod",\n
    106: "*", 107: "=", 109: "-", 110: ".", 111: "/", 127: "Delete",\n
    173: "-", 186: ";", 187: "=", 188: ",", 189: "-", 190: ".", 191: "/", 192: "`", 219: "[", 220: "\\\\",\n
    221: "]", 222: "\'", 63232: "Up", 63233: "Down", 63234: "Left", 63235: "Right", 63272: "Delete",\n
    63273: "Home", 63275: "End", 63276: "PageUp", 63277: "PageDown", 63302: "Insert"\n
  };\n
  (function() {\n
    // Number keys\n
    for (var i = 0; i < 10; i++) keyNames[i + 48] = keyNames[i + 96] = String(i);\n
    // Alphabetic keys\n
    for (var i = 65; i <= 90; i++) keyNames[i] = String.fromCharCode(i);\n
    // Function keys\n
    for (var i = 1; i <= 12; i++) keyNames[i + 111] = keyNames[i + 63235] = "F" + i;\n
  })();\n
\n
  // BIDI HELPERS\n
\n
  function iterateBidiSections(order, from, to, f) {\n
    if (!order) return f(from, to, "ltr");\n
    var found = false;\n
    for (var i = 0; i < order.length; ++i) {\n
      var part = order[i];\n
      if (part.from < to && part.to > from || from == to && part.to == from) {\n
        f(Math.max(part.from, from), Math.min(part.to, to), part.level == 1 ? "rtl" : "ltr");\n
        found = true;\n
      }\n
    }\n
    if (!found) f(from, to, "ltr");\n
  }\n
\n
  function bidiLeft(part) { return part.level % 2 ? part.to : part.from; }\n
  function bidiRight(part) { return part.level % 2 ? part.from : part.to; }\n
\n
  function lineLeft(line) { var order = getOrder(line); return order ? bidiLeft(order[0]) : 0; }\n
  function lineRight(line) {\n
    var order = getOrder(line);\n
    if (!order) return line.text.length;\n
    return bidiRight(lst(order));\n
  }\n
\n
  function lineStart(cm, lineN) {\n
    var line = getLine(cm.doc, lineN);\n
    var visual = visualLine(line);\n
    if (visual != line) lineN = lineNo(visual);\n
    var order = getOrder(visual);\n
    var ch = !order ? 0 : order[0].level % 2 ? lineRight(visual) : lineLeft(visual);\n
    return Pos(lineN, ch);\n
  }\n
  function lineEnd(cm, lineN) {\n
    var merged, line = getLine(cm.doc, lineN);\n
    while (merged = collapsedSpanAtEnd(line)) {\n
      line = merged.find(1, true).line;\n
      lineN = null;\n
    }\n
    var order = getOrder(line);\n
    var ch = !order ? line.text.length : order[0].level % 2 ? lineLeft(line) : lineRight(line);\n
    return Pos(lineN == null ? lineNo(line) : lineN, ch);\n
  }\n
  function lineStartSmart(cm, pos) {\n
    var start = lineStart(cm, pos.line);\n
    var line = getLine(cm.doc, start.line);\n
    var order = getOrder(line);\n
    if (!order || order[0].level == 0) {\n
      var firstNonWS = Math.max(0, line.text.search(/\\S/));\n
      var inWS = pos.line == start.line && pos.ch <= firstNonWS && pos.ch;\n
      return Pos(start.line, inWS ? 0 : firstNonWS);\n
    }\n
    return start;\n
  }\n
\n
  function compareBidiLevel(order, a, b) {\n
    var linedir = order[0].level;\n
    if (a == linedir) return true;\n
    if (b == linedir) return false;\n
    return a < b;\n
  }\n
  var bidiOther;\n
  function getBidiPartAt(order, pos) {\n
    bidiOther = null;\n
    for (var i = 0, found; i < order.length; ++i) {\n
      var cur = order[i];\n
      if (cur.from < pos && cur.to > pos) return i;\n
      if ((cur.from == pos || cur.to == pos)) {\n
        if (found == null) {\n
          found = i;\n
        } else if (compareBidiLevel(order, cur.level, order[found].level)) {\n
          if (cur.from != cur.to) bidiOther = found;\n
          return i;\n
        } else {\n
          if (cur.from != cur.to) bidiOther = i;\n
          return found;\n
        }\n
      }\n
    }\n
    return found;\n
  }\n
\n
  function moveInLine(line, pos, dir, byUnit) {\n
    if (!byUnit) return pos + dir;\n
    do pos += dir;\n
    while (pos > 0 && isExtendingChar(line.text.charAt(pos)));\n
    return pos;\n
  }\n
\n
  // This is needed in order to move \'visually\' through bi-directional\n
  // text -- i.e., pressing left should make the cursor go left, even\n
  // when in RTL text. The tricky part is the \'jumps\', where RTL and\n
  // LTR text touch each other. This often requires the cursor offset\n
  // to move more than one unit, in order to visually move one unit.\n
  function moveVisually(line, start, dir, byUnit) {\n
    var bidi = getOrder(line);\n
    if (!bidi) return moveLogically(line, start, dir, byUnit);\n
    var pos = getBidiPartAt(bidi, start), part = bidi[pos];\n
    var target = moveInLine(line, start, part.level % 2 ? -dir : dir, byUnit);\n
\n
    for (;;) {\n
      if (target > part.from && target < part.to) return target;\n
      if (target == part.from || target == part.to) {\n
        if (getBidiPartAt(bidi, target) == pos) return target;\n
        part = bidi[pos += dir];\n
        return (dir > 0) == part.level % 2 ? part.to : part.from;\n
      } else {\n
        part = bidi[pos += dir];\n
        if (!part) return null;\n
        if ((dir > 0) == part.level % 2)\n
          target = moveInLine(line, part.to, -1, byUnit);\n
        else\n
          target = moveInLine(line, part.from, 1, byUnit);\n
      }\n
    }\n
  }\n
\n
  function moveLogically(line, start, dir, byUnit) {\n
    var target = start + dir;\n
    if (byUnit) while (target > 0 && isExtendingChar(line.text.charAt(target))) target += dir;\n
    return target < 0 || target > line.text.length ? null : target;\n
  }\n
\n
  // Bidirectional ordering algorithm\n
  // See http://unicode.org/reports/tr9/tr9-13.html for the algorithm\n
  // that this (partially) implements.\n
\n
  // One-char codes used for character types:\n
  // L (L):   Left-to-Right\n
  // R (R):   Right-to-Left\n
  // r (AL):  Right-to-Left Arabic\n
  // 1 (EN):  European Number\n
  // + (ES):  European Number Separator\n
  // % (ET):  European Number Terminator\n
  // n (AN):  Arabic Number\n
  // , (CS):  Common Number Separator\n
  // m (NSM): Non-Spacing Mark\n
  // b (BN):  Boundary Neutral\n
  // s (B):   Paragraph Separator\n
  // t (S):   Segment Separator\n
  // w (WS):  Whitespace\n
  // N (ON):  Other Neutrals\n
\n
  // Returns null if characters are ordered as they appear\n
  // (left-to-right), or an array of sections ({from, to, level}\n
  // objects) in the order in which they occur visually.\n
  var bidiOrdering = (function() {\n
    // Character types for codepoints 0 to 0xff\n
    var lowTypes = "bbbbbbbbbtstwsbbbbbbbbbbbbbbssstwNN%%%NNNNNN,N,N1111111111NNNNNNNLLLLLLLLLLLLLLLLLLLLLLLLLLNNNNNNLLLLLLLLLLLLLLLLLLLLLLLLLLNNNNbbbbbbsbbbbbbbbbbbbbbbbbbbbbbbbbb,N%%%%NNNNLNNNNN%%11NLNNN1LNNNNNLLLLLLLLLLLLLLLLLLLLLLLNLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLN";\n
    // Character types for codepoints 0x600 to 0x6ff\n
    var arabicTypes = "rrrrrrrrrrrr,rNNmmmmmmrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrmmmmmmmmmmmmmmrrrrrrrnnnnnnnnnn%nnrrrmrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrmmmmmmmmmmmmmmmmmmmNmmmm";\n
    function charType(code) {\n
      if (code <= 0xf7) return lowTypes.charAt(code);\n
      else if (0x590 <= code && code <= 0x5f4) return "R";\n
      else if (0x600 <= code && code <= 0x6ed) return arabicTypes.charAt(code - 0x600);\n
      else if (0x6ee <= code && code <= 0x8ac) return "r";\n
      else if (0x2000 <= code && code <= 0x200b) return "w";\n
      else if (code == 0x200c) return "b";\n
      else return "L";\n
    }\n
\n
    var bidiRE = /[\\u0590-\\u05f4\\u0600-\\u06ff\\u0700-\\u08ac]/;\n
    var isNeutral = /[stwN]/, isStrong = /[LRr]/, countsAsLeft = /[Lb1n]/, countsAsNum = /[1n]/;\n
    // Browsers seem to always treat the boundaries of block elements as being L.\n
    var outerType = "L";\n
\n
    function BidiSpan(level, from, to) {\n
      this.level = level;\n
      this.from = from; this.to = to;\n
    }\n
\n
    return function(str) {\n
      if (!bidiRE.test(str)) return false;\n
      var len = str.length, types = [];\n
      for (var i = 0, type; i < len; ++i)\n
        types.push(type = charType(str.charCodeAt(i)));\n
\n
      // W1. Examine each non-spacing mark (NSM) in the level run, and\n
      // change the type of the NSM to the type of the previous\n
      // character. If the NSM is at the start of the level run, it will\n
      // get the type of sor.\n
      for (var i = 0, prev = outerType; i < len; ++i) {\n
        var type = types[i];\n
        if (type == "m") types[i] = prev;\n
        else prev = type;\n
      }\n
\n
      // W2. Search backwards from each instance of a European number\n
      // until the first strong type (R, L, AL, or sor) is found. If an\n
      // AL is found, change the type of the European number to Arabic\n
      // number.\n
      // W3. Change all ALs to R.\n
      for (var i = 0, cur = outerType; i < len; ++i) {\n
        var type = types[i];\n
        if (type == "1" && cur == "r") types[i] = "n";\n
        else if (isStrong.test(type)) { cur = type; if (type == "r") types[i] = "R"; }\n
      }\n
\n
      // W4. A single European separator between two European numbers\n
      // changes to a European number. A single common separator between\n
      // two numbers of the same type changes to that type.\n
      for (var i = 1, prev = types[0]; i < len - 1; ++i) {\n
        var type = types[i];\n
        if (type == "+" && prev == "1" && types[i+1] == "1") types[i] = "1";\n
        else if (type == "," && prev == types[i+1] &&\n
                 (prev == "1" || prev == "n")) types[i] = prev;\n
        prev = type;\n
      }\n
\n
      // W5. A sequence of European terminators adjacent to European\n
      // numbers changes to all European numbers.\n
      // W6. Otherwise, separators and terminators change to Other\n
      // Neutral.\n
      for (var i = 0; i < len; ++i) {\n
        var type = types[i];\n
        if (type == ",") types[i] = "N";\n
        else if (type == "%") {\n
          for (var end = i + 1; end < len && types[end] == "%"; ++end) {}\n
          var replace = (i && types[i-1] == "!") || (end < len && types[end] == "1") ? "1" : "N";\n
          for (var j = i; j < end; ++j) types[j] = replace;\n
          i = end - 1;\n
        }\n
      }\n
\n
      // W7. Search backwards from each instance of a European number\n
      // until the first strong type (R, L, or sor) is found. If an L is\n
      // found, then change the type of the European number to L.\n
      for (var i = 0, cur = outerType; i < len; ++i) {\n
        var type = types[i];\n
        if (cur == "L" && type == "1") types[i] = "L";\n
        else if (isStrong.test(type)) cur = type;\n
      }\n
\n
      // N1. A sequence of neutrals takes the direction of the\n
      // surrounding strong text if the text on both sides has the same\n
      // direction. European and Arabic numbers act as if they were R in\n
      // terms of their influence on neutrals. Start-of-level-run (sor)\n
      // and end-of-level-run (eor) are used at level run boundaries.\n
      // N2. Any remaining neutrals take the embedding direction.\n
      for (var i = 0; i < len; ++i) {\n
        if (isNeutral.test(types[i])) {\n
          for (var end = i + 1; end < len && isNeutral.test(types[end]); ++end) {}\n
          var before = (i ? types[i-1] : outerType) == "L";\n
          var after = (end < len ? types[end] : outerType) == "L";\n
          var replace = before || after ? "L" : "R";\n
          for (var j = i; j < end; ++j) types[j] = replace;\n
          i = end - 1;\n
        }\n
      }\n
\n
      // Here we depart from the documented algorithm, in order to avoid\n
      // building up an actual levels array. Since there are only three\n
      // levels (0, 1, 2) in an implementation that doesn\'t take\n
      // explicit embedding into account, we can build up the order on\n
      // the fly, without following the level-based algorithm.\n
      var order = [], m;\n
      for (var i = 0; i < len;) {\n
        if (countsAsLeft.test(types[i])) {\n
          var start = i;\n
          for (++i; i < len && countsAsLeft.test(types[i]); ++i) {}\n
          order.push(new BidiSpan(0, start, i));\n
        } else {\n
          var pos = i, at = order.length;\n
          for (++i; i < len && types[i] != "L"; ++i) {}\n
          for (var j = pos; j < i;) {\n
            if (countsAsNum.test(types[j])) {\n
              if (pos < j) order.splice(at, 0, new BidiSpan(1, pos, j));\n
              var nstart = j;\n
              for (++j; j < i && countsAsNum.test(types[j]); ++j) {}\n
              order.splice(at, 0, new BidiSpan(2, nstart, j));\n
              pos = j;\n
            } else ++j;\n
          }\n
          if (pos < i) order.splice(at, 0, new BidiSpan(1, pos, i));\n
        }\n
      }\n
      if (order[0].level == 1 && (m = str.match(/^\\s+/))) {\n
        order[0].from = m[0].length;\n
        order.unshift(new BidiSpan(0, 0, m[0].length));\n
      }\n
      if (lst(order).level == 1 && (m = str.match(/\\s+$/))) {\n
        lst(order).to -= m[0].length;\n
        order.push(new BidiSpan(0, len - m[0].length, len));\n
      }\n
      if (order[0].level == 2)\n
        order.unshift(new BidiSpan(1, order[0].to, order[0].to));\n
      if (order[0].level != lst(order).level)\n
        order.push(new BidiSpan(order[0].level, len, len));\n
\n
      return order;\n
    };\n
  })();\n
\n
  // THE END\n
\n
  CodeMirror.version = "5.10.0";\n
\n
  return CodeMirror;\n
});

]]></string> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string>CodeMirror</string> </value>
        </item>
        <item>
            <key> <string>version</string> </key>
            <value> <string>4.3.0</string> </value>
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
                <value> <string>romain</string> </value>
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
                        <float>1406898405.86</float>
                        <string>GMT</string>
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
                <value> <string>948.28966.25666.62856</string> </value>
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
                        <float>1453133720.03</float>
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
                <value> <string>detect_converted_file</string> </value>
            </item>
            <item>
                <key> <string>actor</string> </key>
                <value> <string>romain</string> </value>
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
                <value> <string>converted</string> </value>
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
                        <float>1405067899.8</float>
                        <string>GMT</string>
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
