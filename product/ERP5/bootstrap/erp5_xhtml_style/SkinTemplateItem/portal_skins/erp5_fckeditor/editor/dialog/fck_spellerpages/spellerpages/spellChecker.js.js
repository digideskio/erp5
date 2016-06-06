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
            <value> <string>ts83858910.03</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>spellChecker.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

﻿////////////////////////////////////////////////////\r\n
// spellChecker.js\r\n
//\r\n
// spellChecker object\r\n
//\r\n
// This file is sourced on web pages that have a textarea object to evaluate\r\n
// for spelling. It includes the implementation for the spellCheckObject.\r\n
//\r\n
////////////////////////////////////////////////////\r\n
\r\n
\r\n
// constructor\r\n
function spellChecker( textObject ) {\r\n
\r\n
\t// public properties - configurable\r\n
//\tthis.popUpUrl = \'/speller/spellchecker.html\';\t\t\t\t\t\t\t// by FredCK\r\n
\tthis.popUpUrl = \'fck_spellerpages/spellerpages/spellchecker.html\';\t\t// by FredCK\r\n
\tthis.popUpName = \'spellchecker\';\r\n
//\tthis.popUpProps = "menu=no,width=440,height=350,top=70,left=120,resizable=yes,status=yes";\t// by FredCK\r\n
\tthis.popUpProps = null ;\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t// by FredCK\r\n
//\tthis.spellCheckScript = \'/speller/server-scripts/spellchecker.php\';\t\t// by FredCK\r\n
\t//this.spellCheckScript = \'/cgi-bin/spellchecker.pl\';\r\n
\r\n
\t// values used to keep track of what happened to a word\r\n
\tthis.replWordFlag = "R";\t// single replace\r\n
\tthis.ignrWordFlag = "I";\t// single ignore\r\n
\tthis.replAllFlag = "RA";\t// replace all occurances\r\n
\tthis.ignrAllFlag = "IA";\t// ignore all occurances\r\n
\tthis.fromReplAll = "~RA";\t// an occurance of a "replace all" word\r\n
\tthis.fromIgnrAll = "~IA";\t// an occurance of a "ignore all" word\r\n
\t// properties set at run time\r\n
\tthis.wordFlags = new Array();\r\n
\tthis.currentTextIndex = 0;\r\n
\tthis.currentWordIndex = 0;\r\n
\tthis.spellCheckerWin = null;\r\n
\tthis.controlWin = null;\r\n
\tthis.wordWin = null;\r\n
\tthis.textArea = textObject;\t// deprecated\r\n
\tthis.textInputs = arguments;\r\n
\r\n
\t// private methods\r\n
\tthis._spellcheck = _spellcheck;\r\n
\tthis._getSuggestions = _getSuggestions;\r\n
\tthis._setAsIgnored = _setAsIgnored;\r\n
\tthis._getTotalReplaced = _getTotalReplaced;\r\n
\tthis._setWordText = _setWordText;\r\n
\tthis._getFormInputs = _getFormInputs;\r\n
\r\n
\t// public methods\r\n
\tthis.openChecker = openChecker;\r\n
\tthis.startCheck = startCheck;\r\n
\tthis.checkTextBoxes = checkTextBoxes;\r\n
\tthis.checkTextAreas = checkTextAreas;\r\n
\tthis.spellCheckAll = spellCheckAll;\r\n
\tthis.ignoreWord = ignoreWord;\r\n
\tthis.ignoreAll = ignoreAll;\r\n
\tthis.replaceWord = replaceWord;\r\n
\tthis.replaceAll = replaceAll;\r\n
\tthis.terminateSpell = terminateSpell;\r\n
\tthis.undo = undo;\r\n
\r\n
\t// set the current window\'s "speller" property to the instance of this class.\r\n
\t// this object can now be referenced by child windows/frames.\r\n
\twindow.speller = this;\r\n
}\r\n
\r\n
// call this method to check all text boxes (and only text boxes) in the HTML document\r\n
function checkTextBoxes() {\r\n
\tthis.textInputs = this._getFormInputs( "^text$" );\r\n
\tthis.openChecker();\r\n
}\r\n
\r\n
// call this method to check all textareas (and only textareas ) in the HTML document\r\n
function checkTextAreas() {\r\n
\tthis.textInputs = this._getFormInputs( "^textarea$" );\r\n
\tthis.openChecker();\r\n
}\r\n
\r\n
// call this method to check all text boxes and textareas in the HTML document\r\n
function spellCheckAll() {\r\n
\tthis.textInputs = this._getFormInputs( "^text(area)?$" );\r\n
\tthis.openChecker();\r\n
}\r\n
\r\n
// call this method to check text boxe(s) and/or textarea(s) that were passed in to the\r\n
// object\'s constructor or to the textInputs property\r\n
function openChecker() {\r\n
\tthis.spellCheckerWin = window.open( this.popUpUrl, this.popUpName, this.popUpProps );\r\n
\tif( !this.spellCheckerWin.opener ) {\r\n
\t\tthis.spellCheckerWin.opener = window;\r\n
\t}\r\n
}\r\n
\r\n
function startCheck( wordWindowObj, controlWindowObj ) {\r\n
\r\n
\t// set properties from args\r\n
\tthis.wordWin = wordWindowObj;\r\n
\tthis.controlWin = controlWindowObj;\r\n
\r\n
\t// reset properties\r\n
\tthis.wordWin.resetForm();\r\n
\tthis.controlWin.resetForm();\r\n
\tthis.currentTextIndex = 0;\r\n
\tthis.currentWordIndex = 0;\r\n
\t// initialize the flags to an array - one element for each text input\r\n
\tthis.wordFlags = new Array( this.wordWin.textInputs.length );\r\n
\t// each element will be an array that keeps track of each word in the text\r\n
\tfor( var i=0; i<this.wordFlags.length; i++ ) {\r\n
\t\tthis.wordFlags[i] = [];\r\n
\t}\r\n
\r\n
\t// start\r\n
\tthis._spellcheck();\r\n
\r\n
\treturn true;\r\n
}\r\n
\r\n
function ignoreWord() {\r\n
\tvar wi = this.currentWordIndex;\r\n
\tvar ti = this.currentTextIndex;\r\n
\tif( !this.wordWin ) {\r\n
\t\talert( \'Error: Word frame not available.\' );\r\n
\t\treturn false;\r\n
\t}\r\n
\tif( !this.wordWin.getTextVal( ti, wi )) {\r\n
\t\talert( \'Error: "Not in dictionary" text is missing.\' );\r\n
\t\treturn false;\r\n
\t}\r\n
\t// set as ignored\r\n
\tif( this._setAsIgnored( ti, wi, this.ignrWordFlag )) {\r\n
\t\tthis.currentWordIndex++;\r\n
\t\tthis._spellcheck();\r\n
\t}\r\n
\treturn true;\r\n
}\r\n
\r\n
function ignoreAll() {\r\n
\tvar wi = this.currentWordIndex;\r\n
\tvar ti = this.currentTextIndex;\r\n
\tif( !this.wordWin ) {\r\n
\t\talert( \'Error: Word frame not available.\' );\r\n
\t\treturn false;\r\n
\t}\r\n
\t// get the word that is currently being evaluated.\r\n
\tvar s_word_to_repl = this.wordWin.getTextVal( ti, wi );\r\n
\tif( !s_word_to_repl ) {\r\n
\t\talert( \'Error: "Not in dictionary" text is missing\' );\r\n
\t\treturn false;\r\n
\t}\r\n
\r\n
\t// set this word as an "ignore all" word.\r\n
\tthis._setAsIgnored( ti, wi, this.ignrAllFlag );\r\n
\r\n
\t// loop through all the words after this word\r\n
\tfor( var i = ti; i < this.wordWin.textInputs.length; i++ ) {\r\n
\t\tfor( var j = 0; j < this.wordWin.totalWords( i ); j++ ) {\r\n
\t\t\tif(( i == ti && j > wi ) || i > ti ) {\r\n
\t\t\t\t// future word: set as "from ignore all" if\r\n
\t\t\t\t// 1) do not already have a flag and\r\n
\t\t\t\t// 2) have the same value as current word\r\n
\t\t\t\tif(( this.wordWin.getTextVal( i, j ) == s_word_to_repl )\r\n
\t\t\t\t&& ( !this.wordFlags[i][j] )) {\r\n
\t\t\t\t\tthis._setAsIgnored( i, j, this.fromIgnrAll );\r\n
\t\t\t\t}\r\n
\t\t\t}\r\n
\t\t}\r\n
\t}\r\n
\r\n
\t// finally, move on\r\n
\tthis.currentWordIndex++;\r\n
\tthis._spellcheck();\r\n
\treturn true;\r\n
}\r\n
\r\n
function replaceWord() {\r\n
\tvar wi = this.currentWordIndex;\r\n
\tvar ti = this.currentTextIndex;\r\n
\tif( !this.wordWin ) {\r\n
\t\talert( \'Error: Word frame not available.\' );\r\n
\t\treturn false;\r\n
\t}\r\n
\tif( !this.wordWin.getTextVal( ti, wi )) {\r\n
\t\talert( \'Error: "Not in dictionary" text is missing\' );\r\n
\t\treturn false;\r\n
\t}\r\n
\tif( !this.controlWin.replacementText ) {\r\n
\t\treturn false ;\r\n
\t}\r\n
\tvar txt = this.controlWin.replacementText;\r\n
\tif( txt.value ) {\r\n
\t\tvar newspell = new String( txt.value );\r\n
\t\tif( this._setWordText( ti, wi, newspell, this.replWordFlag )) {\r\n
\t\t\tthis.currentWordIndex++;\r\n
\t\t\tthis._spellcheck();\r\n
\t\t}\r\n
\t}\r\n
\treturn true;\r\n
}\r\n
\r\n
function replaceAll() {\r\n
\tvar ti = this.currentTextIndex;\r\n
\tvar wi = this.currentWordIndex;\r\n
\tif( !this.wordWin ) {\r\n
\t\talert( \'Error: Word frame not available.\' );\r\n
\t\treturn false;\r\n
\t}\r\n
\tvar s_word_to_repl = this.wordWin.getTextVal( ti, wi );\r\n
\tif( !s_word_to_repl ) {\r\n
\t\talert( \'Error: "Not in dictionary" text is missing\' );\r\n
\t\treturn false;\r\n
\t}\r\n
\tvar txt = this.controlWin.replacementText;\r\n
\tif( !txt.value ) return false;\r\n
\tvar newspell = new String( txt.value );\r\n
\r\n
\t// set this word as a "replace all" word.\r\n
\tthis._setWordText( ti, wi, newspell, this.replAllFlag );\r\n
\r\n
\t// loop through all the words after this word\r\n
\tfor( var i = ti; i < this.wordWin.textInputs.length; i++ ) {\r\n
\t\tfor( var j = 0; j < this.wordWin.totalWords( i ); j++ ) {\r\n
\t\t\tif(( i == ti && j > wi ) || i > ti ) {\r\n
\t\t\t\t// future word: set word text to s_word_to_repl if\r\n
\t\t\t\t// 1) do not already have a flag and\r\n
\t\t\t\t// 2) have the same value as s_word_to_repl\r\n
\t\t\t\tif(( this.wordWin.getTextVal( i, j ) == s_word_to_repl )\r\n
\t\t\t\t&& ( !this.wordFlags[i][j] )) {\r\n
\t\t\t\t\tthis._setWordText( i, j, newspell, this.fromReplAll );\r\n
\t\t\t\t}\r\n
\t\t\t}\r\n
\t\t}\r\n
\t}\r\n
\r\n
\t// finally, move on\r\n
\tthis.currentWordIndex++;\r\n
\tthis._spellcheck();\r\n
\treturn true;\r\n
}\r\n
\r\n
function terminateSpell() {\r\n
\t// called when we have reached the end of the spell checking.\r\n
\tvar msg = "";\t\t// by FredCK\r\n
\tvar numrepl = this._getTotalReplaced();\r\n
\tif( numrepl == 0 ) {\r\n
\t\t// see if there were no misspellings to begin with\r\n
\t\tif( !this.wordWin ) {\r\n
\t\t\tmsg = "";\r\n
\t\t} else {\r\n
\t\t\tif( this.wordWin.totalMisspellings() ) {\r\n
//\t\t\t\tmsg += "No words changed.";\t\t\t// by FredCK\r\n
\t\t\t\tmsg += FCKLang.DlgSpellNoChanges ;\t// by FredCK\r\n
\t\t\t} else {\r\n
//\t\t\t\tmsg += "No misspellings found.";\t// by FredCK\r\n
\t\t\t\tmsg += FCKLang.DlgSpellNoMispell ;\t// by FredCK\r\n
\t\t\t}\r\n
\t\t}\r\n
\t} else if( numrepl == 1 ) {\r\n
//\t\tmsg += "One word changed.";\t\t\t// by FredCK\r\n
\t\tmsg += FCKLang.DlgSpellOneChange ;\t// by FredCK\r\n
\t} else {\r\n
//\t\tmsg += numrepl + " words changed.";\t// by FredCK\r\n
\t\tmsg += FCKLang.DlgSpellManyChanges.replace( /%1/g, numrepl ) ;\r\n
\t}\r\n
\tif( msg ) {\r\n
//\t\tmsg += "\\n";\t// by FredCK\r\n
\t\talert( msg );\r\n
\t}\r\n
\r\n
\tif( numrepl > 0 ) {\r\n
\t\t// update the text field(s) on the opener window\r\n
\t\tfor( var i = 0; i < this.textInputs.length; i++ ) {\r\n
\t\t\t// this.textArea.value = this.wordWin.text;\r\n
\t\t\tif( this.wordWin ) {\r\n
\t\t\t\tif( this.wordWin.textInputs[i] ) {\r\n
\t\t\t\t\tthis.textInputs[i].value = this.wordWin.textInputs[i];\r\n
\t\t\t\t}\r\n
\t\t\t}\r\n
\t\t}\r\n
\t}\r\n
\r\n
\t// return back to the calling window\r\n
//\tthis.spellCheckerWin.close();\t\t\t\t\t// by FredCK\r\n
\tif ( typeof( this.OnFinished ) == \'function\' )\t// by FredCK\r\n
\t\tthis.OnFinished(numrepl) ;\t\t\t\t\t// by FredCK\r\n
\r\n
\treturn true;\r\n
}\r\n
\r\n
function undo() {\r\n
\t// skip if this is the first word!\r\n
\tvar ti = this.currentTextIndex;\r\n
\tvar wi = this.currentWordIndex;\r\n
\r\n
\tif( this.wordWin.totalPreviousWords( ti, wi ) > 0 ) {\r\n
\t\tthis.wordWin.removeFocus( ti, wi );\r\n
\r\n
\t\t// go back to the last word index that was acted upon\r\n
\t\tdo {\r\n
\t\t\t// if the current word index is zero then reset the seed\r\n
\t\t\tif( this.currentWordIndex == 0 && this.currentTextIndex > 0 ) {\r\n
\t\t\t\tthis.currentTextIndex--;\r\n
\t\t\t\tthis.currentWordIndex = this.wordWin.totalWords( this.currentTextIndex )-1;\r\n
\t\t\t\tif( this.currentWordIndex < 0 ) this.currentWordIndex = 0;\r\n
\t\t\t} else {\r\n
\t\t\t\tif( this.currentWordIndex > 0 ) {\r\n
\t\t\t\t\tthis.currentWordIndex--;\r\n
\t\t\t\t}\r\n
\t\t\t}\r\n
\t\t} while (\r\n
\t\t\tthis.wordWin.totalWords( this.currentTextIndex ) == 0\r\n
\t\t\t|| this.wordFlags[this.currentTextIndex][this.currentWordIndex] == this.fromIgnrAll\r\n
\t\t\t|| this.wordFlags[this.currentTextIndex][this.currentWordIndex] == this.fromReplAll\r\n
\t\t);\r\n
\r\n
\t\tvar text_idx = this.currentTextIndex;\r\n
\t\tvar idx = this.currentWordIndex;\r\n
\t\tvar preReplSpell = this.wordWin.originalSpellings[text_idx][idx];\r\n
\r\n
\t\t// if we got back to the first word then set the Undo button back to disabled\r\n
\t\tif( this.wordWin.totalPreviousWords( text_idx, idx ) == 0 ) {\r\n
\t\t\tthis.controlWin.disableUndo();\r\n
\t\t}\r\n
\r\n
\t\tvar i, j, origSpell ;\r\n
\t\t// examine what happened to this current word.\r\n
\t\tswitch( this.wordFlags[text_idx][idx] ) {\r\n
\t\t\t// replace all: go through this and all the future occurances of the word\r\n
\t\t\t// and revert them all to the original spelling and clear their flags\r\n
\t\t\tcase this.replAllFlag :\r\n
\t\t\t\tfor( i = text_idx; i < this.wordWin.textInputs.length; i++ ) {\r\n
\t\t\t\t\tfor( j = 0; j < this.wordWin.totalWords( i ); j++ ) {\r\n
\t\t\t\t\t\tif(( i == text_idx && j >= idx ) || i > text_idx ) {\r\n
\t\t\t\t\t\t\torigSpell = this.wordWin.originalSpellings[i][j];\r\n
\t\t\t\t\t\t\tif( origSpell == preReplSpell ) {\r\n
\t\t\t\t\t\t\t\tthis._setWordText ( i, j, origSpell, undefined );\r\n
\t\t\t\t\t\t\t}\r\n
\t\t\t\t\t\t}\r\n
\t\t\t\t\t}\r\n
\t\t\t\t}\r\n
\t\t\t\tbreak;\r\n
\r\n
\t\t\t// ignore all: go through all the future occurances of the word\r\n
\t\t\t// and clear their flags\r\n
\t\t\tcase this.ignrAllFlag :\r\n
\t\t\t\tfor( i = text_idx; i < this.wordWin.textInputs.length; i++ ) {\r\n
\t\t\t\t\tfor( j = 0; j < this.wordWin.totalWords( i ); j++ ) {\r\n
\t\t\t\t\t\tif(( i == text_idx && j >= idx ) || i > text_idx ) {\r\n
\t\t\t\t\t\t\torigSpell = this.wordWin.originalSpellings[i][j];\r\n
\t\t\t\t\t\t\tif( origSpell == preReplSpell ) {\r\n
\t\t\t\t\t\t\t\tthis.wordFlags[i][j] = undefined;\r\n
\t\t\t\t\t\t\t}\r\n
\t\t\t\t\t\t}\r\n
\t\t\t\t\t}\r\n
\t\t\t\t}\r\n
\t\t\t\tbreak;\r\n
\r\n
\t\t\t// replace: revert the word to its original spelling\r\n
\t\t\tcase this.replWordFlag :\r\n
\t\t\t\tthis._setWordText ( text_idx, idx, preReplSpell, undefined );\r\n
\t\t\t\tbreak;\r\n
\t\t}\r\n
\r\n
\t\t// For all four cases, clear the wordFlag of this word. re-start the process\r\n
\t\tthis.wordFlags[text_idx][idx] = undefined;\r\n
\t\tthis._spellcheck();\r\n
\t}\r\n
}\r\n
\r\n
function _spellcheck() {\r\n
\tvar ww = this.wordWin;\r\n
\r\n
\t// check if this is the last word in the current text element\r\n
\tif( this.currentWordIndex == ww.totalWords( this.currentTextIndex) ) {\r\n
\t\tthis.currentTextIndex++;\r\n
\t\tthis.currentWordIndex = 0;\r\n
\t\t// keep going if we\'re not yet past the last text element\r\n
\t\tif( this.currentTextIndex < this.wordWin.textInputs.length ) {\r\n
\t\t\tthis._spellcheck();\r\n
\t\t\treturn;\r\n
\t\t} else {\r\n
\t\t\tthis.terminateSpell();\r\n
\t\t\treturn;\r\n
\t\t}\r\n
\t}\r\n
\r\n
\t// if this is after the first one make sure the Undo button is enabled\r\n
\tif( this.currentWordIndex > 0 ) {\r\n
\t\tthis.controlWin.enableUndo();\r\n
\t}\r\n
\r\n
\t// skip the current word if it has already been worked on\r\n
\tif( this.wordFlags[this.currentTextIndex][this.currentWordIndex] ) {\r\n
\t\t// increment the global current word index and move on.\r\n
\t\tthis.currentWordIndex++;\r\n
\t\tthis._spellcheck();\r\n
\t} else {\r\n
\t\tvar evalText = ww.getTextVal( this.currentTextIndex, this.currentWordIndex );\r\n
\t\tif( evalText ) {\r\n
\t\t\tthis.controlWin.evaluatedText.value = evalText;\r\n
\t\t\tww.setFocus( this.currentTextIndex, this.currentWordIndex );\r\n
\t\t\tthis._getSuggestions( this.currentTextIndex, this.currentWordIndex );\r\n
\t\t}\r\n
\t}\r\n
}\r\n
\r\n
function _getSuggestions( text_num, word_num ) {\r\n
\tthis.controlWin.clearSuggestions();\r\n
\t// add suggestion in list for each suggested word.\r\n
\t// get the array of suggested words out of the\r\n
\t// three-dimensional array containing all suggestions.\r\n
\tvar a_suggests = this.wordWin.suggestions[text_num][word_num];\r\n
\tif( a_suggests ) {\r\n
\t\t// got an array of suggestions.\r\n
\t\tfor( var ii = 0; ii < a_suggests.length; ii++ ) {\r\n
\t\t\tthis.controlWin.addSuggestion( a_suggests[ii] );\r\n
\t\t}\r\n
\t}\r\n
\tthis.controlWin.selectDefaultSuggestion();\r\n
}\r\n
\r\n
function _setAsIgnored( text_num, word_num, flag ) {\r\n
\t// set the UI\r\n
\tthis.wordWin.removeFocus( text_num, word_num );\r\n
\t// do the bookkeeping\r\n
\tthis.wordFlags[text_num][word_num] = flag;\r\n
\treturn true;\r\n
}\r\n
\r\n
function _getTotalReplaced() {\r\n
\tvar i_replaced = 0;\r\n
\tfor( var i = 0; i < this.wordFlags.length; i++ ) {\r\n
\t\tfor( var j = 0; j < this.wordFlags[i].length; j++ ) {\r\n
\t\t\tif(( this.wordFlags[i][j] == this.replWordFlag )\r\n
\t\t\t|| ( this.wordFlags[i][j] == this.replAllFlag )\r\n
\t\t\t|| ( this.wordFlags[i][j] == this.fromReplAll )) {\r\n
\t\t\t\ti_replaced++;\r\n
\t\t\t}\r\n
\t\t}\r\n
\t}\r\n
\treturn i_replaced;\r\n
}\r\n
\r\n
function _setWordText( text_num, word_num, newText, flag ) {\r\n
\t// set the UI and form inputs\r\n
\tthis.wordWin.setText( text_num, word_num, newText );\r\n
\t// keep track of what happened to this word:\r\n
\tthis.wordFlags[text_num][word_num] = flag;\r\n
\treturn true;\r\n
}\r\n
\r\n
function _getFormInputs( inputPattern ) {\r\n
\tvar inputs = new Array();\r\n
\tfor( var i = 0; i < document.forms.length; i++ ) {\r\n
\t\tfor( var j = 0; j < document.forms[i].elements.length; j++ ) {\r\n
\t\t\tif( document.forms[i].elements[j].type.match( inputPattern )) {\r\n
\t\t\t\tinputs[inputs.length] = document.forms[i].elements[j];\r\n
\t\t\t}\r\n
\t\t}\r\n
\t}\r\n
\treturn inputs;\r\n
}\r\n


]]></string> </value>
        </item>
        <item>
            <key> <string>precondition</string> </key>
            <value> <string></string> </value>
        </item>
        <item>
            <key> <string>size</string> </key>
            <value> <int>14600</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
