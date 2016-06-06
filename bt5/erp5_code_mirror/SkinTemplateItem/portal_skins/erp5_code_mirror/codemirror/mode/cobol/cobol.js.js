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
            <value> <string>ts21897142.93</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>cobol.js</string> </value>
        </item>
        <item>
            <key> <string>content_type</string> </key>
            <value> <string>application/javascript</string> </value>
        </item>
        <item>
            <key> <string>data</string> </key>
            <value> <string encoding="cdata"><![CDATA[

// CodeMirror, copyright (c) by Marijn Haverbeke and others\n
// Distributed under an MIT license: http://codemirror.net/LICENSE\n
\n
/**\n
 * Author: Gautam Mehta\n
 * Branched from CodeMirror\'s Scheme mode\n
 */\n
(function(mod) {\n
  if (typeof exports == "object" && typeof module == "object") // CommonJS\n
    mod(require("../../lib/codemirror"));\n
  else if (typeof define == "function" && define.amd) // AMD\n
    define(["../../lib/codemirror"], mod);\n
  else // Plain browser env\n
    mod(CodeMirror);\n
})(function(CodeMirror) {\n
"use strict";\n
\n
CodeMirror.defineMode("cobol", function () {\n
  var BUILTIN = "builtin", COMMENT = "comment", STRING = "string",\n
      ATOM = "atom", NUMBER = "number", KEYWORD = "keyword", MODTAG = "header",\n
      COBOLLINENUM = "def", PERIOD = "link";\n
  function makeKeywords(str) {\n
    var obj = {}, words = str.split(" ");\n
    for (var i = 0; i < words.length; ++i) obj[words[i]] = true;\n
    return obj;\n
  }\n
  var atoms = makeKeywords("TRUE FALSE ZEROES ZEROS ZERO SPACES SPACE LOW-VALUE LOW-VALUES ");\n
  var keywords = makeKeywords(\n
      "ACCEPT ACCESS ACQUIRE ADD ADDRESS " +\n
      "ADVANCING AFTER ALIAS ALL ALPHABET " +\n
      "ALPHABETIC ALPHABETIC-LOWER ALPHABETIC-UPPER ALPHANUMERIC ALPHANUMERIC-EDITED " +\n
      "ALSO ALTER ALTERNATE AND ANY " +\n
      "ARE AREA AREAS ARITHMETIC ASCENDING " +\n
      "ASSIGN AT ATTRIBUTE AUTHOR AUTO " +\n
      "AUTO-SKIP AUTOMATIC B-AND B-EXOR B-LESS " +\n
      "B-NOT B-OR BACKGROUND-COLOR BACKGROUND-COLOUR BEEP " +\n
      "BEFORE BELL BINARY BIT BITS " +\n
      "BLANK BLINK BLOCK BOOLEAN BOTTOM " +\n
      "BY CALL CANCEL CD CF " +\n
      "CH CHARACTER CHARACTERS CLASS CLOCK-UNITS " +\n
      "CLOSE COBOL CODE CODE-SET COL " +\n
      "COLLATING COLUMN COMMA COMMIT COMMITMENT " +\n
      "COMMON COMMUNICATION COMP COMP-0 COMP-1 " +\n
      "COMP-2 COMP-3 COMP-4 COMP-5 COMP-6 " +\n
      "COMP-7 COMP-8 COMP-9 COMPUTATIONAL COMPUTATIONAL-0 " +\n
      "COMPUTATIONAL-1 COMPUTATIONAL-2 COMPUTATIONAL-3 COMPUTATIONAL-4 COMPUTATIONAL-5 " +\n
      "COMPUTATIONAL-6 COMPUTATIONAL-7 COMPUTATIONAL-8 COMPUTATIONAL-9 COMPUTE " +\n
      "CONFIGURATION CONNECT CONSOLE CONTAINED CONTAINS " +\n
      "CONTENT CONTINUE CONTROL CONTROL-AREA CONTROLS " +\n
      "CONVERTING COPY CORR CORRESPONDING COUNT " +\n
      "CRT CRT-UNDER CURRENCY CURRENT CURSOR " +\n
      "DATA DATE DATE-COMPILED DATE-WRITTEN DAY " +\n
      "DAY-OF-WEEK DB DB-ACCESS-CONTROL-KEY DB-DATA-NAME DB-EXCEPTION " +\n
      "DB-FORMAT-NAME DB-RECORD-NAME DB-SET-NAME DB-STATUS DBCS " +\n
      "DBCS-EDITED DE DEBUG-CONTENTS DEBUG-ITEM DEBUG-LINE " +\n
      "DEBUG-NAME DEBUG-SUB-1 DEBUG-SUB-2 DEBUG-SUB-3 DEBUGGING " +\n
      "DECIMAL-POINT DECLARATIVES DEFAULT DELETE DELIMITED " +\n
      "DELIMITER DEPENDING DESCENDING DESCRIBED DESTINATION " +\n
      "DETAIL DISABLE DISCONNECT DISPLAY DISPLAY-1 " +\n
      "DISPLAY-2 DISPLAY-3 DISPLAY-4 DISPLAY-5 DISPLAY-6 " +\n
      "DISPLAY-7 DISPLAY-8 DISPLAY-9 DIVIDE DIVISION " +\n
      "DOWN DROP DUPLICATE DUPLICATES DYNAMIC " +\n
      "EBCDIC EGI EJECT ELSE EMI " +\n
      "EMPTY EMPTY-CHECK ENABLE END END. END-ACCEPT END-ACCEPT. " +\n
      "END-ADD END-CALL END-COMPUTE END-DELETE END-DISPLAY " +\n
      "END-DIVIDE END-EVALUATE END-IF END-INVOKE END-MULTIPLY " +\n
      "END-OF-PAGE END-PERFORM END-READ END-RECEIVE END-RETURN " +\n
      "END-REWRITE END-SEARCH END-START END-STRING END-SUBTRACT " +\n
      "END-UNSTRING END-WRITE END-XML ENTER ENTRY " +\n
      "ENVIRONMENT EOP EQUAL EQUALS ERASE " +\n
      "ERROR ESI EVALUATE EVERY EXCEEDS " +\n
      "EXCEPTION EXCLUSIVE EXIT EXTEND EXTERNAL " +\n
      "EXTERNALLY-DESCRIBED-KEY FD FETCH FILE FILE-CONTROL " +\n
      "FILE-STREAM FILES FILLER FINAL FIND " +\n
      "FINISH FIRST FOOTING FOR FOREGROUND-COLOR " +\n
      "FOREGROUND-COLOUR FORMAT FREE FROM FULL " +\n
      "FUNCTION GENERATE GET GIVING GLOBAL " +\n
      "GO GOBACK GREATER GROUP HEADING " +\n
      "HIGH-VALUE HIGH-VALUES HIGHLIGHT I-O I-O-CONTROL " +\n
      "ID IDENTIFICATION IF IN INDEX " +\n
      "INDEX-1 INDEX-2 INDEX-3 INDEX-4 INDEX-5 " +\n
      "INDEX-6 INDEX-7 INDEX-8 INDEX-9 INDEXED " +\n
      "INDIC INDICATE INDICATOR INDICATORS INITIAL " +\n
      "INITIALIZE INITIATE INPUT INPUT-OUTPUT INSPECT " +\n
      "INSTALLATION INTO INVALID INVOKE IS " +\n
      "JUST JUSTIFIED KANJI KEEP KEY " +\n
      "LABEL LAST LD LEADING LEFT " +\n
      "LEFT-JUSTIFY LENGTH LENGTH-CHECK LESS LIBRARY " +\n
      "LIKE LIMIT LIMITS LINAGE LINAGE-COUNTER " +\n
      "LINE LINE-COUNTER LINES LINKAGE LOCAL-STORAGE " +\n
      "LOCALE LOCALLY LOCK " +\n
      "MEMBER MEMORY MERGE MESSAGE METACLASS " +\n
      "MODE MODIFIED MODIFY MODULES MOVE " +\n
      "MULTIPLE MULTIPLY NATIONAL NATIVE NEGATIVE " +\n
      "NEXT NO NO-ECHO NONE NOT " +\n
      "NULL NULL-KEY-MAP NULL-MAP NULLS NUMBER " +\n
      "NUMERIC NUMERIC-EDITED OBJECT OBJECT-COMPUTER OCCURS " +\n
      "OF OFF OMITTED ON ONLY " +\n
      "OPEN OPTIONAL OR ORDER ORGANIZATION " +\n
      "OTHER OUTPUT OVERFLOW OWNER PACKED-DECIMAL " +\n
      "PADDING PAGE PAGE-COUNTER PARSE PERFORM " +\n
      "PF PH PIC PICTURE PLUS " +\n
      "POINTER POSITION POSITIVE PREFIX PRESENT " +\n
      "PRINTING PRIOR PROCEDURE PROCEDURE-POINTER PROCEDURES " +\n
      "PROCEED PROCESS PROCESSING PROGRAM PROGRAM-ID " +\n
      "PROMPT PROTECTED PURGE QUEUE QUOTE " +\n
      "QUOTES RANDOM RD READ READY " +\n
      "REALM RECEIVE RECONNECT RECORD RECORD-NAME " +\n
      "RECORDS RECURSIVE REDEFINES REEL REFERENCE " +\n
      "REFERENCE-MONITOR REFERENCES RELATION RELATIVE RELEASE " +\n
      "REMAINDER REMOVAL RENAMES REPEATED REPLACE " +\n
      "REPLACING REPORT REPORTING REPORTS REPOSITORY " +\n
      "REQUIRED RERUN RESERVE RESET RETAINING " +\n
      "RETRIEVAL RETURN RETURN-CODE RETURNING REVERSE-VIDEO " +\n
      "REVERSED REWIND REWRITE RF RH " +\n
      "RIGHT RIGHT-JUSTIFY ROLLBACK ROLLING ROUNDED " +\n
      "RUN SAME SCREEN SD SEARCH " +\n
      "SECTION SECURE SECURITY SEGMENT SEGMENT-LIMIT " +\n
      "SELECT SEND SENTENCE SEPARATE SEQUENCE " +\n
      "SEQUENTIAL SET SHARED SIGN SIZE " +\n
      "SKIP1 SKIP2 SKIP3 SORT SORT-MERGE " +\n
      "SORT-RETURN SOURCE SOURCE-COMPUTER SPACE-FILL " +\n
      "SPECIAL-NAMES STANDARD STANDARD-1 STANDARD-2 " +\n
      "START STARTING STATUS STOP STORE " +\n
      "STRING SUB-QUEUE-1 SUB-QUEUE-2 SUB-QUEUE-3 SUB-SCHEMA " +\n
      "SUBFILE SUBSTITUTE SUBTRACT SUM SUPPRESS " +\n
      "SYMBOLIC SYNC SYNCHRONIZED SYSIN SYSOUT " +\n
      "TABLE TALLYING TAPE TENANT TERMINAL " +\n
      "TERMINATE TEST TEXT THAN THEN " +\n
      "THROUGH THRU TIME TIMES TITLE " +\n
      "TO TOP TRAILING TRAILING-SIGN TRANSACTION " +\n
      "TYPE TYPEDEF UNDERLINE UNEQUAL UNIT " +\n
      "UNSTRING UNTIL UP UPDATE UPON " +\n
      "USAGE USAGE-MODE USE USING VALID " +\n
      "VALIDATE VALUE VALUES VARYING VLR " +\n
      "WAIT WHEN WHEN-COMPILED WITH WITHIN " +\n
      "WORDS WORKING-STORAGE WRITE XML XML-CODE " +\n
      "XML-EVENT XML-NTEXT XML-TEXT ZERO ZERO-FILL " );\n
\n
  var builtins = makeKeywords("- * ** / + < <= = > >= ");\n
  var tests = {\n
    digit: /\\d/,\n
    digit_or_colon: /[\\d:]/,\n
    hex: /[0-9a-f]/i,\n
    sign: /[+-]/,\n
    exponent: /e/i,\n
    keyword_char: /[^\\s\\(\\[\\;\\)\\]]/,\n
    symbol: /[\\w*+\\-]/\n
  };\n
  function isNumber(ch, stream){\n
    // hex\n
    if ( ch === \'0\' && stream.eat(/x/i) ) {\n
      stream.eatWhile(tests.hex);\n
      return true;\n
    }\n
    // leading sign\n
    if ( ( ch == \'+\' || ch == \'-\' ) && ( tests.digit.test(stream.peek()) ) ) {\n
      stream.eat(tests.sign);\n
      ch = stream.next();\n
    }\n
    if ( tests.digit.test(ch) ) {\n
      stream.eat(ch);\n
      stream.eatWhile(tests.digit);\n
      if ( \'.\' == stream.peek()) {\n
        stream.eat(\'.\');\n
        stream.eatWhile(tests.digit);\n
      }\n
      if ( stream.eat(tests.exponent) ) {\n
        stream.eat(tests.sign);\n
        stream.eatWhile(tests.digit);\n
      }\n
      return true;\n
    }\n
    return false;\n
  }\n
  return {\n
    startState: function () {\n
      return {\n
        indentStack: null,\n
        indentation: 0,\n
        mode: false\n
      };\n
    },\n
    token: function (stream, state) {\n
      if (state.indentStack == null && stream.sol()) {\n
        // update indentation, but only if indentStack is empty\n
        state.indentation = 6 ; //stream.indentation();\n
      }\n
      // skip spaces\n
      if (stream.eatSpace()) {\n
        return null;\n
      }\n
      var returnType = null;\n
      switch(state.mode){\n
      case "string": // multi-line string parsing mode\n
        var next = false;\n
        while ((next = stream.next()) != null) {\n
          if (next == "\\"" || next == "\\\'") {\n
            state.mode = false;\n
            break;\n
          }\n
        }\n
        returnType = STRING; // continue on in string mode\n
        break;\n
      default: // default parsing mode\n
        var ch = stream.next();\n
        var col = stream.column();\n
        if (col >= 0 && col <= 5) {\n
          returnType = COBOLLINENUM;\n
        } else if (col >= 72 && col <= 79) {\n
          stream.skipToEnd();\n
          returnType = MODTAG;\n
        } else if (ch == "*" && col == 6) { // comment\n
          stream.skipToEnd(); // rest of the line is a comment\n
          returnType = COMMENT;\n
        } else if (ch == "\\"" || ch == "\\\'") {\n
          state.mode = "string";\n
          returnType = STRING;\n
        } else if (ch == "\'" && !( tests.digit_or_colon.test(stream.peek()) )) {\n
          returnType = ATOM;\n
        } else if (ch == ".") {\n
          returnType = PERIOD;\n
        } else if (isNumber(ch,stream)){\n
          returnType = NUMBER;\n
        } else {\n
          if (stream.current().match(tests.symbol)) {\n
            while (col < 71) {\n
              if (stream.eat(tests.symbol) === undefined) {\n
                break;\n
              } else {\n
                col++;\n
              }\n
            }\n
          }\n
          if (keywords && keywords.propertyIsEnumerable(stream.current().toUpperCase())) {\n
            returnType = KEYWORD;\n
          } else if (builtins && builtins.propertyIsEnumerable(stream.current().toUpperCase())) {\n
            returnType = BUILTIN;\n
          } else if (atoms && atoms.propertyIsEnumerable(stream.current().toUpperCase())) {\n
            returnType = ATOM;\n
          } else returnType = null;\n
        }\n
      }\n
      return returnType;\n
    },\n
    indent: function (state) {\n
      if (state.indentStack == null) return state.indentation;\n
      return state.indentStack.indent;\n
    }\n
  };\n
});\n
\n
CodeMirror.defineMIME("text/x-cobol", "cobol");\n
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
            <value> <int>10288</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
