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
            <value> <string>ts21897145.5</string> </value>
        </item>
        <item>
            <key> <string>__name__</string> </key>
            <value> <string>mirc.js</string> </value>
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
//mIRC mode by Ford_Lawnmower :: Based on Velocity mode by Steve O\'Hara\n
\n
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
CodeMirror.defineMIME("text/mirc", "mirc");\n
CodeMirror.defineMode("mirc", function() {\n
  function parseWords(str) {\n
    var obj = {}, words = str.split(" ");\n
    for (var i = 0; i < words.length; ++i) obj[words[i]] = true;\n
    return obj;\n
  }\n
  var specials = parseWords("$! $$ $& $? $+ $abook $abs $active $activecid " +\n
                            "$activewid $address $addtok $agent $agentname $agentstat $agentver " +\n
                            "$alias $and $anick $ansi2mirc $aop $appactive $appstate $asc $asctime " +\n
                            "$asin $atan $avoice $away $awaymsg $awaytime $banmask $base $bfind " +\n
                            "$binoff $biton $bnick $bvar $bytes $calc $cb $cd $ceil $chan $chanmodes " +\n
                            "$chantypes $chat $chr $cid $clevel $click $cmdbox $cmdline $cnick $color " +\n
                            "$com $comcall $comchan $comerr $compact $compress $comval $cos $count " +\n
                            "$cr $crc $creq $crlf $ctime $ctimer $ctrlenter $date $day $daylight " +\n
                            "$dbuh $dbuw $dccignore $dccport $dde $ddename $debug $decode $decompress " +\n
                            "$deltok $devent $dialog $did $didreg $didtok $didwm $disk $dlevel $dll " +\n
                            "$dllcall $dname $dns $duration $ebeeps $editbox $emailaddr $encode $error " +\n
                            "$eval $event $exist $feof $ferr $fgetc $file $filename $filtered $finddir " +\n
                            "$finddirn $findfile $findfilen $findtok $fline $floor $fopen $fread $fserve " +\n
                            "$fulladdress $fulldate $fullname $fullscreen $get $getdir $getdot $gettok $gmt " +\n
                            "$group $halted $hash $height $hfind $hget $highlight $hnick $hotline " +\n
                            "$hotlinepos $ial $ialchan $ibl $idle $iel $ifmatch $ignore $iif $iil " +\n
                            "$inelipse $ini $inmidi $inpaste $inpoly $input $inrect $inroundrect " +\n
                            "$insong $instok $int $inwave $ip $isalias $isbit $isdde $isdir $isfile " +\n
                            "$isid $islower $istok $isupper $keychar $keyrpt $keyval $knick $lactive " +\n
                            "$lactivecid $lactivewid $left $len $level $lf $line $lines $link $lock " +\n
                            "$lock $locked $log $logstamp $logstampfmt $longfn $longip $lower $ltimer " +\n
                            "$maddress $mask $matchkey $matchtok $md5 $me $menu $menubar $menucontext " +\n
                            "$menutype $mid $middir $mircdir $mircexe $mircini $mklogfn $mnick $mode " +\n
                            "$modefirst $modelast $modespl $mouse $msfile $network $newnick $nick $nofile " +\n
                            "$nopath $noqt $not $notags $notify $null $numeric $numok $oline $onpoly " +\n
                            "$opnick $or $ord $os $passivedcc $pic $play $pnick $port $portable $portfree " +\n
                            "$pos $prefix $prop $protect $puttok $qt $query $rand $r $rawmsg $read $readomo " +\n
                            "$readn $regex $regml $regsub $regsubex $remove $remtok $replace $replacex " +\n
                            "$reptok $result $rgb $right $round $scid $scon $script $scriptdir $scriptline " +\n
                            "$sdir $send $server $serverip $sfile $sha1 $shortfn $show $signal $sin " +\n
                            "$site $sline $snick $snicks $snotify $sock $sockbr $sockerr $sockname " +\n
                            "$sorttok $sound $sqrt $ssl $sreq $sslready $status $strip $str $stripped " +\n
                            "$syle $submenu $switchbar $tan $target $ticks $time $timer $timestamp " +\n
                            "$timestampfmt $timezone $tip $titlebar $toolbar $treebar $trust $ulevel " +\n
                            "$ulist $upper $uptime $url $usermode $v1 $v2 $var $vcmd $vcmdstat $vcmdver " +\n
                            "$version $vnick $vol $wid $width $wildsite $wildtok $window $wrap $xor");\n
  var keywords = parseWords("abook ajinvite alias aline ame amsg anick aop auser autojoin avoice " +\n
                            "away background ban bcopy beep bread break breplace bset btrunc bunset bwrite " +\n
                            "channel clear clearall cline clipboard close cnick color comclose comopen " +\n
                            "comreg continue copy creq ctcpreply ctcps dcc dccserver dde ddeserver " +\n
                            "debug dec describe dialog did didtok disable disconnect dlevel dline dll " +\n
                            "dns dqwindow drawcopy drawdot drawfill drawline drawpic drawrect drawreplace " +\n
                            "drawrot drawsave drawscroll drawtext ebeeps echo editbox emailaddr enable " +\n
                            "events exit fclose filter findtext finger firewall flash flist flood flush " +\n
                            "flushini font fopen fseek fsend fserve fullname fwrite ghide gload gmove " +\n
                            "gopts goto gplay gpoint gqreq groups gshow gsize gstop gtalk gunload hadd " +\n
                            "halt haltdef hdec hdel help hfree hinc hload hmake hop hsave ial ialclear " +\n
                            "ialmark identd if ignore iline inc invite iuser join kick linesep links list " +\n
                            "load loadbuf localinfo log mdi me menubar mkdir mnick mode msg nick noop notice " +\n
                            "notify omsg onotice part partall pdcc perform play playctrl pop protect pvoice " +\n
                            "qme qmsg query queryn quit raw reload remini remote remove rename renwin " +\n
                            "reseterror resetidle return rlevel rline rmdir run ruser save savebuf saveini " +\n
                            "say scid scon server set showmirc signam sline sockaccept sockclose socklist " +\n
                            "socklisten sockmark sockopen sockpause sockread sockrename sockudp sockwrite " +\n
                            "sound speak splay sreq strip switchbar timer timestamp titlebar tnick tokenize " +\n
                            "toolbar topic tray treebar ulist unload unset unsetall updatenl url uwho " +\n
                            "var vcadd vcmd vcrem vol while whois window winhelp write writeint if isalnum " +\n
                            "isalpha isaop isavoice isban ischan ishop isignore isin isincs isletter islower " +\n
                            "isnotify isnum ison isop isprotect isreg isupper isvoice iswm iswmcs " +\n
                            "elseif else goto menu nicklist status title icon size option text edit " +\n
                            "button check radio box scroll list combo link tab item");\n
  var functions = parseWords("if elseif else and not or eq ne in ni for foreach while switch");\n
  var isOperatorChar = /[+\\-*&%=<>!?^\\/\\|]/;\n
  function chain(stream, state, f) {\n
    state.tokenize = f;\n
    return f(stream, state);\n
  }\n
  function tokenBase(stream, state) {\n
    var beforeParams = state.beforeParams;\n
    state.beforeParams = false;\n
    var ch = stream.next();\n
    if (/[\\[\\]{}\\(\\),\\.]/.test(ch)) {\n
      if (ch == "(" && beforeParams) state.inParams = true;\n
      else if (ch == ")") state.inParams = false;\n
      return null;\n
    }\n
    else if (/\\d/.test(ch)) {\n
      stream.eatWhile(/[\\w\\.]/);\n
      return "number";\n
    }\n
    else if (ch == "\\\\") {\n
      stream.eat("\\\\");\n
      stream.eat(/./);\n
      return "number";\n
    }\n
    else if (ch == "/" && stream.eat("*")) {\n
      return chain(stream, state, tokenComment);\n
    }\n
    else if (ch == ";" && stream.match(/ *\\( *\\(/)) {\n
      return chain(stream, state, tokenUnparsed);\n
    }\n
    else if (ch == ";" && !state.inParams) {\n
      stream.skipToEnd();\n
      return "comment";\n
    }\n
    else if (ch == \'"\') {\n
      stream.eat(/"/);\n
      return "keyword";\n
    }\n
    else if (ch == "$") {\n
      stream.eatWhile(/[$_a-z0-9A-Z\\.:]/);\n
      if (specials && specials.propertyIsEnumerable(stream.current().toLowerCase())) {\n
        return "keyword";\n
      }\n
      else {\n
        state.beforeParams = true;\n
        return "builtin";\n
      }\n
    }\n
    else if (ch == "%") {\n
      stream.eatWhile(/[^,^\\s^\\(^\\)]/);\n
      state.beforeParams = true;\n
      return "string";\n
    }\n
    else if (isOperatorChar.test(ch)) {\n
      stream.eatWhile(isOperatorChar);\n
      return "operator";\n
    }\n
    else {\n
      stream.eatWhile(/[\\w\\$_{}]/);\n
      var word = stream.current().toLowerCase();\n
      if (keywords && keywords.propertyIsEnumerable(word))\n
        return "keyword";\n
      if (functions && functions.propertyIsEnumerable(word)) {\n
        state.beforeParams = true;\n
        return "keyword";\n
      }\n
      return null;\n
    }\n
  }\n
  function tokenComment(stream, state) {\n
    var maybeEnd = false, ch;\n
    while (ch = stream.next()) {\n
      if (ch == "/" && maybeEnd) {\n
        state.tokenize = tokenBase;\n
        break;\n
      }\n
      maybeEnd = (ch == "*");\n
    }\n
    return "comment";\n
  }\n
  function tokenUnparsed(stream, state) {\n
    var maybeEnd = 0, ch;\n
    while (ch = stream.next()) {\n
      if (ch == ";" && maybeEnd == 2) {\n
        state.tokenize = tokenBase;\n
        break;\n
      }\n
      if (ch == ")")\n
        maybeEnd++;\n
      else if (ch != " ")\n
        maybeEnd = 0;\n
    }\n
    return "meta";\n
  }\n
  return {\n
    startState: function() {\n
      return {\n
        tokenize: tokenBase,\n
        beforeParams: false,\n
        inParams: false\n
      };\n
    },\n
    token: function(stream, state) {\n
      if (stream.eatSpace()) return null;\n
      return state.tokenize(stream, state);\n
    }\n
  };\n
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
            <value> <int>10082</int> </value>
        </item>
        <item>
            <key> <string>title</string> </key>
            <value> <string></string> </value>
        </item>
      </dictionary>
    </pickle>
  </record>
</ZopeData>
