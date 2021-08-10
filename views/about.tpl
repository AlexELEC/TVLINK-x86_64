<!DOCTYPE html>
<html>

% include('head.tpl')

<body>
  % include('navbar-top.tpl')
  <p>&nbsp;</p>

  <div style="width:50%;margin: 0 auto;text-align:center;">
    <h4 id="version"><b>TVLINK version: {{version}}</b></h4>
    <p>&nbsp;</p>
    % if is_upd:
      <em id="upd_info">Version <b>{{git_ver}}</b> is available. You can update the program!</em>
      <p></p>
      <button id="btn_upd" class="btn" onClick="server.upd_tvlink()" ><i id="upd_spin" class="fa fa-refresh fa-3x fa-fw"></i></button>
      <p>&nbsp;</p>
    % end
    <p><a href="https://alexelec.tv"><img src="/styles/logo.png" style="border:0" ></a></p>
    <p>&nbsp;</p>
    The program does not broadcast anything.
    TVLINK only caches the streams specified by the user or found in the open Internet access.
    <p>&nbsp;</p>
    <b>License: {{lictype}}</b>
    <p>&nbsp;</p>


    <table class="table" border="2" >
      <tr>
        <td>
          Direct playlist
        </td>
        <td>
          <a href="http://{{HOST}}/playlist">http://{{HOST}}/playlist</a>
        </td>
      </tr>
      <tr>
        <td>
          Tvheadend playlist
        </td>
        <td>
          <a href="http://{{HOST}}/tvhlist">http://{{HOST}}/tvhlist</a>
        </td>
      </tr>
      <tr>
        <td>
          XMLTV EPG
        </td>
        <td>
          <a href="http://{{HOST}}/xmltv">http://{{HOST}}/xmltv</a>
        </td>
      </tr>
    </table>
    <p>&nbsp;</p>
    Telegram chat: <a href="https://t.me/tvlinkae">t.me/tvlinkae</a>
    <p><a href="https://t.me/tvlinkae"><img src="/styles/telegram.png" style="border:0" ></a></p>
    The program uses the open source code of the project <a href="https://streamlink.github.io/index.html">Streamlink</a>
    <p><a href="https://streamlink.github.io/index.html"><img src="/styles/streamlink.png" style="border:0" ></a></p>
    Copyright © 2020 all rights reserved to <a href="https://alexelec.tv">Alex@ELEC</a>
    <p>&nbsp;</p>
  </div>

</body>

</html>
