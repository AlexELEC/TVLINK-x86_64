<!DOCTYPE html>
<html>

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="/styles/font-awesome/css/font-awesome.min.css" type="text/css">
  <link rel="stylesheet" href="/styles/bootstrap-4.3.1.css">
  <link rel="stylesheet" href="/styles/styles.css" type="text/css">
  <link rel="shortcut icon" href="/styles/favicon.ico">
</head>

<body>
  % include('navbar-top.tpl')
  <p>&nbsp;</p>

  <div style="width:50%;margin: 0 auto;text-align:center;">
    <h4 id="version"><b>TVLINK version: {{version}}</b></h4>
    <p>&nbsp;</p>
    % if is_upd:
      <em>Version <b>{{git_ver}}</b> is available. <a href="/update">Update program...</a></em>
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
    Copyright © 2020 all rights reserved to <a href="https://alexelec.tv">Alex@ELEC</a>
  </div>

</body>

</html>
