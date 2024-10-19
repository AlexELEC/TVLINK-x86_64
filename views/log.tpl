<!DOCTYPE html>
<html>

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Cache-control" content="no-cache, no-store, must-revalidate">
  <meta http-equiv="Pragma" content="no-cache">
  <link rel="stylesheet" href="/styles/font-awesome/css/font-awesome.min.css" type="text/css">
  <link rel="stylesheet" href="/styles/bootstrap-4.3.1.css">
  <link rel="stylesheet" href="/styles/styles.css" type="text/css">
  <link rel="shortcut icon" href="/styles/favicon.ico">
  <script src="/styles/jquery.min.js">

  <script>
    var logVal;

    function setRefresh(updTime) {
      logVal = setInterval(function(){
        $("#logger").load("/logger/tvlink.log");
      }, updTime);
    }

    function resetRefresh() {
      updTime = document.getElementById("ltime").value;
      clearInterval(logVal);
      if (updTime > 0){
        setRefresh(updTime * 1000)
      }
    }

    $(document).ready(function(){
      // load log file
      $("#logger").load("/logger/tvlink.log");

      // Then reload it every 5 seconds ...
      setRefresh(5000);
    });
  </script>

</head>

<body>
  % include('navbar-top.tpl')

  <table width="85%" style="position:fixed">
    <tr>
      <td width="30%" align="right"><b><font color="blue" >Refresh page (sec):&nbsp;&nbsp;</font></b></td>
      <td width="1%" align="right"><select id="ltime" class="form-control" width="10%" onchange="resetRefresh()" >
        % for tmr in range(0,31):
          <option {{'selected' if tmr == 5 else ""}} >{{tmr}}</option>
        % end
        </select>
      </td>
  </table>

  <pre>
    <div id="logger"></div>
  </pre>

  <p>&nbsp;</p>

</body>

</html>
