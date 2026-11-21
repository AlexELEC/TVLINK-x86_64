<!DOCTYPE html>
<html>

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Cache-control" content="no-cache, no-store, must-revalidate">
  <meta http-equiv="Pragma" content="no-cache">
  <script src="/styles/theme.js?v=theme-1"></script>
  <link rel="stylesheet" href="/styles/font-awesome/css/font-awesome.min.css" type="text/css">
  <link rel="stylesheet" href="/styles/bootstrap-4.3.1.css">
  <link rel="stylesheet" href="/styles/styles.css?v=theme-3" type="text/css">
  <link rel="shortcut icon" href="/styles/favicon.ico">
  <script src="/styles/jquery.min.js"></script>

  <script>
    var logVal;
    var refreshStorageKey = "tvlink-refresh-interval";

    function getSavedRefreshInterval() {
      try {
        var value = parseInt(window.localStorage.getItem(refreshStorageKey), 10);
        if (value >= 0 && value <= 30) {
          return value;
        }
      } catch (error) {
        // Use the default when browser storage is unavailable.
      }
      return 5;
    }

    function saveRefreshInterval(value) {
      try {
        window.localStorage.setItem(refreshStorageKey, String(value));
      } catch (error) {
        // Refreshing still works when browser storage is unavailable.
      }
    }

    function setRefresh(updTime) {
      logVal = setInterval(function(){
        $("#logger").load("/logger/tvlink.log");
      }, updTime);
    }

    function resetRefresh() {
      var updTime = parseInt(document.getElementById("ltime").value, 10);
      saveRefreshInterval(updTime);
      clearInterval(logVal);
      if (updTime > 0){
        setRefresh(updTime * 1000)
      }
    }

    $(document).ready(function(){
      // load log file
      $("#logger").load("/logger/tvlink.log");

      var refreshInterval = getSavedRefreshInterval();
      document.getElementById("ltime").value = refreshInterval;
      if (refreshInterval > 0) {
        setRefresh(refreshInterval * 1000);
      }
    });
  </script>

</head>

<body>
  % include('navbar-top.tpl')

  <table width="95%" style="position:fixed">
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
