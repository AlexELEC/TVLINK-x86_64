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
    var sysVal;
    var useVal;
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
      sysVal = setInterval(function(){
        $("#stat_system").load("/use-sys");
      }, updTime);
      useVal = setInterval(function(){
        $("#stat_stream").load("/use-tvl");
      }, updTime);
    }

    function resetRefresh() {
      var updTime = parseInt(document.getElementById("rtime").value, 10);
      saveRefreshInterval(updTime);
      clearInterval(sysVal);
      clearInterval(useVal);
      if (updTime > 0){
        setRefresh(updTime * 1000)
      }
    }

    $(document).ready(function(){
      $("#stat_system").load("/use-sys");
      $("#stat_stream").load("/use-tvl");

      var refreshInterval = getSavedRefreshInterval();
      document.getElementById("rtime").value = refreshInterval;
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
      <td width="1%" align="right"><select id="rtime" class="form-control" width="10%" onchange="resetRefresh()" >
        % for tmr in range(0,31):
          <option {{'selected' if tmr == 5 else ""}} >{{tmr}}</option>
        % end
        </select>
      </td>
  </table>

  <div id="stat_system"></div>
  <div id="stat_stream"></div>

  <p>&nbsp;</p>
  <p>&nbsp;</p>
  <p>&nbsp;</p>

  <nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-bottom">
    <div class="container justify-content-center"> <button class="navbar-toggler navbar-toggler-right border-0" type="button" data-toggle="collapse" data-target="#navbar_bottom">
        <span class="navbar-toggler-icon"></span>
      </button>
      <a href="/logs" style="font-size:20px;color:white;font-weight:bold;">View program Logs</a>
    </div>
  </nav>



</body>

</html>
