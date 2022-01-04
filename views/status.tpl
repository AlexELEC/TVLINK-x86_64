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
    $(document).ready(function(){
      $("#stat_system").load("/use-sys");
      $("#stat_stream").load("/use-tvl");

      // Then reload it every x seconds ...
      setInterval(function(){
        $("#stat_system").load("/use-sys");
      }, 10000);
      setInterval(function(){
        $("#stat_stream").load("/use-tvl");
      }, 10000);
    });
  </script>

</head>

<body>
  % include('navbar-top.tpl')

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
