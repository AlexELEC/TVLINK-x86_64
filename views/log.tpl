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
      // load log file
      $("#logger").load("/logger/tvlink.log");

      // Then reload it every x seconds ...
      setInterval(function(){
        $("#logger").load("/logger/tvlink.log");
      }, 5000);
    });
  </script>

</head>

<body>
  % include('navbar-top.tpl')
  <p>&nbsp;</p>

  <pre>
    <div id="logger"></div>
  </pre>

  <p>&nbsp;</p>

</body>

</html>
