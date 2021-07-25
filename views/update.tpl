<!DOCTYPE html>
<html>

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="/styles/font-awesome/css/font-awesome.min.css" type="text/css">
  <link rel="stylesheet" href="/styles/bootstrap-4.3.1.css">
  <link rel="stylesheet" href="/styles/styles.css" type="text/css">
  <link rel="shortcut icon" href="/styles/favicon.ico">
  <script src="/styles/jquery.min.js">

  <script>
    $(document).ready(function(){
      setTimeout(function(){window.location.replace("/about");}, 30000);
    });
  </script>

  <style>
    #blink {
      -webkit-animation: blink 2s linear infinite;
      animation: blink 2s linear infinite;
    }
    @-webkit-keyframes blink {
      0% { color: rgba(34, 34, 34, 1); }
      50% { color: rgba(34, 34, 34, 0); }
      100% { color: rgba(34, 34, 34, 1); }
    }
    @keyframes blink {
      0% { color: rgba(34, 34, 34, 1); }
      50% { color: rgba(34, 34, 34, 0); }
      100% { color: rgba(34, 34, 34, 1); }
    }
  </style>

</head>

<body>
  % include('navbar-top.tpl')
  <p>&nbsp;</p>

  <div style="text-align:center">
    <h4 id="blink"><b>Restart program. Wait 30 seconds...</b></h4>
  </div>

</body>

</html>
