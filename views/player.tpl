<!DOCTYPE html>
<html>

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="/styles/font-awesome/css/font-awesome.min.css" type="text/css">
  <link rel="stylesheet" href="/styles/bootstrap-4.3.1.css">
  <link rel="stylesheet" href="/styles/styles.css" type="text/css">
  <link rel="shortcut icon" href="/styles/favicon.ico">
  <script type="module" src="https://esm.run/mpegts-video-element"></script>
</head>

<body>

<nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-top">
    <div class="container justify-content-center">
      <label style="font-size:20px;color:white;font-weight:bold;">{{chTitle}}&nbsp;({{chGroup}})</label>
    </div>
</nav>
<p>&nbsp;</p>
<p>&nbsp;</p>

  <center>
    <mpegts-video
      muted
      autoplay
      controls
      preload="auto"
      src="{{ch_url}}">
    </mpegts-video>
  </center>


<nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-bottom">
  <div class="container justify-content-center">
    <a href="{{ch_url}}" style="font-size:20px;color:white;font-weight:bold;">{{ch_url}}</label>
  </div>
</nav>

</body>

</html>
