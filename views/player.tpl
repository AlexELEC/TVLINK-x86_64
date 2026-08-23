<!DOCTYPE html>
<html>

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <link rel="stylesheet" href="/styles/font-awesome/css/font-awesome.min.css" type="text/css">
  <link rel="stylesheet" href="/styles/bootstrap-4.3.1.css">
  <link rel="stylesheet" href="/styles/styles.css" type="text/css">
  <link rel="shortcut icon" href="/styles/favicon.ico">

  <script src="https://cdn.jsdelivr.net/npm/mpegts.js@1.8.0/dist/mpegts.min.js"></script>

  <style>
    html, body {
      width: 100%;
      height: 100%;
      margin: 0;
      padding: 0;
      overflow: hidden;
      background: #000;
    }

    .player-header {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      height: 56px;
      z-index: 10;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #151515;
    }

    .player-header label {
      margin: 0;
      padding: 0 10px;
      font-size: 20px;
      line-height: 56px;
      color: white;
      font-weight: bold;
      text-align: center;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .player-area {
      position: fixed;
      top: 56px;
      left: 0;
      right: 0;
      bottom: 56px;

      display: flex;
      align-items: center;
      justify-content: center;

      background: #000;
    }

    #videoElement {
      display: block;
      width: 100%;
      height: 100%;
      object-fit: contain;
      background: #000;
    }

    .player-footer {
      position: fixed;
      left: 0;
      right: 0;
      bottom: 0;
      height: 56px;
      z-index: 10;

      display: flex;
      align-items: center;
      justify-content: center;

      background: #151515;
      overflow: hidden;
    }

    .player-footer a {
      max-width: 100%;
      padding: 0 8px;

      font-size: 16px;
      color: white;
      font-weight: bold;

      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
  </style>
</head>

<body>

  <!-- Channel title -->
  <div class="player-header">
    <label>{{chTitle}}&nbsp;({{chGroup}})</label>
  </div>

  <!-- Video -->
  <div class="player-area">
    <video id="videoElement"
           muted
           autoplay
           controls
           playsinline
           preload="auto">
    </video>
  </div>

  <!-- Stream URL -->
  <div class="player-footer">
    <a href="{{ch_url}}">{{ch_url}}</a>
  </div>


  <script>
    const videoElement = document.getElementById('videoElement');

    const player = mpegts.createPlayer({
      type: 'mpegts',
      isLive: true,
      url: '{{ch_url}}'
    });

    player.attachMediaElement(videoElement);
    player.load();

    player.play().catch(function(error) {
      console.log('Autoplay failed:', error);
    });
  </script>

</body>

</html>
