<!DOCTYPE html>
<html>

% include('head.tpl')

<body>
  % include('navbar-top.tpl')
  <p>&nbsp;</p>

  <table class="table" width="100%" border="2" >

    <tr>
      <th width="10%"  ><a href="#" onClick="sortTo('channel')">Channel</a></th>
      <th width="40%" ><a href="#" onClick="sortTo('auto')">Auto EPG mapping</a></th>
      <th width="40%" ><a href="#" onClick="sortTo('manual')">Manual EPG mapping</a></th>
    </tr>

    <!-- # dataChannels [ 0-chID, 1-chTitle, 2-epgNames_auto, 3-epgNames_hand ] -->
    % for row in dataChannels:
    % rowID = 'row_' + row[0]
    <tr id="{{rowID}}" >
      <!-- Channel Title -->
      <td>
        <label ><b>{{row[1]}}</b></label>
      </td>
      <!-- Auto EPG -->
      <td>
        <label >{{row[2]}}</label>
      </td>
      <!-- Manual EPG -->
      % ids = 'mnl_' + row[0]
      <td>
        <select id="{{ids}}" class="form-control" onchange="server.epg_manual_set('{{ids}}', '{{srcName}}')" >
        % for epgNames in dataListEPGchls:
          % if not row[3]:
            <option {{'selected' if epgNames == '' else ""}} >{{epgNames}}</option>
          % else:
            <option {{'selected' if epgNames == row[3] else ""}} >{{epgNames}}</option>
          % end
        % end
        </select>
      </td>
    </tr>
    % end
  </table>

  <script>
    function sortTo(order) {
        server.sort_epg(order);
        location.reload(true);
    }
  </script>

  <p>&nbsp;</p>
  <p>&nbsp;</p>

  <nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-bottom">
    <div class="container justify-content-center"> <button class="navbar-toggler navbar-toggler-right border-0" type="button" data-toggle="collapse" data-target="#navbar_bottom">
        <span class="navbar-toggler-icon"></span>
      </button>
      <label style="font-size:20px;color:white;font-weight:bold;">source: {{srcName}}</label>
      <div class="collapse navbar-collapse text-center justify-content-center" id="navbar_bottom">
        <ul class="navbar-nav">
          <button class="btn" onclick="window.location.href='/epginputs/{{srcName}}'" ><i class="fa fa-fast-backward" style="font-size:20px;color:white" ></i></button>
          <button class="btn" onclick="window.location.href='/epginputs/{{srcName}}/{{page-1}}'" {{'disabled="disabled"' if page <= 1 else ""}} ><i class="fa fa-backward" style="font-size:20px;color:white" ></i></button>
          <button class="btn" onclick="window.location.href='/epginputs/{{srcName}}/{{page+1}}'" {{'disabled="disabled"' if page >= last_page else ""}} ><i class="fa fa-forward" style="font-size:20px;color:white" ></i></button>
          <button class="btn" onclick="window.location.href='/epginputs/{{srcName}}/{{last_page}}'" ><i class="fa fa-fast-forward" style="font-size:20px;color:white" ></i></button>
        </ul>
      </div>
      <label id="countSrc" style="font-size:20px;color:white;font-weight:bold;">channels: {{CNL_TOTAL}}</label>
    </div>
  </nav>

</body>

</html>
