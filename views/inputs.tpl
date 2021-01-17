<!DOCTYPE html>
<html>

% include('head.tpl')

<body>
  % include('navbar-top.tpl')
  % include('alert.tpl')
  <p>&nbsp;</p>

  <table class="table" width="100%" border="2" >

    <tr>
      <th width="1%" >Logo</th>
      <th width="2%" >Map</th>
      <th width="10%" ><a href="#" onClick="sortTo('names')">Name</a></th>
      <th width="10%" ><a href="#" onClick="sortTo('groups')">Group</a></th>
      <th width="2%" >Info</th>
      <th width="2%" >ID</th>
    </tr>

    <!-- # input channels [ 0-chID, 1-chTitle, 2-chGroup, 3-chUrl, 4-chLogo ] -->
    % for row in dtbInputs:
    % rowID = 'row_' + row[0]
    <tr id="{{rowID}}" >
      <!-- Logo -->
      <%
        import os, sys
        root_dir = os.path.dirname(sys.argv[0])
        sys.path.append(root_dir)
        from utils import get_logo
        logo_url = get_logo(row[0], srcName)
      %>
      <td>
        <img src="{{logo_url}}" style="border:0;width:45%;" >
      </td>
      <!-- Map -->
      <td>
        <label class="switch">
          <input type="checkbox" onClick="server.chbox_map_channel('{{row[0]}}', '{{row[1]}}', '{{row[2]}}', '{{row[3]}}', '{{row[4]}}')" >
        <span class="slider round"></span></label>
      </td>
      <!-- Title -->
      <td>
        <b>{{row[1]}}</b>
      </td>
      <!-- Group -->
      <td>
        <label >{{row[2]}}</label>
      </td>
      <!-- Control -->
      <td>
        <button class="btn" onClick="server.src_channel_info('{{srcName}}', '{{row[0]}}')" ><i class="fa fa-info-circle" style="font-size:26px;color:black" ></i></button>
      </td>
      <!-- ID -->
      <td>
        <label >{{row[0]}}</label>
      </td>
    </tr>
    % end
  </table>

  <script>
    function sortTo(order) {
        server.sort_channels(order);
        location.reload(true);
    }
    function modalClose(winID) {
        document.getElementById(winID).style.display = "none";
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
          <button class="btn" onclick="window.location.href='/inputs/{{srcName}}'" ><i class="fa fa-fast-backward" style="font-size:20px;color:white" ></i></button>
          <button class="btn" onclick="window.location.href='/inputs/{{srcName}}/{{page-1}}'" {{'disabled="disabled"' if page <= 1 else ""}} ><i class="fa fa-backward" style="font-size:20px;color:white" ></i></button>
          <button class="btn" onclick="window.location.href='/inputs/{{srcName}}/{{page+1}}'" {{'disabled="disabled"' if page >= last_page else ""}} ><i class="fa fa-forward" style="font-size:20px;color:white" ></i></button>
          <button class="btn" onclick="window.location.href='/inputs/{{srcName}}/{{last_page}}'" ><i class="fa fa-fast-forward" style="font-size:20px;color:white" ></i></button>
        </ul>
      </div>
      <label id="countSrc" style="font-size:20px;color:white;font-weight:bold;">channels: {{CNL_TOTAL}}</label>
    </div>
  </nav>

</body>

</html>
