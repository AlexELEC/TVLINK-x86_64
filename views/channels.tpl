<!DOCTYPE html>
<html>

% include('head.tpl')

<body>
  % include('navbar-top.tpl')
  <p>&nbsp;</p>

  % include('alert.tpl')
  % include('set-logo.tpl')
  % include('join-channels.tpl')
  % include('split-channels.tpl')
  % include('info-channels.tpl')
  % include('local-logos.tpl')

  <table class="table" width="100%" border="2" >

    <tr>
      <th width="2%" >Logo</th>
      <th width="1%" ><a href="#" onClick="sortTo('number')">Num</a></th>
      <th width="10%" ><a href="#" onClick="sortTo('names')">Name</a></th>
      <th width="10%" ><a href="#" onClick="sortTo('groups')">Group</a></th>
      <th width="2%" ><a href="#" onClick="uncheckSpl()">Clean</a></th> 
      <th width="12%" >Control</th>
      <th width="3%" >ID</th>
    </tr>

    <!-- channels database [ 0-chID, 1-chTitle, 2-chGroup, 3-chLogo, 4-chBinds, 5-chSplit, 6-chExist, 7-chNum ] -->
    % for row in dtbChannels:
    % rowID = 'row_' + row[0]
    <tr id="{{rowID}}" >
      <!-- Logo -->
      <%
        ids = 'ico_' + row[0]
        import os, sys
        root_dir = os.path.dirname(sys.argv[0])
        sys.path.append(root_dir)
        from utils import get_logo
        logo_url = get_logo(row[0])
      %>
      <td>
        <button class="btn" style="border:0" onClick="server.show_modal_logo('{{ids}}')" >
          <img id="{{ids}}" src="{{logo_url}}" style="width:60%" >
        </button>
      </td>
      <!-- Number -->
      <%
        ids = 'num_' + row[0]
        try:
            num = row[7]
        except:
            num = ""
        end
        if not num:
            num = ""
        end
      %>
      <td>
        <input id="{{ids}}" class="form-control" type="text" value="{{num}}" onchange="server.set_ch_number('{{ids}}')" >
      </td>
      <!-- Title -->
      % ids = 'cht_' + row[0]
      <td>
        <input id="{{ids}}" class="form-control" type="text" value="{{row[1]}}" onchange="server.rename_ch_title('{{ids}}')" >
      </td>
      <!-- Group -->
      % ids = 'chg_' + row[0]
      <td>
        <select id="{{ids}}" class="form-control" onchange="server.rename_ch_group('{{ids}}')" >
        % for grp in listGroups:
          % if not row[2]:
            <option {{'selected' if grp[0] == '' else ""}} >{{grp[0]}}</option>
          % else:
            <option {{'selected' if grp[0] == row[2] else ""}} >{{grp[0]}}</option>
          % end
        % end
      </td>
      <!-- CheckBox Join -->
      % ids = 'spl_' + row[0]
      <td>
        <input id="{{ids}}" class="form-control" type="checkbox" onClick="server.join_channel_chbox('{{ids}}')" {{'checked="checked"' if row[5] == 1 else ""}} >
      </td>
      <!-- Control -->
      % ids = 'ctl_' + row[0]
      <td>
        <button class="btn" onClick="server.show_info_modal('{{row[0]}}', '{{row[1]}}')" ><i class="fa fa-info-circle" style="font-size:26px;color:black" ></i></button>
        <button class="btn" onClick="server.show_join_modal('{{ids}}')" ><i class="fa fa-link" style="font-size:26px;color:blue" ></i></button>
        <button class="btn" onClick="server.show_split_modal('{{ids}}')" ><i class="fa fa-chain-broken" style="font-size:26px;color:green" ></i></button>
        <button class="btn" onClick="server.del_channel_button('{{rowID}}')" ><i class="fa fa-trash-o" style="font-size:26px;color:red" ></i></button>
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
    function uncheckSpl() {
        server.uncheck_channels_split();
        location.reload(true);
    }
    function delAllChannels() {
        if (confirm("Delete all Channels?")) {
            server.delete_all_channels();
        }
    }
    function modalClose(winID) {
        if (winID == "mdJoin" || winID == "mdSplit") {
            server.clean_jnsp_vars(winID);
        }
        document.getElementById(winID).style.display = "none";
    }
  </script>

  <p>&nbsp;</p>
  <p>&nbsp;</p>

  <nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-bottom">
    <div class="container justify-content-center"> <button class="navbar-toggler navbar-toggler-right border-0" type="button" data-toggle="collapse" data-target="#navbar_bottom">
        <span class="navbar-toggler-icon"></span>
      </button>
      <a href="/playlist" id="countCH" style="font-size:20px;color:white;font-weight:bold;">Channels: {{CNL_TOTAL}}</a>
      <div class="collapse navbar-collapse text-center justify-content-center" id="navbar_bottom">
        <ul class="navbar-nav">
          <button class="btn" onclick="window.location.href='/channels'" ><i class="fa fa-fast-backward" style="font-size:20px;color:white" ></i></button>
          <button class="btn" onclick="window.location.href='/channels/{{page-1}}'" {{'disabled="disabled"' if page <= 1 else ""}} ><i class="fa fa-backward" style="font-size:20px;color:white" ></i></button>
          <button class="btn" onclick="window.location.href='/channels/{{page+1}}'" {{'disabled="disabled"' if page >= last_page else ""}} ><i class="fa fa-forward" style="font-size:20px;color:white" ></i></button>
          <button class="btn" onclick="window.location.href='/channels/{{last_page}}'" ><i class="fa fa-fast-forward" style="font-size:20px;color:white" ></i></button>
        </ul>
      </div>
      <a href="/" onClick="delAllChannels()" style="font-size:20px;color:white;font-weight:bold;" >Delete channels</a>
    </div>
  </nav>

</body>

</html>
