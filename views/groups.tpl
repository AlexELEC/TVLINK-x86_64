<!DOCTYPE html>
<html>

% include('head.tpl')

<body>
  % include('navbar-top.tpl')
  <p>&nbsp;</p>

  <form class="form-inline" >
    <label><b>Create new group:</b></label>
    <input id="txt_new_grp" type="text" placeholder="Enter new group" >
    <button id="btn_new_grp" type="button" onClick="createGroup()">OK</button>
    <label style="margin-left:10%;"><b>Clean all groups:</b></label>
    <button id="btn_new_grp" type="button" onClick="delGroupsAll()">Clean</button>
  </form>

  <script>
    function createGroup() {
        server.create_grp_button(document.getElementById('txt_new_grp').value);
        location.reload(true);
    }
    function delGroupsAll() {
        if (confirm("Delete all Groups?")) {
            server.del_all_grps_button();
            location.reload(true);
        }
    }
    function renameGroup(ids) {
        server.rename_grp_button(ids, document.getElementById(ids).value);
        location.reload(true);
    }
    function delGroup(ids) {
        server.del_grp_button(ids);
        location.reload(true);
    }
  </script>

  <p>&nbsp;</p>
  
    <% tbl_head = '''
    <tr>
      <th width="10%" >Title</th>
      <th width="2%" >Enabled</th>
      <th width="2%" >Delete</th>
    </tr>'''
    %>

  <div style="overflow:hidden;_zoom:1">

    % show_grps_table1 = 1 if len(dtbGroups1) else 0
    <table class="table" border="2" style={{"float:left;width:49%;display:block" if show_grps_table1 == 1 else "display:none"}} >

      {{!tbl_head}}

      <!-- groups database [ 0-grpID, 1-grpTitle, 2-enabled ] -->
      % for row in dtbGroups1:
      <tr>
        <!-- Title -->
        % ids = 'rmn_' + row[0]
        <td>
          <input id="{{ids}}" class="form-control" type="text" value="{{row[1]}}" onchange="renameGroup('{{ids}}')" >
        </td>
        <!-- Enabled -->
        % ids = 'egs_' + row[0]
        <td><label class="switch">
          <input id={{ids}} type="checkbox" onClick="server.enabled_grp_switch('{{ids}}')" {{'checked="checked"' if row[2] == 1 else ""}} >
          <span class="slider round"></span></label>
        </td>
        <!-- Delete -->
        % ids = 'dgb_' + row[0]
        <td>
          <button class="btn" onClick="delGroup('{{ids}}')" ><i class="fa fa-trash-o" style="font-size:26px;color:red" ></i></button>
        </td>
      </tr>
      % end
    </table>

    % show_grps_table2 = 1 if len(dtbGroups2) else 0
    <table class="table" border="2" style={{"float:right;width:49%;display:block" if show_grps_table2 == 1 else "display:none"}} >

      {{!tbl_head}}

      <!-- groups database [ 0-grpID, 1-grpTitle, 2-enabled ] -->
      % for row in dtbGroups2:
      <tr>
        <!-- Title -->
        % ids = 'rmn_' + row[0]
        <td>
          <input id="{{ids}}" class="form-control" type="text" value="{{row[1]}}" onchange="renameGroup('{{ids}}')" >
        </td>
        <!-- Enabled -->
        % ids = 'egs_' + row[0]
        <td><label class="switch">
          <input id={{ids}} type="checkbox" onClick="server.enabled_grp_switch('{{ids}}')" {{'checked="checked"' if row[2] == 1 else ""}} >
          <span class="slider round"></span></label>
        </td>
        <!-- Delete -->
        % ids = 'dgb_' + row[0]
        <td>
          <button class="btn" onClick="delGroup('{{ids}}')" ><i class="fa fa-trash-o" style="font-size:26px;color:red" ></i></button>
        </td>
      </tr>
      % end
    </table>

  </div>

  <p>&nbsp;</p>
  <p>&nbsp;</p>

  <nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-bottom">
    <div class="container justify-content-center"> <button class="navbar-toggler navbar-toggler-right border-0" type="button" data-toggle="collapse" data-target="#navbar_bottom">
        <span class="navbar-toggler-icon"></span>
      </button>
      <a href="/sort_groups" id="sortGRP" style="font-size:20px;color:white;font-weight:bold;">Sort groups</a>
    </div>
  </nav>

</body>

</html>
