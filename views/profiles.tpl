<!DOCTYPE html>
<html>

% include('head.tpl')

<body>
  % include('navbar-top.tpl')
  <p>&nbsp;</p>

  <!-- GROUPS -->
  % if is_groups:
  <h4><b><font color="blue">Groups profile:</font></b></h4>
  <p>&nbsp;</p>
  
    <% tbl_head = '''
    <tr>
      <th width="10%">Group Title</th>
      <th width="2%" >Enabled</th>
    </tr>'''
    %>

  <div style="overflow:hidden;_zoom:1">

    % show_grps_table1 = 1 if len(dtbGroups1) else 0
    <table class="table" border="2" style={{"float:left;width:49%;display:block" if show_grps_table1 == 1 else "display:none"}} >

      {{!tbl_head}}

      <!-- groups database [ 0-grpTitle ] -->
      % for row in dtbGroups1:
      <tr>
        <!-- Title -->
        <td>
          <label class="form-control">{{row[0]}}</label>
        </td>
      <!-- Enabled -->
      <%
        from zlib import crc32
        grp_code = crc32(row[0].encode('utf-8')) & 0xFFFFFFFF
        ids = 'grp_' + str("%08X" % grp_code)
        if row[0] in delGroups:
            grp_status = False
        else:
            grp_status = True
        end
      %>
       <td><label class="switch">
          <input id="{{ids}}" type="checkbox" onClick="server.profile_grps('{{ids}}', '{{usrName}}', '{{row[0]}}')" {{'checked="checked"' if grp_status else ""}} >
          <span class="slider round"></span></label>
        </td>
      </tr>
      % end
    </table>

    % show_grps_table2 = 1 if len(dtbGroups2) else 0
    <table class="table" border="2" style={{"float:right;width:49%;display:block" if show_grps_table2 == 1 else "display:none"}} >

      {{!tbl_head}}

      <!-- groups database [ 0-grpTitle ] -->
      % for row in dtbGroups2:
      <tr>
        <!-- Title -->
        <td>
          <label class="form-control">{{row[0]}}</label>
        </td>
      <!-- Enabled -->
      <%
        from zlib import crc32
        grp_code = crc32(row[0].encode('utf-8')) & 0xFFFFFFFF
        ids = 'grp_' + str("%08X" % grp_code)
        if row[0] in delGroups:
            grp_status = False
        else:
            grp_status = True
        end
      %>
       <td><label class="switch">
          <input id="{{ids}}" type="checkbox" onClick="server.profile_grps('{{ids}}', '{{usrName}}', '{{row[0]}}')" {{'checked="checked"' if grp_status else ""}} >
          <span class="slider round"></span></label>
        </td>
      </tr>
      % end
    </table>

  </div>

  <p>&nbsp;</p>
   % end

  <!-- CHANNELS -->
  % if is_channels:
  <h4><b><font color="blue">Channels profile:</font></b></h4>
  <p>&nbsp;</p>

  <table class="table" width="100%" border="2" >

    <tr>
      <th width="1%"  >Logo</th>
      <th width="2%"  >Enabled</th>
      <th width="10%" ><a href="#" onClick="sortTo('names')">Name</a></th>
      <th width="10%" ><a href="#" onClick="sortTo('groups')">Group</a></th>
      <th width="2%"  >ID</th>
    </tr>

    <!-- # channels database [ 0-chID, 1-chTitle, 2-chGroup, 3-chLogo ] -->
    % for row in dtbChannels:
    <tr>
      <!-- Logo -->
      <%
        import os, sys
        root_dir = os.path.dirname(sys.argv[0])
        sys.path.append(root_dir)
        from utils import get_logo
        logo_url = get_logo(row[0])
      %>
      <td bgcolor="2C3E50">
        <img src="{{logo_url}}" style="border:0;width:45%;" >
      </td>
      <!-- Enabled -->
      <%
        ids = 'cnl_' + row[0]
        if row[0] in delChannels:
            cnl_status = False
        else:
            cnl_status = True
        end
      %>
      <td>
        <label class="switch">
           <input id="{{ids}}" type="checkbox" onClick="server.profile_chls('{{ids}}', '{{usrName}}', '{{row[0]}}')" {{'checked="checked"' if cnl_status else ""}} >
        <span class="slider round"></span></label>
      </td>
      <!-- Name -->
      <td>
        <b>{{row[1]}}</b>
      </td>
      <!-- Group -->
      <td>
        <label >{{row[2]}}</label>
      </td>
      <!-- ID -->
      <td>
        <label >{{row[0]}}</label>
      </td>
    </tr>
    % end
  </table>


  % end

  <script>
    function sortTo(order) {
        server.sort_channels(order);
        location.reload(true);
    }
  </script>

  <!-- FOOTER -->
  <p>&nbsp;</p>
  <p>&nbsp;</p>

  <nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-bottom">
    <div class="container justify-content-center"> <button class="navbar-toggler navbar-toggler-right border-0" type="button" data-toggle="collapse" data-target="#navbar_bottom">
        <span class="navbar-toggler-icon"></span>
      </button>
      <label style="font-size:20px;color:white;font-weight:bold;">profile: {{usrName}}</label>
      <div class="collapse navbar-collapse text-center justify-content-center" id="navbar_bottom">
        <ul class="navbar-nav">
          <button class="btn" onclick="window.location.href='/profile/{{usrName}}'" ><i class="fa fa-fast-backward" style="font-size:20px;color:white" ></i></button>
          <button class="btn" onclick="window.location.href='/profile/{{usrName}}/{{page-1}}'" {{'disabled="disabled"' if page <= 1 else ""}} ><i class="fa fa-backward" style="font-size:20px;color:white" ></i></button>
          <label style="font-size:20px;color:white;font-weight:bold;">&nbsp;&nbsp;&nbsp;{{page}}&nbsp;&nbsp;&nbsp;</label>
          <button class="btn" onclick="window.location.href='/profile/{{usrName}}/{{page+1}}'" {{'disabled="disabled"' if page >= last_page else ""}} ><i class="fa fa-forward" style="font-size:20px;color:white" ></i></button>
          <button class="btn" onclick="window.location.href='/profile/{{usrName}}/{{last_page}}'" ><i class="fa fa-fast-forward" style="font-size:20px;color:white" ></i></button>
        </ul>
      </div>
      <label id="countSrc" style="font-size:20px;color:white;font-weight:bold;">channels: {{CNL_TOTAL}}</label>
    </div>
  </nav>

</body>

</html>
