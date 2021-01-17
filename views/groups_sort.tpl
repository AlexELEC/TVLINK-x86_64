<!DOCTYPE html>
<html>

% include('head.tpl')

<body>
  % include('navbar-top.tpl')
  <p>&nbsp;</p>

  <h4><b>Sort groups for Direct playlist:</b></h4>
  <p>&nbsp;</p>
  
    <% tbl_head = '''
    <tr>
      <th width="10%" >Group Title</th>
      <th width="2%" >Number</th>
    </tr>'''
    %>

  <div style="overflow:hidden;_zoom:1">

    % show_grps_table1 = 1 if len(dtbGroups1) else 0
    <table class="table" border="2" style={{"float:left;width:49%;display:block" if show_grps_table1 == 1 else "display:none"}} >

      {{!tbl_head}}

      <!-- groups database [ 0-grpID, 1-grpTitle, 2-grpNum ] -->
      % for row in dtbGroups1:
      <tr>
        <!-- Title -->
        <td>
          <label class="form-control">{{row[1]}}</label>
        </td>
      <!-- Number -->
      <%
        ids = 'num_' + row[0]
        try:
            num = row[2]
        except:
            num = ""
        end
        if not num:
            num = ""
        end
      %>
        <td>
          <input id="{{ids}}" class="form-control" type="text" value="{{num}}" onchange="server.set_grp_number('{{ids}}')" >
        </td>
      </tr>
      % end
    </table>

    % show_grps_table2 = 1 if len(dtbGroups2) else 0
    <table class="table" border="2" style={{"float:right;width:49%;display:block" if show_grps_table2 == 1 else "display:none"}} >

      {{!tbl_head}}

      <!-- groups database [ 0-grpID, 1-grpTitle, 2-grpNum ] -->
      % for row in dtbGroups2:
      <tr>
        <!-- Title -->
        <td>
          <label class="form-control">{{row[1]}}</label>
        </td>
      <!-- Number -->
      <%
        ids = 'num_' + row[0]
        try:
            num = row[2]
        except:
            num = ""
        end
        if not num:
            num = ""
        end
      %>
        <td>
          <input id="{{ids}}" class="form-control" type="text" value="{{num}}" onchange="server.set_grp_number('{{ids}}')" >
        </td>
      </tr>
      % end
    </table>

  </div>

  <p>&nbsp;</p>
  <p>&nbsp;</p>

</body>

</html>
