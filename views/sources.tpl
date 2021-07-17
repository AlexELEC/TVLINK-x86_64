<!DOCTYPE html>
<html>

% include('head.tpl')

<body>
  % include('navbar-top.tpl')
  % include('alert.tpl')
  <p>&nbsp;</p>

  <script>
    function modalClose(winID) {
        document.getElementById(winID).style.display = "none";
    }
    function delSource(m3uName) {
        if (confirm(m3uName + ": delete this source?")) {
            server.del_m3u_source(m3uName);
            location.reload(true);
        }
    }
    function delAddon(addonName) {
        if (confirm(addonName + ": delete this source?")) {
            server.del_addon_source(addonName);
            location.reload(true);
        }
    }
    function delEPG_map() {
        if (confirm("Delete EPG manual mapping channels?")) {
            server.delEPG_map();
        }
    }
    function delEpgSource(epgName) {
        if (confirm(epgName + ": delete this EPG source?")) {
            server.del_epg_source(epgName);
            location.reload(true);
        }
    }
    function delProfile(usrName) {
        if (confirm(usrName + ": delete this Profile?")) {
            server.del_profile(usrName);
            location.reload(true);
        }
    }
  </script>

  <!-- M3U Playlists -->

  % include('add-m3u.tpl')

  % checked_m3u = in_grps.get('Playlists')
  <table width="100%">
    <tr>
      <td width="20%"><b>Playlists sources:</b></td>
      <td><label class="switch">
        <input id="chbox_m3u_src" type="checkbox" onClick="server.m3u_src_grp()" {{'checked="checked"' if checked_m3u == 1 else ""}} >
        <span class="slider round"></span> </label>
      </td>
    </tr>
  </table>

  % if checked_m3u == 1:
  <p>&nbsp;</p>

  <form id="add_m3u_form" class="form-inline">
    <button id="btn_add_m3u" type="button" onClick="server.add_m3u_source()">Add playlist</button>
  </form>
  
  <p>&nbsp;</p>
  % end

  <table class="table" width="100%" border="2" id="m3u_table" style={{"display:block" if checked_m3u == 1 and is_m3u else "display:none"}} >

    <% tbl_head = '''
    <tr>
      <th width="4%" >Name</th>
      <th width="2%" >Enable</th> 
      <th width="2%" >Prio</th>
       <!-- <th width="2%" >Prio mode</th> -->
      <th width="2%" >Add channels</th>
      <th width="2%" >New channels</th>
      <th width="2%" >Update period</th>
      <th width="3%" >Update</th>
      <th width="3%" >Links</th>
    </tr>'''
    %>

    {{!tbl_head}}

    <!-- input_sources [ 0-srcName, 1-enabled, 2-grpName, 3-prio, 4-prioMode, 5-addCh, 6-updPeriod, 7-updDate, 8-links, 9-srcUrl, 10-newCh ] -->
    % for row in in_srcs:
    % if row[2] == 'Playlists':
    <tr>
      <!-- Name -->
      % ids = 'hrf_' + row[0]
        <td>
          <a id={{ids}} {{'href=/inputs/'+row[0] if row[1] == 1 and row[8] > 0 else ""}} >{{row[0]}}</a>
          <button class="btn" onClick="server.show_m3u_info('{{row[0]}}')" ><i class="fa fa-info-circle" style="font-size:26px;color:blue" ></i></button>
          <button class="btn" onClick="delSource('{{row[0]}}')" ><i class="fa fa-trash-o" style="font-size:26px;color:red" ></i></button>
        </td>
      <!-- Enable -->
      <td><label class="switch">
        % ids = 'src_' + row[0]
        <input id={{ids}} type="checkbox" onClick="server.click_switch('{{ids}}')" {{'checked="checked"' if row[1] == 1 else ""}} >
        <span class="slider round"></span></label>
      </td>
      <!-- Prio -->
      % ids = 'pri_' + row[0]
      <td><select id={{ids}} class="form-control" onchange="server.change_select('{{ids}}')" >
        % for prio in range(1,21):
          <option {{'selected' if prio == row[3] else ""}} >{{prio}}</option>
        % end
        </select>
      </td>
      <!-- Add channels -->
      <td><label class="switch">
        % ids = 'ach_' + row[0]
        <input id={{ids}} type="checkbox" onClick="server.click_switch('{{ids}}')" {{'checked="checked"' if row[5] == 1 else ""}} >
        <span class="slider round"></span></label>
      </td>
      <!-- New channels -->
      <td><label class="switch">
        % ids = 'new_' + row[0]
        <input id={{ids}} type="checkbox" onClick="server.click_switch('{{ids}}')" {{'checked="checked"' if row[10] == 1 else ""}} >
        <span class="slider round"></span></label>
      </td>
      <!-- Update period -->
      % ids = 'upr_' + row[0]
      <td><select id={{ids}} class="form-control" onchange="server.change_select('{{ids}}')" >
        % for prio in range(1,21):
          <option {{'selected' if prio == row[6] else ""}} >{{prio}}</option>
        % end
        </select>
      </td>
      <!-- Update -->
      % ids_bt = 'ubt_' + row[0]
      % ids_lb = 'ulb_' + row[0]
      <td>
        <button class="btn" onClick="server.upd_src_button('{{ids_lb}}')" ><i id={{ids_bt}} class="fa fa-refresh"></i></button>
        <label id={{ids_lb}} >{{row[7]}}</label>
      </td>
      <!-- Links -->
      % ids = 'lks_' + row[0]
      <td>
        <label id={{ids}} >{{row[8]}}</label>
      </td>
    </tr>
    % end
    % end
  </table>

  % if checked_m3u == 1:
  <p>&nbsp;</p>
  <p>&nbsp;</p>
  % end

  <!-- Addon sources -->

  % include('add-addon.tpl')

  % checked_addon = in_grps.get('Addons')
  <table width="100%">
    <tr>
      <td width="20%"><b>Addon sources:</b></td>
      <td><label class="switch">
        <input id="chbox_addon_src" type="checkbox" onClick="server.addon_src_grp()" {{'checked="checked"' if checked_addon == 1 else ""}} >
        <span class="slider round"></span> </label>
      </td>
    </tr>
  </table>

  % if checked_addon == 1:
  <p>&nbsp;</p>

  <form id="add_addon_form" class="form-inline">
    <button id="btn_add_addon" type="button" onClick="server.add_addon_source()">Add addon</button>
  </form>
  
  <p>&nbsp;</p>
  % end

  <table class="table" width="100%" border="2" id="addon_table" style={{"display:block" if checked_addon == 1 and is_addon else "display:none"}} >

    {{!tbl_head}}

    <!-- input_sources [ 0-srcName, 1-enabled, 2-grpName, 3-prio, 4-prioMode, 5-addCh, 6-updPeriod, 7-updDate, 8-links, 9-srcUrl, 10-newCh ] -->
    % for row in in_srcs:
    % if row[2] == 'Addons':
    <tr>
      <!-- Name -->
      % ids = 'hrf_' + row[0]
        <td>
          <a id={{ids}} {{'href=/inputs/'+row[0] if row[1] == 1 and row[8] > 0 else ""}} >{{row[0]}}</a>
          <button class="btn" onClick="delAddon('{{row[0]}}')" ><i class="fa fa-trash-o" style="font-size:26px;color:red" ></i></button>
        </td>
      <!-- Enable -->
      <td><label class="switch">
        % ids = 'src_' + row[0]
        <input id={{ids}} type="checkbox" onClick="server.click_switch('{{ids}}')" {{'checked="checked"' if row[1] == 1 else ""}} >
        <span class="slider round"></span></label>
      </td>
      <!-- Prio -->
      % ids = 'pri_' + row[0]
      <td><select id={{ids}} class="form-control" onchange="server.change_select('{{ids}}')" >
        % for prio in range(1,21):
          <option {{'selected' if prio == row[3] else ""}} >{{prio}}</option>
        % end
        </select>
      </td>
      <!-- Add channels -->
      <td><label class="switch">
        % ids = 'ach_' + row[0]
        <input id={{ids}} type="checkbox" onClick="server.click_switch('{{ids}}')" {{'checked="checked"' if row[5] == 1 else ""}} >
        <span class="slider round"></span></label>
      </td>
      <!-- New channels -->
      <td><label class="switch">
        % ids = 'new_' + row[0]
        <input id={{ids}} type="checkbox" onClick="server.click_switch('{{ids}}')" {{'checked="checked"' if row[10] == 1 else ""}} >
        <span class="slider round"></span></label>
      </td>
      <!-- Update period -->
      % ids = 'upr_' + row[0]
      <td><select id={{ids}} class="form-control" onchange="server.change_select('{{ids}}')" >
        % for prio in range(1,21):
          <option {{'selected' if prio == row[6] else ""}} >{{prio}}</option>
        % end
        </select>
      </td>
      <!-- Update -->
      % ids_bt = 'ubt_' + row[0]
      % ids_lb = 'ulb_' + row[0]
      <td>
        <button class="btn" onClick="server.upd_src_button('{{ids_lb}}')" ><i id={{ids_bt}} class="fa fa-refresh"></i></button>
        <label id={{ids_lb}} >{{row[7]}}</label>
      </td>
      <!-- Links -->
      % ids = 'lks_' + row[0]
      <td>
        <label id={{ids}} >{{row[8]}}</label>
      </td>
    </tr>
    % end
    % end
  </table>

  <p>&nbsp;</p>
  <p>&nbsp;</p>

  <!-- EPG sources -->

  <h4><b>XMLTV EPG sources</b></h4>
  <p>&nbsp;</p>

  <!-- EPG Static sources -->

  % checked_epg_static = in_grps_epg.get('Static')
  <table width="100%">
    <tr>
      <td width="20%"><b>EPG Static sources:</b></td>
      <td><label class="switch">
        <input id="epgbox_static_src" type="checkbox" onClick="server.epg_static_src_grp()" {{'checked="checked"' if checked_epg_static == 1 else ""}} >
        <span class="slider round"></span> </label>
      </td>
    </tr>
  </table>

  % if checked_epg_static == 1:
  <p>&nbsp;</p>
  % end

  <table class="table" width="100%" border="2" id="epg_static_table" style={{"display:block" if checked_epg_static == 1 else "display:none"}} >

    <% epg_tbl_head = '''
    <tr>
      <th width="4%" >Name</th>
      <th width="2%" >Enable</th> 
      <th width="2%" >Prio</th>
      <th width="3%" >File date</th>
      <th width="3%" >Update</th>
      <th width="3%" >Channels</th>
    </tr>'''
    %>

    {{!epg_tbl_head}}

    <!-- epg_sources [ 0-srcName, 1-enabled, 2-grpName, 3-prio, 4-xmlDate, 5-updDate, 6-srcUrl, 7-noDate, 8-links ] -->
    % for row in in_srcs_epg:
    % if row[2] == 'Static':
    <tr>
      <!-- Name -->
      % ids = 'hrf_' + row[0]
      <td><a id={{ids}} {{'href=/epginputs/'+row[0] if row[1] == 1 and row[8] > 0 else ""}} >{{row[0]}}</a></td>
      <!-- Enable -->
      <td><label class="switch">
        % ids = 'src_' + row[0]
        <input id={{ids}} type="checkbox" onClick="server.click_switch_epg('{{ids}}')" {{'checked="checked"' if row[1] == 1 else ""}} >
        <span class="slider round"></span></label>
      </td>
      <!-- Prio -->
      % ids = 'pri_' + row[0]
      <td><select id={{ids}} class="form-control" onchange="server.change_select_epg('{{ids}}')" >
        % for prio in range(1,21):
          <option {{'selected' if prio == row[3] else ""}} >{{prio}}</option>
        % end
        </select>
      </td>
      <!-- XMLTV file Date -->
      % ids = 'fdt_' + row[0]
      <td>
        <label id={{ids}} >{{row[4]}}</label>
      </td>
      <!-- Update -->
      % ids_bt = 'ubt_' + row[0]
      % ids_lb = 'ulb_' + row[0]
      <td>
        <button class="btn" onClick="server.upd_epgsrc_button('{{ids_lb}}')" ><i id={{ids_bt}} class="fa fa-refresh"></i></button>
        <label id={{ids_lb}} >{{row[5]}}</label>
      </td>
      <!-- Channels in EPG -->
      % ids = 'lks_' + row[0]
      <td>
        <label id={{ids}} >{{row[8]}}</label>
      </td>
    </tr>
    % end
    % end
  </table>

  % if checked_epg_static == 1:
  <p>&nbsp;</p>
  % end

  <!-- EPG User sources -->

  % include('add-epg.tpl')

  % checked_epg_user = in_grps_epg.get('User')
  <table width="100%">
    <tr>
      <td width="20%"><b>EPG Custom sources:</b></td>
      <td><label class="switch">
        <input id="epgbox_user_src" type="checkbox" onClick="server.epg_user_src_grp()" {{'checked="checked"' if checked_epg_user == 1 else ""}} >
        <span class="slider round"></span> </label>
      </td>
    </tr>
  </table>

  % if checked_epg_user == 1:
  <p>&nbsp;</p>
  <form id="epg_user_form" class="form-inline">
    <button id="btn_add_epg" type="button" onClick="server.add_epg_source()">Add EPG</button>
  </form>
  <p>&nbsp;</p>
  % end

  <table class="table" width="100%" border="2" id="epg_user_table" style={{"display:block" if checked_epg_user == 1 and is_epg else "display:none"}} >

    {{!epg_tbl_head}}

    <!-- epg_sources [ 0-srcName, 1-enabled, 2-grpName, 3-prio, 4-xmlDate, 5-updDate, 6-srcUrl, 7-noDate, 8-links ] -->
    % for row in in_srcs_epg:
    % if row[2] == 'User':
    <tr>
      <!-- Name -->
      % ids = 'hrf_' + row[0]
      <td>
        <a id={{ids}} {{'href=/epginputs/'+row[0] if row[1] == 1 and row[8] > 0 else ""}} >{{row[0]}}</a>
        <button class="btn" onClick="server.show_epg_info('{{row[0]}}')" ><i class="fa fa-info-circle" style="font-size:26px;color:blue" ></i></button>
        <button class="btn" onClick="delEpgSource('{{row[0]}}')" ><i class="fa fa-trash-o" style="font-size:26px;color:red" ></i></button>
      </td>
      <!-- Enable -->
      <td><label class="switch">
        % ids = 'src_' + row[0]
        <input id={{ids}} type="checkbox" onClick="server.click_switch_epg('{{ids}}')" {{'checked="checked"' if row[1] == 1 else ""}} >
        <span class="slider round"></span></label>
      </td>
      <!-- Prio -->
      % ids = 'pri_' + row[0]
      <td><select id={{ids}} class="form-control" onchange="server.change_select_epg('{{ids}}')" >
        % for prio in range(1,21):
          <option {{'selected' if prio == row[3] else ""}} >{{prio}}</option>
        % end
        </select>
      </td>
      <!-- XMLTV file Date -->
      % ids = 'fdt_' + row[0]
      <td>
        <label id={{ids}} >{{row[4]}}</label>
      </td>
      <!-- Update -->
      % ids_bt = 'ubt_' + row[0]
      % ids_lb = 'ulb_' + row[0]
      <td>
        <button class="btn" onClick="server.upd_epgsrc_button('{{ids_lb}}')" ><i id={{ids_bt}} class="fa fa-refresh"></i></button>
        <label id={{ids_lb}} >{{row[5]}}</label>
      </td>
      <!-- Channels in EPG -->
      % ids = 'lks_' + row[0]
      <td>
        <label id={{ids}} >{{row[8]}}</label>
      </td>
    </tr>
    % end
    % end
  </table>

  % if checked_epg_user == 1:
  <p>&nbsp;</p>
  % end
  <p>&nbsp;</p>

  <form class="form-inline" style={{"display:block" if checked_epg_static == 1 or checked_epg_user == 1 else "display:none"}}>
    <button id="btn_create_epg" type="button" onClick="server.createEPG()">Create EPG</button>
    <button id="btn_clean_epg" type="button" style="margin-left:2%;" onClick="delEPG_map()">Clean manual EPG mapping</button>
  </form>

  <p>&nbsp;</p>
  <p>&nbsp;</p>

  <!-- User Profiles -->

  % include('add-profile.tpl')

  <h4><b>User Profiles</b></h4>
  <p>&nbsp;</p>

  <form id="add_user" class="form-inline">
    <button id="btn_add_user" type="button" onClick="server.add_user()">Add user</button>
  </form>
  
  <p>&nbsp;</p>

  <table class="table" width="100%" border="2" id="usr_table" style={{"display:block" if is_users else "display:none"}} >

    <tr>
      <th width="5%" >Name</th>
      <th width="10%" >Comment</th>
    </tr>

    <!-- usr_profiles [ 0-usrName, 1-usrText ] -->
    % for row in in_users:
    <tr>
      <!-- Name -->
      <td>
        <a href="/profile/{{row[0]}}">{{row[0]}}    </a>
        <button class="btn" onClick="delProfile('{{row[0]}}')" ><i class="fa fa-trash-o" style="font-size:26px;color:red" ></i></button>
      </td>
      <!-- Comment -->
      <td>
        <label>{{row[1]}}</label>
      </td>
    </tr>
    % end
  </table>

  <p>&nbsp;</p>
  <p>&nbsp;</p>

</body>

</html>
