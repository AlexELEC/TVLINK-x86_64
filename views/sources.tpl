<!DOCTYPE html>
<html>

% include('head.tpl')

<body>
  % include('navbar-top.tpl')
  % include('alert.tpl')
  % include('edit-epg.tpl')
  % include('src-conf.tpl')
  <p>&nbsp;</p>

  <script>
    function modalClose(winID) {
        document.getElementById(winID).style.display = "none";
        location.reload(true);
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

  <!-- Prio  -->
  % val_prio = range(1,51)
  <!-- Update period  -->
  % val_update = range(0,97)

  <table class="table" width="100%" border="2" id="m3u_table" style={{"display:block" if checked_m3u == 1 and is_m3u else "display:none"}} >

    <tr>
      <th width="4%" >Name</th>
      <th width="2%" >Catchup</th>
      <th width="1%" >Enable</th> 
      <th width="2%" >Prio</th>
      <th width="2%" >Limit</th>
      <th width="2%" >Add channels</th>
      <th width="2%" >New channels</th>
      <th width="2%" >Update period</th>
      <th width="4%" >Update</th>
      <th width="1%" >Links</th>
    </tr>

    <!-- input_sources [ 0-srcName, 1-enabled, 2-grpName, 3-prio, 4-catchUp, 5-addCh, 6-updPeriod, 7-updDate, 8-links, 9-srcUrl, 10-newCh, 11-maxStrm ] -->
    % for row in in_srcs:
    % if row[2] == 'Playlists':
    <tr>
      <!-- Name -->
      % srcName = row[0]
      % ids = f'hrf_{srcName}'
      % shortName = srcName.replace("m3u_", "")
        <td>
          <a id={{ids}} {{f'href=/inputs/{srcName}' if row[1] == 1 and row[8] > 0 else ""}} >{{shortName}}</a>
          <button class="btn" onClick="server.show_src_conf('{{srcName}}')" ><i class="fa fa-wrench" style="font-size:26px;color:{{options_dist[srcName]}}" ></i></button>
          <button class="btn" onClick="delSource('{{srcName}}')" ><i class="fa fa-trash-o" style="font-size:26px;color:red" ></i></button>
        </td>
      <!-- Catchup -->
      % ids = f'arg_{srcName}'
      <td><select id={{ids}} class="form-control" onchange="server.change_select('{{ids}}')" >
        % for cath in ['none', 'append', 'flussonic', 'shift']:
          <option {{'selected' if cath == row[4] else ""}} >{{cath}}</option>
        % end
        </select>
      </td>
      <!-- Enable -->
      <td><label class="switch">
        % ids = f'src_{srcName}'
        <input id={{ids}} type="checkbox" onClick="server.click_switch('{{ids}}')" {{'checked="checked"' if row[1] == 1 else ""}} >
        <span class="slider round"></span></label>
      </td>
      <!-- Prio -->
      % ids = f'pri_{srcName}'
      <td><select id={{ids}} class="form-control" onchange="server.change_select('{{ids}}')" >
        % for prio in val_prio:
          <option {{'selected' if prio == row[3] else ""}} >{{prio}}</option>
        % end
        </select>
      </td>
      <!-- Max streams Limit -->
      % ids = f'mst_{srcName}'
      <td>
        <input id={{ids}} type="number" step="1" min="0" max="10" class="form-control" value="{{row[11]}}" onchange="server.change_select('{{ids}}')" >
      </td>
      <!-- Add channels -->
      <td><label class="switch">
        % ids = f'ach_{srcName}'
        <input id={{ids}} type="checkbox" onClick="server.click_switch('{{ids}}')" {{'checked="checked"' if row[5] == 1 else ""}} >
        <span class="slider round"></span></label>
      </td>
      <!-- New channels -->
      <td><label class="switch">
        % ids = f'new_{srcName}'
        <input id={{ids}} type="checkbox" onClick="server.click_switch('{{ids}}')" {{'checked="checked"' if row[10] == 1 else ""}} >
        <span class="slider round"></span></label>
      </td>
      <!-- Update period -->
      % ids = f'upr_{srcName}'
      <td><select id={{ids}} class="form-control" onchange="server.change_select('{{ids}}')" >
        % for prio in val_update:
          <option {{'selected' if prio == row[6] else ""}} >{{prio}}</option>
        % end
        </select>
      </td>
      <!-- Update -->
      % ids_bt = f'ubt_{srcName}'
      % ids_lb = f'ulb_{srcName}'
      <td>
        <button class="btn" onClick="server.upd_src_button('{{ids_lb}}')" ><i id={{ids_bt}} class="fa fa-refresh"></i></button>
        <label id={{ids_lb}} >{{row[7]}}</label>
      </td>
      <!-- Links -->
      % ids = f'lks_{srcName}'
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

    <tr>
      <th width="4%" >Name</th>
      <th width="2%" >Enable</th> 
      <th width="2%" >Prio</th>
      <th width="2%" >Limit</th>
      <th width="2%" >Add channels</th>
      <th width="2%" >New channels</th>
      <th width="2%" >Update period</th>
      <th width="3%" >Update</th>
      <th width="3%" >Links</th>
    </tr>

    <!-- input_sources [ 0-srcName, 1-enabled, 2-grpName, 3-prio, 4-catchUp, 5-addCh, 6-updPeriod, 7-updDate, 8-links, 9-srcUrl, 10-newCh, 11-maxStrm ] -->
    % for row in in_srcs:
    % if row[2] == 'Addons':
    <tr>
      <!-- Name -->
      % srcName = row[0]
      % ids = f'hrf_{srcName}'
        <td>
          <a id={{ids}} {{f'href=/inputs/{srcName}' if row[1] == 1 and row[8] > 0 else ""}} >{{srcName}}</a>
          <button class="btn" onClick="server.show_src_conf('{{srcName}}')" ><i class="fa fa-wrench" style="font-size:26px;color:{{options_dist[srcName]}}" ></i></button>
          <button class="btn" onClick="delAddon('{{srcName}}')" ><i class="fa fa-trash-o" style="font-size:26px;color:red" ></i></button>
        </td>
      <!-- Enable -->
      <td><label class="switch">
        % ids = f'src_{srcName}'
        <input id={{ids}} type="checkbox" onClick="server.click_switch('{{ids}}')" {{'checked="checked"' if row[1] == 1 else ""}} >
        <span class="slider round"></span></label>
      </td>
      <!-- Prio -->
      % ids = f'pri_{srcName}'
      <td><select id={{ids}} class="form-control" onchange="server.change_select('{{ids}}')" >
        % for prio in val_prio:
          <option {{'selected' if prio == row[3] else ""}} >{{prio}}</option>
        % end
        </select>
      </td>
      <!-- Max streams Limit -->
      % ids = f'mst_{srcName}'
      <td>
        <input id={{ids}} type="number" step="1" min="0" max="10" class="form-control" value="{{row[11]}}" onchange="server.change_select('{{ids}}')" >
      </td>
      <!-- Add channels -->
      <td><label class="switch">
        % ids = f'ach_{srcName}'
        <input id={{ids}} type="checkbox" onClick="server.click_switch('{{ids}}')" {{'checked="checked"' if row[5] == 1 else ""}} >
        <span class="slider round"></span></label>
      </td>
      <!-- New channels -->
      <td><label class="switch">
        % ids = f'new_{srcName}'
        <input id={{ids}} type="checkbox" onClick="server.click_switch('{{ids}}')" {{'checked="checked"' if row[10] == 1 else ""}} >
        <span class="slider round"></span></label>
      </td>
      <!-- Update period -->
      % ids = f'upr_{srcName}'
      <td><select id={{ids}} class="form-control" onchange="server.change_select('{{ids}}')" >
        % for prio in val_update:
          <option {{'selected' if prio == row[6] else ""}} >{{prio}}</option>
        % end
        </select>
      </td>
      <!-- Update -->
      % ids_bt = f'ubt_{srcName}'
      % ids_lb = f'ulb_{srcName}'
      <td>
        <button class="btn" onClick="server.upd_src_button('{{ids_lb}}')" ><i id={{ids_bt}} class="fa fa-refresh"></i></button>
        <label id={{ids_lb}} >{{row[7]}}</label>
      </td>
      <!-- Links -->
      % ids = f'lks_{srcName}'
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
      % srcName = row[0]
      % ids = f'hrf_{srcName}'
      <td>
        <a id={{ids}} {{f'href=/epginputs/{srcName}' if row[1] == 1 and row[8] > 0 else ""}} >{{srcName}}</a>
        <button class="btn" onClick="server.show_edit_epg_url('{{srcName}}')" ><i class="fa fa-pencil-square-o" style="font-size:26px;color:blue" ></i></button>
      </td>
      <!-- Enable -->
      <td><label class="switch">
        % ids = f'src_{srcName}'
        <input id={{ids}} type="checkbox" onClick="server.click_switch_epg('{{ids}}')" {{'checked="checked"' if row[1] == 1 else ""}} >
        <span class="slider round"></span></label>
      </td>
      <!-- Prio -->
      % ids = f'pri_{srcName}'
      <td><select id={{ids}} class="form-control" onchange="server.change_select_epg('{{ids}}')" >
        % for prio in val_prio:
          <option {{'selected' if prio == row[3] else ""}} >{{prio}}</option>
        % end
        </select>
      </td>
      <!-- XMLTV file Date -->
      % ids = f'fdt_{srcName}'
      <td>
        <label id={{ids}} >{{row[4]}}</label>
      </td>
      <!-- Update -->
      % ids_bt = f'ubt_{srcName}'
      % ids_lb = f'ulb_{srcName}'
      <td>
        <button class="btn" onClick="server.upd_epgsrc_button('{{ids_lb}}')" ><i id={{ids_bt}} class="fa fa-refresh"></i></button>
        <label id={{ids_lb}} >{{row[5]}}</label>
      </td>
      <!-- Channels in EPG -->
      % ids = f'lks_{srcName}'
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
      % srcName = row[0]
      % ids = f'hrf_{srcName}'
      <td>
        <a id={{ids}} {{f'href=/epginputs/{srcName}' if row[1] == 1 and row[8] > 0 else ""}} >{{srcName}}</a>
        <button class="btn" onClick="server.show_epg_info('{{srcName}}')" ><i class="fa fa-info-circle" style="font-size:26px;color:blue" ></i></button>
        <button class="btn" onClick="delEpgSource('{{srcName}}')" ><i class="fa fa-trash-o" style="font-size:26px;color:red" ></i></button>
      </td>
      <!-- Enable -->
      <td><label class="switch">
        % ids = f'src_{srcName}'
        <input id={{ids}} type="checkbox" onClick="server.click_switch_epg('{{ids}}')" {{'checked="checked"' if row[1] == 1 else ""}} >
        <span class="slider round"></span></label>
      </td>
      <!-- Prio -->
      % ids = f'pri_{srcName}'
      <td><select id={{ids}} class="form-control" onchange="server.change_select_epg('{{ids}}')" >
        % for prio in val_prio:
          <option {{'selected' if prio == row[3] else ""}} >{{prio}}</option>
        % end
        </select>
      </td>
      <!-- XMLTV file Date -->
      % ids = f'fdt_{srcName}'
      <td>
        <label id={{ids}} >{{row[4]}}</label>
      </td>
      <!-- Update -->
      % ids_bt = f'ubt_{srcName}'
      % ids_lb = f'ulb_{srcName}'
      <td>
        <button class="btn" onClick="server.upd_epgsrc_button('{{ids_lb}}')" ><i id={{ids_bt}} class="fa fa-refresh"></i></button>
        <label id={{ids_lb}} >{{row[5]}}</label>
      </td>
      <!-- Channels in EPG -->
      % ids = f'lks_{srcName}'
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
      <th width="10%" >Playlist URL</th>
      <th width="10%" >Comment</th>
    </tr>

    <!-- usr_profiles [ 0-usrName, 1-usrText, 2-usrIP, 3-usrToken ] -->
    % for row in in_users:
    <tr>
      <!-- Name -->
      % usrName = row[0]
      % usrText = row[1]
      % usrIP = row[2]
      % usrToken = row[3]
      <td>
        <a href="/profile/{{usrName}}">{{usrName}}</a>
        <button class="btn" onClick="server.edit_user('{{usrName}}')" ><i class="fa fa-wrench" style="font-size:26px;color:blue" ></i></button>
        <button class="btn" onClick="delProfile('{{usrName}}')" ><i class="fa fa-trash-o" style="font-size:26px;color:red" ></i></button>
      </td>
      <!-- Playlist -->
      <td>
        % if is_token == 'true':
          % pr_link = f'http://{usrIP}:{PORT}/{usrToken}/playlist/{usrName}'
        % else:
          % pr_link = f'http://{usrIP}:{PORT}/playlist/{usrName}'
        % end
        <a href="{{pr_link}}">{{pr_link}}</a>
      </td>
      <!-- Comment -->
      <td>
        <label>{{usrText}}</label>
      </td>
    </tr>
    % end
  </table>

  <p>&nbsp;</p>
  <p>&nbsp;</p>
  <p>&nbsp;</p>

  % if is_enabled:
  <nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-bottom">
    <div class="container justify-content-center"> <button class="navbar-toggler navbar-toggler-right border-0" type="button" data-toggle="collapse" data-target="#navbar_bottom">
        <span class="navbar-toggler-icon"></span>
      </button>
      <a href="/updsrc" id="countCH" style="font-size:20px;color:white;font-weight:bold;">Update all sources</a>
    </div>
  </nav>
  % end

</body>

</html>
