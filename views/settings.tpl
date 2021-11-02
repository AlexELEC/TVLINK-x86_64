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
  </script>

    <% tbl_head = '''
    <tr>
      <th width="10%" >Option</th>
      <th width="3%" >Value</th>
    </tr>'''
    %>

  <h4><b>Service settings:</b></h4>
  <p>&nbsp;</p>

  <div style="overflow:hidden;_zoom:1">

    <table class="table" border="2" style="float:left;width:49%;display:block" >

      {{!tbl_head}}

      <!-- Port -->
      <tr>
        <td >
          <label class="form-control">Server Port</label>
        </td>
        <td>
          <input id="srv_port" class="form-control" type="text" value="{{PORT}}" onchange="server.set_port()" >
        </td>
      </tr>
      <!-- IP -->
      <tr>
        <td>
          <label class="form-control">Playlist IP</label>
        </td>
        <td>
          <select id="pls_ip" class="form-control" onchange="server.set_ip()" >
            % for ip in ip_list:
              <option {{'selected' if ip == IP else ""}} >{{ip}}</option>
            % end
          </select>
        </td>
      </tr>
      <!-- Auto IP -->
      <tr>
        <td>
          <label class="form-control">Auto playlist IP</label>
        </td>
        <td><label class="switch">
          <input id="aut_ip" type="checkbox" onClick="server.auto_ip()" {{'checked="checked"' if not auto_ip == 'false' else ""}} >
          <span class="slider round"></span></label>
        </td>
      </tr>
      <!-- Check internet IP -->
      <tr>
        <td>
          <label class="form-control">Check internet IP</label>
        </td>
        <td>
          <input id="check_ip" class="form-control" type="text" value="{{check_net_ip}}" onchange="server.set_checkip()" >
        </td>
      </tr>

    </table>

    <table class="table" border="2" style="float:right;width:49%;display:block" >

      {{!tbl_head}}

      <!-- Refresh startup -->
      <tr>
        <td>
          <label class="form-control">Refresh sources at startup</label>
        </td>
        <td><label class="switch">
          <input id="upd_ch_start" type="checkbox" onClick="server.update_ch_startup()" {{'checked="checked"' if upd_ch_start == 'true' else ""}} >
          <span class="slider round"></span></label>
        </td>
      </tr>
      <!-- Refresh startup -->
      <tr>
        <td>
          <label class="form-control">Refresh sources at playlist</label>
        </td>
        <td><label class="switch">
          <input id="upd_ch_list" type="checkbox" onClick="server.update_ch_list()" {{'checked="checked"' if upd_ch_list == 'true' else ""}} >
          <span class="slider round"></span></label>
        </td>
      </tr>
      <!-- Remove channels -->
      <tr>
        <td>
          <label class="form-control">Remove broken channels</label>
        </td>
        <td><label class="switch">
          <input id="del_ch_broken" type="checkbox" onClick="server.del_broken_channel()" {{'checked="checked"' if del_ch == 'true' else ""}} >
          <span class="slider round"></span></label>
        </td>
      </tr>
      <!-- Check internet timeout -->
      <tr>
        <td >
          <label class="form-control">Check internet max time</label>
        </td>
        <td>
          <select id="check_time" class="form-control" onchange="server.setting_options('check_time')" >
            % for chtime in ['10sec','30sec','60sec','10min','30min','60min','10hr','30hr','60hr']:
            <option {{'selected' if chtime == check_time else ""}} >{{chtime}}</option>
            % end
          </select>
        </td>
      </tr>

    </table>

  </div>

  <p>&nbsp;</p>
  <b>Periodic reload settings:</b>
  <p>&nbsp;</p>
  <div style="overflow:hidden;_zoom:1">
  <table class="table" border="2" style="float:left;width:49%;display:block" >

      {{!tbl_head}}

      <!-- Reload by interval -->
      <tr>
        <td>
          <label class="form-control">Reload by interval</label>
        </td>
        <td><label class="switch">
          <input id="swt_period" type="checkbox" onClick="server.reload_period('period')" {{'checked="checked"' if swt_period == 'true' else ""}} >
          <span class="slider round"></span></label>
        </td>
      </tr>
      <!-- Reload once a day -->
      <tr>
        <td>
          <label class="form-control">Reload once a day</label>
        </td>
        <td><label class="switch">
          <input id="swt_once" type="checkbox" onClick="server.reload_period('once')" {{'checked="checked"' if swt_once == 'true' else ""}} >
          <span class="slider round"></span></label>
        </td>
      </tr>
  </table>

  <table class="table" border="2" style="float:right;width:49%;display:block" >

    {{!tbl_head}}

      <!-- Reload by interval (hours) -->
      <tr>
        <td>
          <label class="form-control">Reload every hours</label>
        </td>
        <td>
          <select id="reset_period" class="form-control" onchange="server.setting_options('reset_period')" >
            % for rst in [1,2,3,4,5,6,7,8,9,10,12,14,18,20,24,48,72,120,168]:
            <option {{'selected' if rst == int(reset_period) else ""}} >{{rst}}</option>
            % end
          </select>
        </td>
      </tr>
      <!-- Reload once a day (time) -->
      <tr>
        <td>
          <label class="form-control">Reload at o'clock</label>
        </td>
        <td>
          <select id="reset_once" class="form-control" onchange="server.setting_options('reset_once')" >
            % for once in range(0,24):
            <option {{'selected' if once == int(reset_once) else ""}} >{{once}}</option>
            % end
          </select>
        </td>
      </tr>

  </table>
  </div>

  <p>&nbsp;</p>
  <label><b>Empty channel link</b></label>
  <form class="form-inline" >
    <input id="empty_chlink" class="form-control" size="100%" value="{{empty_chlink}}" onchange="server.set_empty_chlink()">
  </form>

  <p>&nbsp;</p>
  <label><b>Exclude these lines from channel names when mapping (comma separated)</b></label>
  <form class="form-inline" >
    <input id="exclude_title" class="form-control" size="100%" value="{{exclude_title}}" onchange="server.set_exclude_title()">
  </form>

  <p>&nbsp;</p>
  <h4><b>M3U playlist settings (optional):</b></h4>
  <p>&nbsp;</p>

  <label><b>add elements to #EXTM3U</b></label>
  <form class="form-inline" >
    <input id="extm3u" class="form-control" size="100%" value="{{extm3u}}" onchange="server.set_extm3u()">
  </form>

  <p>&nbsp;</p>
  <label><b>add elements to #EXTINF</b></label>
  <form class="form-inline" >
    <input id="extinf" class="form-control" size="100%" value="{{extinf}}" onchange="server.set_extinf()">
  </form>
  <p>&nbsp;</p>

  <h4><b>Streamer settings:</b></h4>
  <p>&nbsp;</p>

  <form class="form-inline" >
    <label class="form-control"><b>Main User-Agent:</b></label>
    <input id="usr_agent" size="50%" class="form-control" value="{{usr_agent}}" onchange="server.set_usr_agent()">
  </form>
  <p>&nbsp;</p>

  <div style="overflow:hidden;_zoom:1">

    <table class="table" border="2" style="float:left;width:49%;display:block" >

      {{!tbl_head}}
      % buf_values = [5,10,20,30,40,50,80,100,150,200]
      % chunk_values = [8192, 16384, 24576, 32768, 65536]

      <!-- Stream Buffer -->
      <tr>
        <td >
          <label class="form-control">Stream buffer (Mb)</label>
        </td>
        <td>
          <select id="ring_buffer" class="form-control" onchange="server.setting_options('ring_buffer')" >
            % for tbuf in buf_values:
            <option {{'selected' if tbuf == int(ring_buffer) else ""}} >{{tbuf}}</option>
            % end
          </select>
        </td>
      </tr>
      <!-- TS chunk size -->
      <tr>
        <td >
          <label class="form-control">TS chunk size</label>
        </td>
        <td>
          <select id="chunk_size_ts" class="form-control" onchange="server.setting_options('chunk_size_ts')" >
            % for tchunk in chunk_values:
            <option {{'selected' if tchunk == int(chunk_size_ts) else ""}} >{{tchunk}}</option>
            % end
          </select>
        </td>
      </tr>
      <!-- HLS chunk size -->
      <tr>
        <td >
          <label class="form-control">HLS chunk size</label>
        </td>
        <td>
          <select id="chunk_size_hls" class="form-control" onchange="server.setting_options('chunk_size_hls')" >
            % for tchunk in chunk_values:
            <option {{'selected' if tchunk == int(chunk_size_hls) else ""}} >{{tchunk}}</option>
            % end
          </select>
        </td>
      </tr>
      <!-- Stream Timeout -->
      <tr>
        <td>
          <label class="form-control">Stream/Segment timeout (sec)</label>
        </td>
        <td>
          <select id="stream_timeout" class="form-control" onchange="server.setting_options('stream_timeout')" >
            % for ht_tout in range(1,61):
            <option {{'selected' if ht_tout == int(stream_timeout) else ""}} >{{ht_tout}}</option>
            % end
          </select>
        </td>
      </tr>
      <!-- Stream retry count -->
      <tr>
        <td>
          <label class="form-control">Stream retry count</label>
        </td>
        <td>
          <select id="stream_retry" class="form-control" onchange="server.setting_options('stream_retry')" >
            % for hl_tout in range(0,61):
            <option {{'selected' if hl_tout == int(stream_retry) else ""}} >{{hl_tout}}</option>
            % end
          </select>
        </td>
      </tr>

    </table>

    <table class="table" border="2" style="float:right;width:49%;display:block" >

      {{!tbl_head}}

      <!-- Segment Threads -->
      <tr>
        <td>
          <label class="form-control">Segment threads</label>
        </td>
        <td>
          <select id="stream_segment_threads" class="form-control" onchange="server.setting_options('stream_segment_threads')" >
            % for thrd in range(1,11):
            <option {{'selected' if thrd == int(stream_segment_threads) else ""}} >{{thrd}}</option>
            % end
          </select>
        </td>
      </tr>
      <!-- HLS Live Edge -->
      <tr>
        <td>
          <label class="form-control">HLS live edge</label>
        </td>
        <td>
          <select id="hls_live_edge" class="form-control" onchange="server.setting_options('hls_live_edge')" >
            % for edge in range(1,11):
            <option {{'selected' if edge == int(hls_live_edge) else ""}} >{{edge}}</option>
            % end
          </select>
        </td>
      </tr>
      <!-- HLS Playlist Reload Time -->
      <tr>
        <td>
          <label class="form-control">HLS playlist reload time</label>
        </td>
        <td>
          <select id="hls_playlist_reload_time" class="form-control" onchange="server.setting_options('hls_playlist_reload_time')" >
            % for rltime in ['default', 'duration', 'segment', 'average']:
            <option {{'selected' if rltime == hls_playlist_reload_time else ""}} >{{rltime}}</option>
            % end
          </select>
        </td>
      </tr>
      <!-- HLS Live Restart -->
      <tr>
        <td>
          <label class="form-control">HLS Live Restart</label>
        </td>
        <td>
          <label class="switch">
          <input id="hls_restart" type="checkbox" onClick="server.hls_restart()" {{'checked="checked"' if hls_restart == 'true' else ""}} >
          <span class="slider round"></span>
          </label>
        </td>
      </tr>
      <!-- Debug Streams -->
      <tr>
        <td>
          <label class="form-control">Debug Streams</label>
        </td>
        <td>
          <label class="switch">
          <input id="dbg_stream" type="checkbox" onClick="server.dbg_stream()" {{'checked="checked"' if dbg_stream == 'true' else ""}} >
          <span class="slider round"></span>
          </label>
        </td>
      </tr>

    </table>

  </div>

  <p>&nbsp;</p>

  <form class="form-inline">
    <label class="form-control"><b>Sources Proxy:</b></label>
    <input id="src_proxy" size="47%" class="form-control" type="text" value="{{proxy_url}}" onchange="server.set_proxy()"></input>
  </form>

  <p>&nbsp;</p>
  <h4><b>EPG settings:</b></h4>
  <p>&nbsp;</p>

  <div style="overflow:hidden;_zoom:1">

    <table class="table" border="2" style="float:left;width:49%;display:block" >

      {{!tbl_head}}

      <!-- EPG update -->
      <tr>
        <td>
          <label class="form-control">Auto update EPG</label>
        </td>
        <td><label class="switch">
          <input id="epg_enabled" type="checkbox" onClick="server.set_epg_enable()" {{'checked="checked"' if not epg_enabled == 'false' else ""}} >
          <span class="slider round"></span></label>
        </td>
      </tr>

    </table>

    <table class="table" border="2" style="float:right;width:49%;display:block" >

      {{!tbl_head}}
      % epg_period_values = [3,5,8,10,12,24,36,48,72,96,120,'1 (once night)', '2 (once night)', '3 (once night)', '4 (once night)', '5 (once night)']

      <!-- EPG period -->
      <tr>
        <td >
          <label class="form-control">Update period EPG (hours)</label>
        </td>
        <td>
          <select id="epg_period" class="form-control" onchange="server.setting_options('epg_period')" >
            % for tpr in epg_period_values:
            <option {{'selected' if str(tpr) == str(epg_period) else ""}} >{{tpr}}</option>
            % end
          </select>
        </td>
      </tr>

    </table>

  </div>

  <p>&nbsp;</p>
  <p>&nbsp;</p>

  <form class="form-inline">
    <label class="form-control"><b>License key:</b></label>
    <input id="lic_key" size="50%" class="form-control" type="password" value="{{lic_key}}"></input>
    <button id="btn_ae_auth" type="button" onClick="server.set_lickey()">OK</button>
  </form>

  <p>&nbsp;</p>
  <p>&nbsp;</p>
  <p>&nbsp;</p>

  <nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-bottom">
    <div class="container justify-content-center"> <button class="navbar-toggler navbar-toggler-right border-0" type="button" data-toggle="collapse" data-target="#navbar_bottom">
        <span class="navbar-toggler-icon"></span>
      </button>
      <a href="/reload" id="countCH" style="font-size:20px;color:white;font-weight:bold;">Reload program</a>
    </div>
  </nav>



</body>

</html>
