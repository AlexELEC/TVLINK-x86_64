<!DOCTYPE html>

  <p>&nbsp;</p>

  <div style="width:50%;margin: 0 auto;text-align:center;">

  <table class="table" border="2" >

    % sysval = {"TVLINK uptime": start_time, "TVLINK uses memory": mem_tvlink, "TVLINK open sockets": use_sockets, "Free system memory": use_ram}
    % for sys_name in sysval.keys():
    % sys_value = sysval.get(sys_name)
    <tr>
      <!-- Option -->
      <td>
        <label><b>{{sys_name}}</b></label>
      </td>
      <!-- Value -->
      <td>
        <label><b>{{sys_value}}</b></label>
      </td>
    </tr>
    % end
  </table>

  </div>
