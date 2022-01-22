<!DOCTYPE html>

  <p>&nbsp;</p>
  <h4><b>Active streams:</b></h4>
  <p>&nbsp;</p>

  <table class="table" width="100%" border="2" >

    <tr>
      <th width="5%"  >Client</th>
      <th width="5%"  >Channel</th>
      <th width="2%"  >ID</th>
      <th width="5%"  >Start Time</th>
      <th width="12%" >URL</th>

    </tr>

    <!-- STATUS_STREAMS {user_ip: [chID, chTitle, lnk, startTime]} -->
    % for client in STATUS_STREAMS.keys():
    % client_val = STATUS_STREAMS.get(client)
    % chID = client_val[0]
    % chTitle = client_val[1]
    % cnLink = client_val[2]
    % cnStart = client_val[3]
    <tr>
      <!-- Client -->
      <td>
        <label>{{client}}  </label><button class="btn" onClick='server.next_channel("{{chID}}", "{{client}}")' ><i class="fa fa-exchange" style="font-size:20px;color:red" ></i></button>
      </td>
      <!-- Channel -->
      <td>
        <label>{{chTitle}}</label>
      </td>
      <!-- ID -->
      <td>
        <label>{{chID}}</label>
      </td>
      <!-- Start Time -->
      <td>
        <label>{{cnStart}}</label>
      </td>
      <!-- URL -->
      <td>
        <label>{{cnLink}}</label>
      </td>
    </tr>
    % end
  </table>

