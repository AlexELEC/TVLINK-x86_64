<!DOCTYPE html>

  <p>&nbsp;</p>
  <h4><b>Active streams:</b></h4>
  <p>&nbsp;</p>

  <script>
    function nextStream(chTitle, chID, client) {
        if (confirm(chTitle + ": switch to next stream?")) {
            server.next_channel(chID, client);
            location.reload(true);
        }
    }
  </script>

  <table class="table" width="100%" border="2" >

    <tr>
      <th width="3%"  >Client</th>
      <th width="4%"  >Channel</th>
      <th width="3%"  >Source</th>
      <th width="5%"  >Start Time</th>
      <th width="12%" >URL</th>

    </tr>

    <!-- STATUS_STREAMS {user_ip: [chID, srcName, chTitle, lnk, startTime, orgURL]} -->
    % for client in STATUS_STREAMS.keys():
    % chID, chSource, chTitle, chLink, chStart, chOrgUrl = STATUS_STREAMS.get(client)
    % chSource = chSource.replace("m3u_", "")
    % if "?" in chOrgUrl:
    % chOrgUrl = chOrgUrl.split('?')[0]
    % end
    <tr>
      <!-- Client -->
      <td>
        <label>{{client}}  </label><button title="Next stream" class="btn" onClick='nextStream("{{chTitle}}", "{{chID}}", "{{client}}")' ><i class="fa fa-forward fa-border" style="font-size:16px;color:red" ></i></button>
      </td>
      <!-- Channel -->
      <td>
        <label>{{chTitle}} [{{chID}}]</label>
      </td>
      <!-- Source -->
      <td>
        <label>{{chSource}}</label>
      </td>
      <!-- Start Time -->
      <td>
        <label>{{chStart}}</label>
      </td>
      <!-- URL -->
      <td>
        <label>{{chOrgUrl}}</label>
      </td>
    </tr>
    % end
  </table>
