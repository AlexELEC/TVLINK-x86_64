<!DOCTYPE html>
<html>

% include('head.tpl')

<body>
  % include('navbar-top.tpl')
  <p>&nbsp;</p>

  <table class="table" width="100%" border="2" >

    <tr>
      <th width="10%"  ><a href="#" onClick="sortTo('channel')">Channel</a></th>
      <th width="40%" ><a href="#" onClick="sortTo('auto')">Auto EPG mapping</a></th>
      <th width="40%" ><a href="#" onClick="sortTo('manual')">Manual EPG mapping</a></th>
    </tr>

    <!-- # dataChannels [ 0-chID, 1-chTitle, 2-epgNames_auto, 3-epgNames_hand ] -->
    % for row in dataChannels:
    % rowID = 'row_' + row[0]
    % lblID = 'epg_lbl_' + row[0]
    <tr id="{{rowID}}" >
      <!-- Channel Title -->
      <td>
        <label ><b>{{row[1]}}</b></label>
      </td>
      <!-- Auto EPG -->
      <td>
        <label >{{row[2]}}</label>
      </td>
      <!-- Manual EPG -->
      <td>
        <div style="display:flex;gap:8px;align-items:center;">
          <label id="{{lblID}}" style="margin:0;flex:1;">{{row[3]}}</label>
          <button type="button" class="btn btn-sm btn-primary" onclick="openEpgPicker('{{row[0]}}', '{{row[1]}}')">Change</button>
        </div>
      </td>
    </tr>
    % end
  </table>

  <div id="epgPickerModal" class="modal" tabindex="-1" role="dialog" style="display:none;background:rgba(0,0,0,0.5);">
    <div class="modal-dialog modal-lg" role="document" style="margin-top:10vh;">
      <div class="modal-content">
        <div class="modal-header">
          <h5 id="epgPickerTitle" class="modal-title">Manual EPG mapping</h5>
          <button type="button" class="close" aria-label="Close" onclick="closeEpgPicker()">
            <span aria-hidden="true">&times;</span>
          </button>
        </div>
        <div class="modal-body">
          <input type="hidden" id="epgPickerChannelID" value="">
          <select id="epgPickerSelect" class="form-control">
            {{!dataEpgTitles}}
          </select>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-primary" onclick="saveEpgPicker()">Save</button>
          <button type="button" class="btn btn-secondary" onclick="closeEpgPicker()">Close</button>
        </div>
      </div>
    </div>
  </div>

  <script>
    function sortTo(order) {
        server.sort_epg(order);
        location.reload(true);
    }
    function goPage(srcName) {
        page = document.getElementById('go_page').value;
        window.location.href = "/epginputs/" + srcName + "/" + page;
    }

    function openEpgPicker(chID, chTitle) {
        var label = document.getElementById('epg_lbl_' + chID);
        var currentValue = '';
        if (label) {
            currentValue = label.textContent.trim();
        }

        var title = document.getElementById('epgPickerTitle');
        title.innerHTML = 'Manual EPG mapping: <b></b>';
        title.querySelector('b').textContent = chTitle;

        document.getElementById('epgPickerChannelID').value = chID;
        document.getElementById('epgPickerSelect').value = currentValue;
        document.getElementById('epgPickerModal').style.display = 'block';
    }

    function closeEpgPicker() {
        document.getElementById('epgPickerTitle').textContent = 'Manual EPG mapping';
        document.getElementById('epgPickerModal').style.display = 'none';
    }

    function saveEpgPicker() {
        var chID = document.getElementById('epgPickerChannelID').value;
        var epgName = document.getElementById('epgPickerSelect').value;

        server.epg_manual_set_value(chID, '{{srcName}}', epgName);

        var label = document.getElementById('epg_lbl_' + chID);
        if (label) {
            label.textContent = epgName;
        }

        closeEpgPicker();
    }

    window.onclick = function(event) {
        var modal = document.getElementById('epgPickerModal');
        if (event.target == modal) {
            closeEpgPicker();
        }
    }
  </script>

  <p>&nbsp;</p>
  <p>&nbsp;</p>

  <nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-bottom">
    <div class="container justify-content-center"> <button class="navbar-toggler navbar-toggler-right border-0" type="button" data-toggle="collapse" data-target="#navbar_bottom">
        <span class="navbar-toggler-icon"></span>
      </button>
      <label style="font-size:20px;color:white;font-weight:bold;">source: {{srcName}}</label>
      <div class="collapse navbar-collapse text-center justify-content-center" id="navbar_bottom">
        <ul class="navbar-nav">
          <button class="btn" onclick="window.location.href='/epginputs/{{srcName}}'" ><i class="fa fa-fast-backward" style="font-size:20px;color:white" ></i></button>
          <button class="btn" onclick="window.location.href='/epginputs/{{srcName}}/{{page-1}}'" {{'disabled="disabled"' if page <= 1 else ""}} ><i class="fa fa-backward" style="font-size:20px;color:white" ></i></button>
          <label style="font-size:20px;color:white;font-weight:bold;">&nbsp;&nbsp;&nbsp;{{page}}&nbsp;&nbsp;&nbsp;</label>
          <button class="btn" onclick="window.location.href='/epginputs/{{srcName}}/{{page+1}}'" {{'disabled="disabled"' if page >= last_page else ""}} ><i class="fa fa-forward" style="font-size:20px;color:white" ></i></button>
          <button class="btn" onclick="window.location.href='/epginputs/{{srcName}}/{{last_page}}'" ><i class="fa fa-fast-forward" style="font-size:20px;color:white" ></i></button>
          % if last_page > 2:
            &nbsp;&nbsp;&nbsp;
            <select class="form-control" id="go_page" onChange="goPage('{{srcName}}')" >
                <option>go to</option>
                % for pg in range(1, last_page+1):
                <option>{{pg}}</option>
                % end
            </select>
          % end
        </ul>
      </div>
      <label id="countSrc" style="font-size:20px;color:white;font-weight:bold;">channels: {{CNL_TOTAL}}</label>
    </div>
  </nav>

</body>

</html>
