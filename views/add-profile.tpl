<!DOCTYPE html>

  <div class="modal" id="mdUSER" >
    <div class="modal-dialog modal-lg" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <b><h4 class="modal-title" id="profile_title">Add user profile</h4></b>
        </div>
        <div class="modal-body">
          <p>User:</p>
          <input id="usr_name" class="form-control" style="width:30%" type="text" value="" onClick="this.select();">
          <p>&nbsp;</p>
          <p>Playlist IP (optional):</p>
            <select id="usr_ip" class="form-control" style="width:30%" onClick="this.select();" >
              % for ip in ip_list:
                <option {{'selected' if ip == IP else ""}} >{{ip}}</option>
              % end
            </select>
          <p>&nbsp;</p>
          <p>Token for playlist/streams (optional):</p>
          <input id="usr_token" class="form-control" type="text" value="" onClick="this.select();">
          <p>&nbsp;</p>
          <p>Comment (optional):</p>
          <input id="usr_text" class="form-control" type="text" value="" onClick="this.select();">
        </div>
        <div class="modal-footer"> 
          <button type="button" class="btn btn-primary" onClick="server.save_profile()" >Save changes</button>
          <button type="button" class="btn btn-secondary" onClick="modalClose('mdUSER')" >Close</button>
        </div>
      </div>
    </div>
  </div>
  <script src="/styles/jquery-3.3.1.slim.min.js" ></script>
  <script src="/styles/popper.min.js" ></script>
  <script src="/styles/bootstrap.min.js" ></script>
