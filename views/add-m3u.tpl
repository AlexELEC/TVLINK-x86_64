<!DOCTYPE html>

  <div class="modal" id="mdM3U" >
    <div class="modal-dialog modal-lg" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <b><h4 class="modal-title" ></h4>Add new playlist</b>
        </div>
        <div class="modal-body">
          <p>Playlist name (for catchup/archive add ending: "_append", "_shift" or "_flussonic"):</p>
          <input id="m3u_name" class="form-control" style="width:30%" type="text" value="" onClick="this.select();">
          <p>&nbsp;</p>
          <p>Playlist path:</p>
          <input id="m3u_path" class="form-control" type="text" value="" onClick="this.select();">
        </div>
        <div class="modal-footer"> 
          <button type="button" class="btn btn-primary" onClick="server.save_new_playlist()" >Save changes</button>
          <button type="button" class="btn btn-secondary" onClick="modalClose('mdM3U')" >Close</button>
        </div>
      </div>
    </div>
  </div>
  <script src="/styles/jquery-3.3.1.slim.min.js" ></script>
  <script src="/styles/popper.min.js" ></script>
  <script src="/styles/bootstrap.min.js" ></script>
