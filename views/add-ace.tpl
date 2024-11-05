<!DOCTYPE html>

  <div class="modal" id="mdAce" >
    <div class="modal-dialog modal-lg" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <b><h4 class="modal-title" ></h4>Add new AceStream source</b>
        </div>
        <div class="modal-body">
          <p>Source name:</p>
          <input id="ace_name" class="form-control" style="width:30%" type="text" value="" onClick="this.select();">
          <p>&nbsp;</p>
          <p>AceStream engine address:</p>
          <input id="ace_ip" class="form-control" type="text" value="http://192.168.1.1:6878" onClick="this.select();">
          <p>&nbsp;</p>
          <p>Use HLS streams:</p>
          <label class="switch">
            <input id="ace_hls" type="checkbox" onClick="this.select();">
            <span class="slider round"></span>
          </label>
        </div>
        <div class="modal-footer"> 
          <button type="button" class="btn btn-primary" onClick="server.create_new_ace()" >Save changes</button>
          <button type="button" class="btn btn-secondary" onClick="modalClose('mdAce')" >Close</button>
        </div>
      </div>
    </div>
  </div>
  <script src="/styles/jquery-3.3.1.slim.min.js" ></script>
  <script src="/styles/popper.min.js" ></script>
  <script src="/styles/bootstrap.min.js" ></script>
