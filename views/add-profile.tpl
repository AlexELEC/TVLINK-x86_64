<!DOCTYPE html>

  <div class="modal" id="mdUSER" >
    <div class="modal-dialog modal-lg" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <b><h4 class="modal-title" ></h4>Add user profile</b>
        </div>
        <div class="modal-body">
          <p>User:</p>
          <input id="usr_name" class="form-control" style="width:30%" type="text" value="" onClick="this.select();">
          <p>&nbsp;</p>
          <p>Comment:</p>
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
