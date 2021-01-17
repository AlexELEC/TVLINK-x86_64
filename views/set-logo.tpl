<!DOCTYPE html>

  <div class="modal" id="mdLogo" >
    <div class="modal-dialog" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <b><h4 class="modal-title" id="logo_chName"></h4></b>
        </div>
        <div class="modal-body">
          <p>Enter logo url for the channel:</p>
          <input id="logo_chURL" class="form-control" type="text" value="" onClick="this.select();">
        </div>
        <div class="modal-footer"> 
          <button type="button" class="btn btn-warning" onClick="server.choice_local_logo()" >Local logos</button>
          <button type="button" class="btn btn-primary" onClick="server.save_logo_url()" >Save changes</button>
          <button type="button" class="btn btn-secondary" onClick="modalClose('mdLogo')" >Close</button>
        </div>
      </div>
    </div>
  </div>
  <script src="/styles/jquery-3.3.1.slim.min.js" ></script>
  <script src="/styles/popper.min.js" ></script>
  <script src="/styles/bootstrap.min.js" ></script>
