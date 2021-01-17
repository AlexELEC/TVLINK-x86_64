<!DOCTYPE html>

  <div class="modal" id="mdJoin" >
    <div class="modal-dialog" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <b><h4 class="modal-title" id="jn_header"></h4></b>
        </div>
        <div class="modal-body">
          <p>attach the following channels:</p>
          <p id="jn_body"></p>
        </div>
        <div class="modal-footer"> 
          <button type="button" class="btn btn-primary" onClick="server.channels_join()" >Save changes</button>
          <button type="button" class="btn btn-secondary" onClick="modalClose('mdJoin')" >Close</button>
        </div>
      </div>
    </div>
  </div>
  <script src="/styles/jquery-3.3.1.slim.min.js" ></script>
  <script src="/styles/popper.min.js" ></script>
  <script src="/styles/bootstrap.min.js" ></script>
