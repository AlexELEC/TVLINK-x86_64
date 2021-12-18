<!DOCTYPE html>

  <div class="modal" id="mdTOKEN" >
    <div class="modal-dialog modal-lg" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <b><h4 class="modal-title" ></h4>Create Token (playlist/streams)</b>
        </div>
        <div class="modal-body">
          <p>Token:</p>
          <input id="token_key" class="form-control" type="text" value="" onClick="this.select();">
          <p>&nbsp;</p>
          <p>Comment:</p>
          <input id="token_text" class="form-control" type="text" value="" onClick="this.select();">
        </div>
        <div class="modal-footer"> 
          <button type="button" class="btn btn-primary" onClick="server.save_token()" >Save changes</button>
          <button type="button" class="btn btn-secondary" onClick="modalClose('mdTOKEN')" >Close</button>
        </div>
      </div>
    </div>
  </div>
  <script src="/styles/jquery-3.3.1.slim.min.js" ></script>
  <script src="/styles/popper.min.js" ></script>
  <script src="/styles/bootstrap.min.js" ></script>
