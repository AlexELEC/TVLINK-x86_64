<!DOCTYPE html>

  <div class="modal" id="mdEditEPG" >
    <div class="modal-dialog modal-lg" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <b><h4 class="modal-title" id="epg_edit_header"></h4></b>
        </div>
        <div class="modal-body">
          <p>EPG url:</p>
          <input id="epg_edit_url" class="form-control" type="text" value="" onClick="this.select();">
        </div>
        <div class="modal-footer"> 
          <button type="button" class="btn btn-primary" onClick="server.save_epg_url()" >Save changes</button>
          <button type="button" class="btn btn-secondary" onClick="modalClose('mdEditEPG')" >Close</button>
        </div>
      </div>
    </div>
  </div>
  <script src="/styles/jquery-3.3.1.slim.min.js" ></script>
  <script src="/styles/popper.min.js" ></script>
  <script src="/styles/bootstrap.min.js" ></script>
