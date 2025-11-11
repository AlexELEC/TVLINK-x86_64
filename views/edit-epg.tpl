<!DOCTYPE html>

  <div class="modal" id="mdEditEPG" >
    <div class="modal-dialog modal-lg" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <b><h4 class="modal-title" id="epg_edit_header"></h4></b>
        </div>
        <div class="modal-body">
          <p><b>EPG url:</b></p>
          <input id="epg_edit_url" class="form-control" type="text" value="" onClick="this.select();">
          <p>&nbsp;</p>
          <p><b>Modify channel names:</b></p>
          <p>change from (regular expression)</p>
          <input id="epg_strFrom" class="form-control" type="text" value="" onClick="this.select();"><p></p>
          <p>to</p>
          <input id="epg_strTo" class="form-control" type="text" value="" onClick="this.select();">
        </div>
        <div class="modal-footer"> 
          <button type="button" class="btn btn-primary" onClick="server.edit_epg()" >Save changes</button>
          <button type="button" class="btn btn-secondary" onClick="modalClose('mdEditEPG')" >Close</button>
        </div>
      </div>
    </div>
  </div>
  <script src="/styles/jquery-3.3.1.slim.min.js" ></script>
  <script src="/styles/popper.min.js" ></script>
  <script src="/styles/bootstrap.min.js" ></script>
