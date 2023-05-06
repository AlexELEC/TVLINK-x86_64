<!DOCTYPE html>

  <div class="modal" id="mdGrpAlias" >
    <div class="modal-dialog modal-lg" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <b><h4 class="modal-title" id="grp_alias_header"></h4></b>
        </div>
        <div class="modal-body">
          <p>Group aliases (comma delimiter):</p>
          <input id="grp_edit_alias" class="form-control" type="text" value="" onClick="this.select();">
        </div>
        <div class="modal-footer"> 
          <button type="button" class="btn btn-primary" onClick="server.save_grp_alias()" >Save changes</button>
          <button type="button" class="btn btn-secondary" onClick="modalClose('mdGrpAlias')" >Close</button>
        </div>
      </div>
    </div>
  </div>
  <script src="/styles/jquery-3.3.1.slim.min.js" ></script>
  <script src="/styles/popper.min.js" ></script>
  <script src="/styles/bootstrap.min.js" ></script>
