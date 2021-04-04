<!DOCTYPE html>

  <div class="modal" id="mdAddon" >
    <div class="modal-dialog modal-lg" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <b><h4 class="modal-title" ></h4>Add new addon</b>
        </div>
        <div class="modal-body">
          <p>Addon name:</p>
          <input id="addon_name" list="plugins" name="addons" class="form-control" style="width:30%" type="text" value="" onClick="this.select();">
          <datalist id="plugins">
            % for row in in_addons:
              <option value="{{row}}">
            % end
          </datalist>
        </div>
        <div class="modal-footer"> 
          <button type="button" class="btn btn-primary" onClick="server.create_new_addon()" >Save changes</button>
          <button type="button" class="btn btn-secondary" onClick="modalClose('mdAddon')" >Close</button>
        </div>
      </div>
    </div>
  </div>
  <script src="/styles/jquery-3.3.1.slim.min.js" ></script>
  <script src="/styles/popper.min.js" ></script>
  <script src="/styles/bootstrap.min.js" ></script>
