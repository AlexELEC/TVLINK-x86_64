<!DOCTYPE html>

  <div class="modal" id="mdPortal" >
    <div class="modal-dialog modal-lg" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <b><h4 class="modal-title" ></h4>Add new Portal (Stаlker Middleware)</b>
        </div>
        <div class="modal-body">
          <p>Portal name:</p>
          <input id="port_name" class="form-control" style="width:30%" type="text" value="" onClick="this.select();">
          <p>&nbsp;</p>
          <p>Portal url:</p>
          <input id="port_path" class="form-control" type="text" value="" onClick="this.select();">
          <p>&nbsp;</p>
          <p>User MAC:</p>
          <input id="port_mac" class="form-control" style="width:30%" type="text" value="" onClick="this.select();">
          <p>&nbsp;</p>
          <p>Use HLS streams:</p>
          <label class="switch">
            <input id="port_hls" type="checkbox" onClick="this.select();">
            <span class="slider round"></span>
          </label>
        </div>
        <div class="modal-footer"> 
          <button type="button" class="btn btn-primary" onClick="server.create_new_portal()" >Save changes</button>
          <button type="button" class="btn btn-secondary" onClick="modalClose('mdPortal')" >Close</button>
        </div>
      </div>
    </div>
  </div>
  <script src="/styles/jquery-3.3.1.slim.min.js" ></script>
  <script src="/styles/popper.min.js" ></script>
  <script src="/styles/bootstrap.min.js" ></script>
