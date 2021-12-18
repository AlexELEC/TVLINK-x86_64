<!DOCTYPE html>

  <div class="modal" id="mdInfo" >
    <div class="modal-dialog modal-xl modal-dialog-scrollable" role="document">
      <div class="modal-content">
        <div class="modal-header text-center justify-content-center">
          <table width="100%" border="0" >
            <tr>
              <td bgcolor="2C3E50" width="15%"><img class="modal-title" id="inf_logo" src="" style="width:50%" ></td>
              <td><b><h4 id="inf_header"></h4></b></td>
            </tr>
          </table>
        </div>
        <div class="modal-body">
          <p id="inf_body"></p>
        </div>
        <div class="modal-footer"> 
          <button type="button" class="btn btn-secondary" onClick="modalClose('mdInfo')" >Close</button>
        </div>
      </div>
    </div>
  </div>
  <script src="/styles/jquery-3.3.1.slim.min.js" ></script>
  <script src="/styles/popper.min.js" ></script>
  <script src="/styles/bootstrap.min.js" ></script>
