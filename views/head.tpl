<!DOCTYPE html>

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="/styles/font-awesome/css/font-awesome.min.css" type="text/css">
  <link rel="stylesheet" href="/styles/bootstrap-4.3.1.css">
  <link rel="stylesheet" href="/styles/styles.css?v=responsive-3" type="text/css">
  <link rel="shortcut icon" href="/styles/favicon.ico">
  <script>
    document.addEventListener("DOMContentLoaded", function () {
      document.querySelectorAll("table.table").forEach(function (table) {
        var headerRow = table.querySelector("tr");
        if (!headerRow) {
          return;
        }

        var headers = Array.from(headerRow.querySelectorAll("th")).map(function (header) {
          return header.textContent.trim();
        });

        if (!headers.length) {
          return;
        }

        var isWideTable = headers.length >= 5;
        table.classList.toggle("table-wide", isWideTable);

        if (isWideTable && !table.parentElement.classList.contains("table-responsive-shell")) {
          var wrapper = document.createElement("div");
          wrapper.className = "table-responsive-shell";

          if (table.style.display === "none") {
            wrapper.style.display = "none";
          }

          table.parentNode.insertBefore(wrapper, table);
          wrapper.appendChild(table);
        }

        if (table.parentElement) {
          table.parentElement.classList.toggle("table-responsive-wide", isWideTable);
        }

        table.querySelectorAll("tr").forEach(function (row) {
          Array.from(row.children).forEach(function (cell, index) {
            if (cell.tagName.toLowerCase() === "td" && headers[index]) {
              cell.setAttribute("data-label", headers[index]);
            }
          });
        });
      });
    });
  </script>
</head>
