(function () {
  var storageKey = "tvlink-theme";

  window.setTvlinkTheme = function (theme) {
    var isDark = theme === "dark";
    document.documentElement.setAttribute("data-theme", isDark ? "dark" : "light");

    try {
      window.localStorage.setItem(storageKey, isDark ? "dark" : "light");
    } catch (error) {
      // The theme still works when browser storage is unavailable.
    }

    var switcher = document.getElementById("theme-switch");
    if (switcher) {
      switcher.checked = isDark;
      switcher.setAttribute("aria-checked", String(isDark));
    }
  };

  try {
    if (window.localStorage.getItem(storageKey) === "dark") {
      document.documentElement.setAttribute("data-theme", "dark");
    }
  } catch (error) {
    // Use the default light theme when browser storage is unavailable.
  }

  document.addEventListener("DOMContentLoaded", function () {
    var switcher = document.getElementById("theme-switch");
    if (switcher) {
      var isDark = document.documentElement.getAttribute("data-theme") === "dark";
      switcher.checked = isDark;
      switcher.setAttribute("aria-checked", String(isDark));
    }
  });
}());
