// All of the Node.js APIs are available in the preload process.
// It has the same sandbox as a Chrome extension.

const path = require("path");
const { Notification, Tray } = require("electron").remote;
const mainProcess = require("electron").remote.require(path.join(__dirname, "/../../main.js"));
const LRU = require("lru-cache");
const cache = mainProcess.getCache();

function disableAllDataButtons(disabled) {
  const buttons = document.querySelectorAll(".buttons button");
  const functionButtons = document.querySelectorAll(".info-container button");

  for (const button of buttons) {
    button.disabled = disabled;
  }

  for (const button of functionButtons) {
    button.disabled = disabled;
  }
}
function isEmpty(obj) {
  for (var key in obj) {
    if (obj.hasOwnProperty(key)) return false;
  }
  return true;
}

var powershell = require("node-powershell");
var ps = new powershell({
  executionPolicy: "Bypass",
  noProfile: true,
});

const functionsFile = path.join(__dirname, "/../../scripts/Functions.ps1");
const packageJsonFile = path.join(__dirname, "/../../../package.json");
const version = require(packageJsonFile).version;

ps.addCommand(`. '${functionsFile}'`);
ps.invoke()
  .then((output) => {
    console.log("PowerShell loaded.");
    disableAllDataButtons(false);
    document.getElementById("osBtn").click();
  })
  .catch((err) => {
    console.error(err);
  });

function createTable(contents, name) {
  const allTables = document.getElementById("allTables");
  const table = document.getElementById("template-new-table").content.cloneNode(true);
  const body = table.querySelector("tbody");
  const header = table.querySelector("thead");

  table.querySelector(".table-title h1").innerText = name;

  insertToTable(contents, body, header);
  allTables.appendChild(table);
}

function clearTable() {
  const tableBody = document.getElementById("data-body");
  const tableHeader = document.getElementById("data-header");
  tableBody.innerHTML = "";
  tableHeader.innerHTML = "";
}

function hideMainTable(toHide) {
  const mainTable = document.getElementById("mainTable");
  if (toHide) {
    mainTable.classList.add("hidden");
  } else {
    mainTable.classList.remove("hidden");
  }
}

function clearAllTables() {
  document.getElementById("allTables").innerHTML = "";
}

function setAllTableNotice(noticeText) {
  const allTables = document.getElementById("allTables");
  const allTablesNotice = document.createElement("h5");
  allTablesNotice.innerText = noticeText;
  allTables.appendChild(allTablesNotice);
}

function insertToTable(contents, applyToTableBody, applyToTableHeader) {
  let tableBody = document.getElementById("data-body");
  let tableHeader = document.getElementById("data-header");

  if (applyToTableBody) {
    tableBody = applyToTableBody;
  }

  if (applyToTableHeader) {
    tableHeader = applyToTableHeader;
  }

  tableBody.innerHTML = "";
  tableHeader.innerHTML = "";

  if (isEmpty(contents)) {
    return;
  }

  if (Array.isArray(contents)) {
    const sampleRow = contents[0];
    const headerRow = document.createElement("tr");

    for (let key in sampleRow) {
      const tableData = document.createElement("td");
      tableData.innerText = key;
      tableData.classList.add("key");
      headerRow.appendChild(tableData);
    }
    tableHeader.appendChild(headerRow);

    for (let row of contents) {
      const tableRow = document.createElement("tr");
      for (let key in row) {
        const tableData = document.createElement("td");
        const value = row[key] === null || row[key] === "" ? "None/Unknown" : row[key];
        tableData.innerText = value;
        tableRow.appendChild(tableData);
      }
      tableBody.appendChild(tableRow);
    }
  } else {
    for (let key in contents) {
      const template = document.getElementById("template-key-value-row").content.cloneNode(true);
      const keyElement = template.querySelector(".key");
      const valueElement = template.querySelector(".value");

      const value = contents[key] === null || contents[key] === "" ? "None/Unknown" : contents[key];
      keyElement.innerText = key;
      valueElement.innerText = value;

      tableBody.appendChild(template);
    }
  }
}

function setTableHeader(header, headerNull = "No data found.") {
  if (tableHasContent()) {
    document.getElementById("table-title").innerText = header;
  } else {
    document.getElementById("table-title").innerText = headerNull;
  }
}

async function loadContents(powershellFunction) {
  hideMainTable(false);

  const process = (output) => {
    const contents = JSON.parse(output);
    insertToTable(contents);
  };

  const cachedContents = cache.get(powershellFunction);
  if (cachedContents) {
    process(cachedContents);
    return;
  }

  ps.addCommand(powershellFunction);
  loading(true);

  await ps
    .invoke()
    .then((output) => {
      clearAllTables();
      console.log(output);
      process(output);
      cache.set(powershellFunction, output);
    })
    .catch((err) => {
      console.error(err);
    })
    .finally(() => {
      loading(false);
    });
}

async function executePowerShell(powershellFunction) {
  ps.addCommand(powershellFunction);
  loading(true);

  return await ps
    .invoke()
    .then((output) => {
      console.log(output);
      const contents = JSON.parse(output);
      return contents;
    })
    .catch((err) => {
      console.error(err);
    })
    .finally(() => {
      loading(false);
    });
}

function tableHasContent() {
  return document.getElementById("data-body").childNodes.length !== 0;
}

function loading(isLoading) {
  try {
    const loader = document.getElementById("loader");
    if (isLoading) {
      loader.classList.remove("hidden");
      disableAllDataButtons(true);
    } else {
      loader.classList.add("hidden");
      disableAllDataButtons(false);
    }
  } catch {}
}

function setNotice(message) {
  document.getElementById("noticeText").innerText = message;
}

function showNotice(toShow) {
  const notice = document.getElementById("notice");
  if (toShow) {
    notice.classList.remove("hidden");
  } else {
    notice.classList.add("hidden");
  }
}

function resetNotice() {
  showNotice(false);
  setNotice("");
}

window.addEventListener("DOMContentLoaded", () => {
  var $ = require("jquery");
  var toastr = require("toastr");
  toastr.options = {
    closeButton: true,
    debug: false,
    newestOnTop: false,
    progressBar: true,
    positionClass: "toast-bottom-center",
    preventDuplicates: false,
    onclick: null,
    showDuration: "300",
    hideDuration: "1000",
    timeOut: "5000",
    extendedTimeOut: "1000",
    showEasing: "swing",
    hideEasing: "linear",
    showMethod: "fadeIn",
    hideMethod: "fadeOut",
  };

  const osBtn = document.getElementById("osBtn");
  const hardwareBtn = document.getElementById("hardwareBtn");
  const userBtn = document.getElementById("userBtn");
  const driveSpaceBtn = document.getElementById("driveSpaceBtn");
  const ipBtn = document.getElementById("ipBtn");
  const nicBtn = document.getElementById("nicBtn");
  const allBtn = document.getElementById("allBtn");
  const buttons = document.getElementById("buttons");

  disableAllDataButtons(true);
  document.querySelector(".footer .version").innerText = "v" + version;
  document.getElementById("computer").innerText = "Computer Name: " + process.env.COMPUTERNAME;

  buttons.addEventListener("click", (e) => {
    resetNotice();
  });

  osBtn.addEventListener("click", async (e) => {
    await loadContents("Get-OperatingSystem");
    setTableHeader("Operating System");
  });

  hardwareBtn.addEventListener("click", async (e) => {
    await loadContents("Get-HardwareInfo");
    setTableHeader("Hardware Info");
  });

  userBtn.addEventListener("click", async (e) => {
    await loadContents("Get-ADSystemInfo");
    setTableHeader("User Info");
  });

  driveSpaceBtn.addEventListener("click", async (e) => {
    await loadContents("Get-DiskSpace");
    setTableHeader("Disk Space");
  });

  ipBtn.addEventListener("click", async (e) => {
    await loadContents("Get-IPInfo");
    setTableHeader("IP Information");
  });

  nicBtn.addEventListener("click", async (e) => {
    await loadContents("Get-NICInfo");
    setTableHeader("NIC Information");
  });

  allBtn.addEventListener("click", async (e) => {
    loading(true);

    setTableHeader("Loading...", "Loading...");
    const contents = await executePowerShell("Get-AllData");
    clearTable();
    clearAllTables();
    setAllTableNotice("🛈 A file has been created on your desktop with the information below.");
    mainProcess.showBalloonTip({
      iconType: "info",
      content: "A file has been created on your desktop containing all the information.",
      title: "All Computer Details",
    });
    for (key in contents) {
      createTable(contents[key], key);
    }

    loading(false);
    hideMainTable(true);
  });

  const recycleBinBtn = document.getElementById("recycleBinBtn");

  recycleBinBtn.addEventListener("click", async (e) => {
    const notice = await executePowerShell("Start-EmptyRecycleBin");
    setNotice(notice.message);
    showNotice(true);
    // toastr[notice.state](notice.message);
    // new Notification({title: "A Title", body: "A message body."}).show();
    if (notice.state === "success") {
      mainProcess.showBalloonTip({ iconType: "info", content: notice.message, title: "Empty Recycle Bin" });
    } else {
      mainProcess.showBalloonTip({ iconType: "warning", content: notice.message, title: "Empty Recycle Bin" });
    }
  });
});
