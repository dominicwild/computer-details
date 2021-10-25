const { app, BrowserWindow, Menu, Tray } = require("electron");
const path = require("path");
const fs = require("fs");
const LRU = require("lru-cache");
const cache = new LRU({
  max: 100,
  stale: false,
  maxAge: 1000 * 60 * 5, // 5 minutes
});
require(path.join(__dirname, "/env/env"));

// Handle creating/removing shortcuts on Windows when installing/uninstalling.
const isInstalling = require("electron-squirrel-startup");
if (isInstalling) {
  // eslint-disable-line global-require
  const sourceDir = path.join(__dirname, "/build dependency/swiftshader");
  const destinationDir = path.join(__dirname, "../../../swiftshader");
  fs.renameSync(sourceDir, destinationDir);
  app.quit();
}

const iconFile = path.join(__dirname, "/images/system-information-64.ico");
let mainWindow = null;
let tray = null;

const createWindow = () => {
  // Create the browser window.
  mainWindow = new BrowserWindow({
    //height: 1000,
    width: 1000,
    webPreferences: {
      preload: path.join(__dirname, "/pages/index/preload.js"),
      nodeIntegration: true,
      enableRemoteModule: true,
    },
  });
  mainWindow.setIcon(path.join(__dirname, "/images/system-information-64.ico"));
  const menu = Menu.buildFromTemplate([
    {
      label: "App",
      submenu: [
        {
          label: "Reset Cache",
          click: () => {
            cache.reset();
          },
        }, {
          role: "quit"
        }
      ],
    },
  ]);
  mainWindow.setMenu(menu);
  // mainWindow.setMenuBarVisibility(false);

  // and load the index.html of the app.
  mainWindow.loadFile(path.join(__dirname, "/pages/index/index.html"));

  // Open the DevTools.
  if(process.env.NODE_ENV === "dev"){
    mainWindow.webContents.openDevTools();
  }
};

function createTray() {
  tray = new Tray(iconFile);
  tray.setTitle("Computer Details");
  tray.setToolTip("Computer Details");

  const template = [
    {
      label: "Open",
      click: () => {
        mainWindow.show();
      },
    },
    {
      role: "quit",
    },
    {
      label: "Reset Cache",
      click: () => {
        cache.reset();
      },
    },
  ];

  const menu = Menu.buildFromTemplate(template);
  tray.setContextMenu(menu);

  tray.on("double-click", (e) => {
    mainWindow.show();
  });
}

// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
// Some APIs can only be used after this event occurs.
app.on("ready", () => {
  if (!isInstalling) {
    createWindow();
    createTray();
  }
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

module.exports.showBalloonTip = (balloonConfiguration) => {
  console.log(balloonConfiguration);
  tray.displayBalloon(balloonConfiguration);
};

module.exports.getCache = () => {
  return cache;
};
