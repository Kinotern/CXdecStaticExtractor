window.onerror = function (msg, url, line, col, error) {
  if (window.__TAURI__) {
    window.__TAURI__.invoke("handle_post_message", {
      message: { type: 'log', text: 'JS ERROR: ' + msg + ' at line ' + line }
    });
  }
};

const state = {
  schemes: [],
  selectedSchemeId: "",
  queue: [],
  outRoot: "",
  queueRunning: false,
  queueCurrentJobId: null,
  pendingXp3Paths: [],
};

const $ = (sel) => document.querySelector(sel);
const log = $("#log");

function appendLog(text) {
  if (log) {
    log.textContent += "\n" + text;
    log.scrollTop = log.scrollHeight;
  }
}

function post(message) {
  if (window.__TAURI__) {
    window.__TAURI__.invoke("handle_post_message", { message });
  }
}

// ----- Scheme Utilities -----
function schemeLabel(scheme) {
  if (!scheme) return "未选择方案";
  return (scheme.game || scheme.name || "未知游戏") + " [" + (scheme.version || "Unknown") + "]";
}

function isSchemeReady(scheme) {
  return Boolean(scheme && scheme.hasDrip && scheme.hasHxv4Key);
}

function selectedScheme() {
  return state.schemes.find((s) => s.id === state.selectedSchemeId) || null;
}

// ----- Navigation -----
document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".page").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    const pageId = btn.dataset.page;
    if ($("#" + pageId)) $("#" + pageId).classList.add("active");
    
    const titles = {
      scheme: ["方案库", "管理解包方案配置"],
      queue: ["解包队列", "批量执行解包任务"],
    };
    if (titles[pageId] && $("#pageTitle")) {
      $("#pageTitle").textContent = titles[pageId][0];
      $("#pageSubtitle").textContent = titles[pageId][1];
    }
  });
});

// ----- Scheme Rendering -----
function renderSchemes() {
  const list = $("#schemeList");
  if (!list) return;
  list.innerHTML = "";

  const groups = {};
  state.schemes.forEach((scheme) => {
    const comp = scheme.company || "未分类(Others)";
    const game = scheme.game || scheme.name || "Unknown Game";
    if (!groups[comp]) groups[comp] = {};
    if (!groups[comp][game]) groups[comp][game] = [];
    groups[comp][game].push(scheme);
  });

  Object.keys(groups).sort().forEach((comp) => {
    const compDiv = document.createElement("div");
    compDiv.className = "company-group";

    const compHeader = document.createElement("div");
    compHeader.className = "company-header";
    compHeader.style.display = "flex";
    compHeader.style.justifyContent = "space-between";
    compHeader.style.alignItems = "center";
    
    const compTitleSpan = document.createElement("span");
    compTitleSpan.innerHTML = "🏢 " + comp;
    compHeader.appendChild(compTitleSpan);
    
    const compActions = document.createElement("div");
    compActions.style.display = "flex";
    compActions.style.alignItems = "center";
    compActions.style.gap = "8px";
    
    const compAddBtn = document.createElement("button");
    compAddBtn.className = "ghost";
    compAddBtn.style.padding = "2px 6px";
    compAddBtn.style.fontSize = "12px";
    compAddBtn.style.height = "auto";
    compAddBtn.style.color = "#10b981"; // Green text for new game
    compAddBtn.style.fontWeight = "bold";
    compAddBtn.textContent = "+ 子游戏";
    compAddBtn.onclick = (e) => {
      e.stopPropagation();
      openCreateGameModal(comp);
    };
    compActions.appendChild(compAddBtn);
    
    const compToggle = document.createElement("small");
    compToggle.textContent = "🔽";
    compToggle.style.cursor = "pointer";
    compActions.appendChild(compToggle);
    
    compHeader.appendChild(compActions);
    compDiv.appendChild(compHeader);

    const gamesDiv = document.createElement("div");
    gamesDiv.className = "company-games";

    let compExpanded = true;
    compHeader.addEventListener("click", () => {
      compExpanded = !compExpanded;
      gamesDiv.style.display = compExpanded ? "block" : "none";
      compHeader.querySelector("small").textContent = compExpanded ? "🔽" : "◀";
    });

    Object.keys(groups[comp]).sort().forEach((game) => {
      const gameDiv = document.createElement("div");
      gameDiv.className = "game-group";

      const gameHeader = document.createElement("div");
      gameHeader.className = "game-header";
      gameHeader.style.display = "flex";
      gameHeader.style.justifyContent = "space-between";
      gameHeader.style.alignItems = "center";
      
      const titleSpan = document.createElement("span");
      titleSpan.textContent = "🎮 " + game;
      gameHeader.appendChild(titleSpan);
      
      const addBtn = document.createElement("button");
      addBtn.className = "ghost";
      addBtn.style.padding = "2px 6px";
      addBtn.style.fontSize = "12px";
      addBtn.style.height = "auto";
      addBtn.style.color = "#3b82f6"; // Blue text
      addBtn.style.fontWeight = "bold";
      addBtn.textContent = "+ 子版本";
      addBtn.onclick = (e) => {
        e.stopPropagation();
        openSubVersionModal(groups[comp][game][0].id, game);
      };
      gameHeader.appendChild(addBtn);

      const versionsDiv = document.createElement("div");
      versionsDiv.className = "game-versions";

      let gameExpanded = true;
      gameHeader.addEventListener("click", () => {
        gameExpanded = !gameExpanded;
        versionsDiv.style.display = gameExpanded ? "block" : "none";
      });

      groups[comp][game].forEach((scheme) => {
        const btn = document.createElement("button");
        btn.className = "scheme-item" + (scheme.id === state.selectedSchemeId ? " active" : "");
        const ready = isSchemeReady(scheme);
        const steamTag = scheme.isSteam ? " <span style='font-size:10px; background:#1b2838; color:#c7d5e0; padding:1px 4px; border-radius:3px; margin-left:4px;'>Steam</span>" : "";
        btn.innerHTML =
          "<strong>" +
          (scheme.version || "默认版本") +
          steamTag +
          "</strong><span style='" +
          (ready ? "color:#10b981;font-weight:bold" : "") +
          "'>" +
          (ready ? "可行" : "草稿") +
          "</span>";
        btn.addEventListener("click", () => selectScheme(scheme.id));
        versionsDiv.appendChild(btn);
      });

      gameDiv.appendChild(gameHeader);
      gameDiv.appendChild(versionsDiv);
      gamesDiv.appendChild(gameDiv);
    });

    compDiv.appendChild(gamesDiv);
    list.appendChild(compDiv);
  });

  if ($("#schemeCount")) $("#schemeCount").textContent = state.schemes.length + " 个方案";
}

function selectScheme(id) {
  state.selectedSchemeId = id;
  const scheme = selectedScheme();
  renderSchemes();

  if (!scheme) {
    if ($("#detailIdText")) $("#detailIdText").textContent = "未选择";
    if ($("#detailFolderName")) $("#detailFolderName").textContent = "未选择";
    if ($("#detailReadyState")) $("#detailReadyState").textContent = "未选择";
    if ($("#editCompanyName")) $("#editCompanyName").value = "";
    if ($("#editGameName")) $("#editGameName").value = "";
    if ($("#editVersionName")) $("#editVersionName").value = "";
    if ($("#schemeText")) $("#schemeText").value = "";
    return;
  }
  if ($("#detailIdText")) $("#detailIdText").textContent = scheme.id;
  if ($("#detailFolderName")) $("#detailFolderName").textContent = scheme.folderName || "";
  if ($("#detailReadyState")) {
    const ready = isSchemeReady(scheme);
    $("#detailReadyState").textContent = ready ? "可行 (已配置密钥)" : "草稿，需要先恢复写入";
    $("#detailReadyState").style.color = ready ? "#10b981" : "";
  }
  if ($("#detailSteamRow")) {
    if (scheme.isSteam) {
      $("#detailSteamRow").style.display = "flex";
      $("#detailSteamText").textContent = "是";
    } else {
      $("#detailSteamRow").style.display = "none";
    }
  }
  if ($("#editCompanyName")) $("#editCompanyName").value = scheme.company || "";
  if ($("#editGameName")) $("#editGameName").value = scheme.game || "";
  if ($("#editVersionName")) $("#editVersionName").value = scheme.version || "";
  if ($("#schemeText")) $("#schemeText").value = scheme.json || "";
  updateRenamePreview();
}

// ----- Scheme Creation & Modification -----
function updateCreatePreview() {
  const exe = $("#newExePath") ? $("#newExePath").value.trim() : "";
  const company = $("#newCompanyName") ? $("#newCompanyName").value.trim() : "";
  const game = $("#newGameName") ? $("#newGameName").value.trim() : "";
  const version = $("#newVersionName") ? $("#newVersionName").value.trim() : "";
  
  const title = (company ? company + " " : "") + game + " [" + version + "]";
  const rawId = (company ? company + " " + game + " " + version : game + " " + version).toLowerCase();
  const id = rawId.replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "game-local";
  const folder = company ? company + "/" + game + "/" + game + "[" + version + "]" : game + "/" + game + "[" + version + "]";

  if ($("#previewTitle")) $("#previewTitle").textContent = title;
  if ($("#previewId")) $("#previewId").textContent = id;
  if ($("#previewFolder")) $("#previewFolder").textContent = folder;
}

function updateRenamePreview() {
  const company = $("#editCompanyName") ? $("#editCompanyName").value.trim() : "";
  const game = $("#editGameName") ? ($("#editGameName").value.trim() || "Game") : "Game";
  const version = $("#editVersionName") ? ($("#editVersionName").value.trim() || "Local") : "Local";
  const folder = company ? company + "/" + game + "/" + game + "[" + version + "]" : game + "/" + game + "[" + version + "]";
  if ($("#renamePreview")) $("#renamePreview").textContent = folder;
}

["#newExePath", "#newCompanyName", "#newGameName", "#newVersionName", "#newLstPath"].forEach((sel) => {
  if ($(sel)) $(sel).addEventListener("input", updateCreatePreview);
});
["#editCompanyName", "#editGameName", "#editVersionName"].forEach((sel) => {
  if ($(sel)) $(sel).addEventListener("input", updateRenamePreview);
});



function openCreateGameModal(companyName) {
  if ($("#newCompanyName")) $("#newCompanyName").value = companyName || "";
  if ($("#newExePath")) $("#newExePath").value = "";
  if ($("#newGameName")) $("#newGameName").value = "";
  if ($("#newVersionName")) $("#newVersionName").value = "Local";
  if ($("#newLstPath")) $("#newLstPath").value = "";
  updateCreatePreview();
  const modal = $("#createSchemeModal");
  if (modal && modal.showModal) modal.showModal();
}

if ($("#openCreateModal")) $("#openCreateModal").addEventListener("click", () => {
  openCreateGameModal("");
});
if ($("#closeCreateModal")) $("#closeCreateModal").addEventListener("click", () => {
  const modal = $("#createSchemeModal");
  if (modal && modal.close) modal.close();
});

if ($("#createScheme")) $("#createScheme").addEventListener("click", () => {
  const exe = $("#newExePath") ? $("#newExePath").value.trim() : "";
  const company = $("#newCompanyName") ? $("#newCompanyName").value.trim() : "";
  const game = $("#newGameName") ? $("#newGameName").value.trim() : "";
  const version = $("#newVersionName") ? $("#newVersionName").value.trim() : "";
  const lst = $("#newLstPath") ? $("#newLstPath").value.trim() : "";
  if (!exe) return alert("请选择游戏 EXE！");
  if (!game) return alert("请填写游戏名！");
  if (!version) return alert("请填写版本名！");
  post({ type: "createScheme", exe, company, game, version, lst });
  const modal = $("#createSchemeModal");
  if (modal && modal.close) modal.close();
});

if ($("#renameScheme")) $("#renameScheme").addEventListener("click", () => {
  const scheme = selectedScheme();
  if (!scheme) return alert("请先选择方案");
  const company = $("#editCompanyName") ? $("#editCompanyName").value.trim() : "";
  const game = $("#editGameName") ? $("#editGameName").value.trim() : "";
  const version = $("#editVersionName") ? $("#editVersionName").value.trim() : "";
  if (!game || !version) return alert("游戏名和版本不能为空");
  post({ type: "renameScheme", schemeId: scheme.id, company, game, version });
});

if ($("#deleteScheme")) $("#deleteScheme").addEventListener("click", () => {
  const scheme = selectedScheme();
  if (!scheme) return;
  post({ type: "deleteScheme", schemeId: scheme.id });
});

// Pickers
document.querySelectorAll("[data-pick]").forEach((btn) => {
  btn.addEventListener("click", () => post({ type: "pick", target: btn.dataset.pick }));
});

// ----- Sub-Version Creation -----
let subVersionBaseId = "";

function openSubVersionModal(baseId, gameName) {
  subVersionBaseId = baseId;
  if ($("#subBaseGame")) $("#subBaseGame").textContent = gameName;
  if ($("#subVersionName")) $("#subVersionName").value = "";
  if ($("#subExePath")) $("#subExePath").value = "";
  const modal = $("#createSubVersionModal");
  if (modal && modal.showModal) modal.showModal();
}

if ($("#closeSubModal")) $("#closeSubModal").addEventListener("click", () => {
  const modal = $("#createSubVersionModal");
  if (modal && modal.close) modal.close();
});

if ($("#createSubVersion")) $("#createSubVersion").addEventListener("click", () => {
  const newVersion = $("#subVersionName") ? $("#subVersionName").value.trim() : "";
  const newExe = $("#subExePath") ? $("#subExePath").value.trim() : "";
  if (!newVersion) return alert("请填写新版本名！");
  if (!newExe) return alert("请选择新版本对应的游戏 EXE 程序！");
  post({
    type: "duplicateScheme",
    baseSchemeId: subVersionBaseId,
    newVersion: newVersion,
    newExe: newExe
  });
  const modal = $("#createSubVersionModal");
  if (modal && modal.close) modal.close();
});

// ----- Queue Logic -----
function uuid() {
  return Math.random().toString(36).substring(2, 10);
}

function renderQueue() {
  const list = $("#queueList");
  if (!list) return;

  if (state.queue.length === 0) {
    list.innerHTML = "<div class=\"queue-empty\">\n      <div style=\"font-size: 48px; margin-bottom: 12px;\">📦</div>\n      <p>还没有队列项目</p>\n      <small>点击「添加 XP3」开始添加封包</small>\n    </div>";
    if ($("#runQueue")) $("#runQueue").disabled = true;
    if ($("#queueStats")) $("#queueStats").textContent = "0 个任务";
    return;
  }

  list.innerHTML = "";
  state.queue.forEach((job, index) => {
    const item = document.createElement("div");
    let classes = "queue-item";
    if (job.status === "running") classes += " running";
    if (job.status === "done") classes += " done";
    item.className = classes;
    item.dataset.jobId = job.id;

    const leaf = job.xp3Path.split(/[\\/]/).pop();
    item.innerHTML = "<div class=\"queue-progress-bar\" style=\"width: " + (job.pct || "0%") + "\"></div>\n" +
      "<div class=\"queue-item-info\">\n        <strong>" + job.schemeName + "</strong>\n        <span title=\"" + job.xp3Path.replace(/"/g, "&quot;") + "\">XP3: " + leaf + "</span>\n        <span title=\"" + job.outDir.replace(/"/g, "&quot;") + "\">输出: " + job.outDir + "</span>\n      </div>\n      <div class=\"queue-item-status\">\n        " + 
      (job.status === 'running' ? '<div class=\"spinner\"></div> <span class=\"queue-item-status-text\" style=\"font-size:13px; font-weight:bold; color:#10b981\">' + (job.pct || '0%') + '</span>' : '') + 
      "\n        " + (job.status === 'done' ? '<span style=\"color:#10b981\">✅ 完成</span>' : '') + 
      "\n      </div>\n      <div class=\"queue-item-actions\">\n        <button class=\"ghost q-up\" title=\"上移\" " + (index === 0 || state.queueRunning ? 'disabled' : '') + ">⬆️</button>\n        <button class=\"ghost q-down\" title=\"下移\" " + (index === state.queue.length - 1 || state.queueRunning ? 'disabled' : '') + ">⬇️</button>\n        <button class=\"ghost q-del\" title=\"删除\" " + (state.queueRunning ? 'disabled' : '') + ">❌</button>\n      </div>";

    const upBtn = item.querySelector('.q-up');
    if (upBtn) upBtn.addEventListener('click', () => {
      if (index > 0) {
        const tmp = state.queue[index - 1];
        state.queue[index - 1] = state.queue[index];
        state.queue[index] = tmp;
        renderQueue();
      }
    });

    const downBtn = item.querySelector('.q-down');
    if (downBtn) downBtn.addEventListener('click', () => {
      if (index < state.queue.length - 1) {
        const tmp = state.queue[index + 1];
        state.queue[index + 1] = state.queue[index];
        state.queue[index] = tmp;
        renderQueue();
      }
    });

    const delBtn = item.querySelector('.q-del');
    if (delBtn) delBtn.addEventListener('click', () => {
      state.queue.splice(index, 1);
      renderQueue();
    });

    list.appendChild(item);
  });

  if ($("#runQueue")) $("#runQueue").disabled = state.queueRunning || state.queue.length === 0;
  const doneCount = state.queue.filter(j => j.status === 'done').length;
  if ($("#queueStats")) $("#queueStats").textContent = state.queue.length + " 个任务 (" + doneCount + " 已完成)";
}

if ($("#openAddQueueModal")) $("#openAddQueueModal").addEventListener("click", () => {
  const sel = $("#queueSchemeSelect");
  if (sel) {
    sel.innerHTML = "";
    state.schemes.filter(s => isSchemeReady(s)).forEach(scheme => {
      const opt = document.createElement("option");
      opt.value = scheme.id;
      opt.textContent = schemeLabel(scheme);
      sel.appendChild(opt);
    });
    if (state.selectedSchemeId && isSchemeReady(selectedScheme())) {
      sel.value = state.selectedSchemeId;
    }
  }
  state.pendingXp3Paths = [];
  updateQueuePreview();
  const modal = $("#addQueueModal");
  if (modal && modal.showModal) modal.showModal();
});
if ($("#closeAddQueueModal")) $("#closeAddQueueModal").addEventListener("click", () => {
  const modal = $("#addQueueModal");
  if (modal && modal.close) modal.close();
});

function updateQueuePreview() {
  const sel = $("#queueSchemeSelect");
  const scheme = state.schemes.find(s => s.id === (sel ? sel.value : ""));
  if (scheme) {
    if ($("#queueSchemePreview")) $("#queueSchemePreview").style.display = "block";
    if ($("#queuePreviewName")) $("#queuePreviewName").textContent = schemeLabel(scheme);
  } else {
    if ($("#queueSchemePreview")) $("#queueSchemePreview").style.display = "none";
  }

  const items = $("#queueXp3Items");
  if (state.pendingXp3Paths.length > 0) {
    if ($("#queueXp3List")) $("#queueXp3List").style.display = "block";
    if ($("#queueXp3Paths")) $("#queueXp3Paths").value = "已选择 " + state.pendingXp3Paths.length + " 个文件";
    if (items) items.innerHTML = "";
    state.pendingXp3Paths.forEach((p, idx) => {
      const div = document.createElement("div");
      div.textContent = p.split(/[\\/]/).pop();
      div.style.padding = "4px 8px";
      div.style.background = "var(--surface-hover)";
      div.style.borderRadius = "4px";
      div.style.display = "flex";
      div.style.justifyContent = "space-between";
      div.style.alignItems = "center";
      
      const removeBtn = document.createElement("span");
      removeBtn.innerHTML = "&times;";
      removeBtn.style.cursor = "pointer";
      removeBtn.style.fontSize = "16px";
      removeBtn.style.lineHeight = "1";
      removeBtn.style.color = "var(--muted)";
      removeBtn.onclick = (e) => {
        e.stopPropagation();
        state.pendingXp3Paths.splice(idx, 1);
        updateQueuePreview();
      };
      
      div.appendChild(removeBtn);
      if (items) items.appendChild(div);
    });
    
    // Output preview (using first file)
    const schemeId = $("#queueSchemeSelect") ? $("#queueSchemeSelect").value : "";
    const scheme = state.schemes.find(s => s.id === schemeId);
    const folder = scheme && scheme.folderName ? scheme.folderName + "/" : "";
    const firstXp3 = state.pendingXp3Paths[0];
    const leaf = firstXp3.split(/[\\/]/).pop().replace(/\.[^.]+$/, "");
    if ($("#queueOutPreview")) $("#queueOutPreview").style.display = "block";
    if ($("#queueOutPreviewText")) $("#queueOutPreviewText").textContent = (state.outRoot || "out/") + "/" + folder + leaf;
  } else {
    if ($("#queueXp3List")) $("#queueXp3List").style.display = "none";
    if ($("#queueXp3Paths")) $("#queueXp3Paths").value = "";
    if ($("#queueOutPreview")) $("#queueOutPreview").style.display = "none";
  }
}

if ($("#clearQueueXp3Btn")) $("#clearQueueXp3Btn").addEventListener("click", () => {
  state.pendingXp3Paths = [];
  updateQueuePreview();
});

if ($("#queueSchemeSelect")) $("#queueSchemeSelect").addEventListener("change", updateQueuePreview);

if ($("#confirmAddQueue")) $("#confirmAddQueue").addEventListener("click", () => {
  const sel = $("#queueSchemeSelect");
  const scheme = state.schemes.find(s => s.id === (sel ? sel.value : ""));
  if (!scheme) return alert("请选择有效的方案 (需要已经配好密钥的)");
  if (state.pendingXp3Paths.length === 0) return alert("请选择至少一个 XP3 文件");

  state.pendingXp3Paths.forEach(xp3Path => {
    const leaf = xp3Path.split(/[\\/]/).pop().replace(/\.[^.]+$/, "");
    const folder = scheme && scheme.folderName ? scheme.folderName + "\\" : "";
    const outDir = (state.outRoot || "out\\") + "\\" + folder + leaf;
    state.queue.push({
      id: uuid(),
      schemeId: scheme.id,
      schemeName: schemeLabel(scheme),
      exe: "",
      xp3Path: xp3Path,
      outDir: outDir,
      status: "pending",
      pct: "0%"
    });
  });

  renderQueue();
  const modal = $("#addQueueModal");
  if (modal && modal.close) modal.close();
});

if ($("#clearQueue")) $("#clearQueue").addEventListener("click", () => {
  if (state.queueRunning) return alert("队列正在运行中，无法清空");
  if (confirm("确定要清空队列吗？")) {
    state.queue = [];
    renderQueue();
  }
});

function runNextQueueJob() {
  const job = state.queue.find(j => j.status === "pending");
  if (!job) {
    state.queueRunning = false;
    state.queueCurrentJobId = null;
    renderQueue();
    appendLog("== 队列执行完毕 ==");
    updateGlobalProgress();
    return;
  }

  state.queueRunning = true;
  state.queueCurrentJobId = job.id;
  job.status = "running";
  renderQueue();

  post({
    type: "action",
    action: "extract",
    schemeId: job.schemeId,
    exe: job.exe,
    xp3: job.xp3Path,
    out: job.outDir,
    verifyCount: 20,
    jobId: job.id
  });
}

if ($("#runQueue")) $("#runQueue").addEventListener("click", () => {
  if (state.queueRunning) return;
  if (state.queue.filter(j => j.status === "pending").length === 0) {
    state.queue.forEach(j => {
      j.status = "pending";
      j.pct = "0%";
      j.current = 0;
      j.total = 0;
    });
  }
  appendLog("== 开始执行队列 ==");
  updateGlobalProgress();
  runNextQueueJob();
});

function updateGlobalProgress() {
  if (!state.queueRunning || state.queue.length === 0) {
    if ($("#queueGlobalProgress")) $("#queueGlobalProgress").style.display = "none";
    return;
  }
  let totalJobs = state.queue.length;
  let completedPct = 0;
  state.queue.forEach(j => {
    if (j.status === "done") {
      completedPct += 100;
    } else if (j.status === "running" && j.total > 0) {
      completedPct += (j.current / j.total) * 100;
    }
  });
  const globalPct = (completedPct / totalJobs).toFixed(1) + "%";
  if ($("#queueGlobalProgress")) {
    $("#queueGlobalProgress").style.display = "inline";
    $("#queueGlobalProgress").textContent = "总进度: " + globalPct;
  }
  const rootProgressBar = $("#progressBar");
  if (rootProgressBar && rootProgressBar.parentElement.style.display !== "none") {
    rootProgressBar.value = completedPct / totalJobs;
  }
}

// ----- IPC Messages -----
if (window.__TAURI__) {
  window.__TAURI__.event.listen("backend-message", (event) => {
    const msg = typeof event.payload === "string" ? JSON.parse(event.payload) : event.payload;
    
    if (msg.type === "init") {
      state.schemes = msg.schemes || [];
      state.selectedSchemeId = msg.selectedScheme || (state.schemes[0] ? state.schemes[0].id : "");
      state.outRoot = msg.outRoot || "";
      if ($("#queueOutRootPath")) $("#queueOutRootPath").value = state.outRoot;
      renderSchemes();
      selectScheme(state.selectedSchemeId);
    }
    
    else if (msg.type === "schemeRecovered") {
      if (msg.message) appendLog(msg.message);
      if (msg.ok && msg.schemes) {
        state.schemes = msg.schemes;
        selectScheme(msg.scheme.id);
      }
    }
    
    else if (msg.type === "schemeCreated" || msg.type === "schemeRenamed" || msg.type === "schemeDeleted" || msg.type === "schemeDuplicated") {
      if (msg.message) appendLog(msg.message);
      if (msg.ok && msg.schemes) {
        state.schemes = msg.schemes;
        selectScheme(msg.scheme ? msg.scheme.id : (state.schemes[0] ? state.schemes[0].id : ""));
      }
    }

    else if (msg.type === "pickedMulti" && msg.target === "queueXp3") {
      const newPaths = msg.paths || [];
      newPaths.forEach(p => {
        if (!state.pendingXp3Paths.includes(p)) {
          state.pendingXp3Paths.push(p);
        }
      });
      updateQueuePreview();
    }
    
    else if (msg.type === "picked") {
      if (msg.target === "schemeExe") {
        if ($("#newExePath")) $("#newExePath").value = msg.path;
        updateCreatePreview();
      }
      else if (msg.target === "schemeLst") {
        if ($("#newLstPath")) $("#newLstPath").value = msg.path;
        updateCreatePreview();
      }
      else if (msg.target === "subExe") {
        if ($("#subExePath")) $("#subExePath").value = msg.path;
      }
      else if (msg.target === "lstExe") {
        if ($("#lstExePath")) {
          $("#lstExePath").value = msg.path;
          const leaf = msg.path.split(/[\\/]/).pop().replace(/\.[^.]+$/, "");
          if ($("#lstOutputName")) $("#lstOutputName").value = leaf + "_lst.lst";
          updateLstPreview();
        }
      }
      else if (msg.target === "lstBase") {
        if ($("#lstBasePath")) {
          $("#lstBasePath").value = msg.path;
          updateLstPreview();
        }
      }
      else if (msg.target === "queueOutRoot") {
        state.outRoot = msg.path;
        if ($("#queueOutRootPath")) $("#queueOutRootPath").value = state.outRoot;
        updateQueuePreview();
      }
    }
    
    else if (msg.type === "log") {
      appendLog(msg.text);
    }
    
    else if (msg.type === "recoveryLog") {
      if ($("#lstPageLogOutput")) {
        if ($("#lstPageLogOutput").textContent === "等待执行...") {
          $("#lstPageLogOutput").textContent = "";
        }
        $("#lstPageLogOutput").textContent += msg.text;
        $("#lstPageLogOutput").scrollTop = $("#lstPageLogOutput").scrollHeight;
      }
      if ($("#logOutput")) {
        $("#logOutput").textContent += msg.text;
        $("#logOutput").parentElement.scrollTop = $("#logOutput").parentElement.scrollHeight;
      }
    }
    
    else if (msg.type === "recoveryDone") {
      const statusText = msg.ok ? "\n\n[成功] LST 制作完成！\n" : `\n\n[失败] 发生错误: ${msg.error}\n`;
      if ($("#lstPageLogOutput")) {
        $("#lstPageLogOutput").textContent += statusText;
        $("#lstPageLogOutput").scrollTop = $("#lstPageLogOutput").scrollHeight;
      }
      if ($("#logOutput")) {
        $("#logOutput").textContent += statusText;
        $("#logOutput").parentElement.scrollTop = $("#logOutput").parentElement.scrollHeight;
      }
      if ($("#closeLogModal")) $("#closeLogModal").style.display = "block";
    }
    
    else if (msg.type === "progress") {
      if (msg.jobId) {
        const job = state.queue.find(j => j.id === msg.jobId);
        if (job) {
          job.current = msg.current;
          job.total = msg.total;
          if (job.total > 0) {
            job.pct = (job.current / job.total * 100).toFixed(1) + "%";
            const itemEl = document.querySelector(`.queue-item[data-job-id="${job.id}"]`);
            if (itemEl) {
              const bar = itemEl.querySelector('.queue-progress-bar');
              if (bar) bar.style.width = job.pct;
              const statusText = itemEl.querySelector('.queue-item-status-text');
              if (statusText) statusText.textContent = job.pct;
            }
          }
        }
      }
      updateGlobalProgress();
    }
    
    else if (msg.type === "done") {
      if (state.queueRunning && state.queueCurrentJobId) {
        const job = state.queue.find(j => j.id === state.queueCurrentJobId);
        if (job) {
          job.status = msg.ok ? "done" : "error";
          if (msg.ok) {
            job.current = job.total = 100;
            job.pct = "100%";
          }
        }
        renderQueue();
        updateGlobalProgress();
        runNextQueueJob();
      }
    }
  });
}

// ----- LST Recovery -----
function updateLstPreview() {
  const exePath = $("#lstExePath") ? $("#lstExePath").value : "";
  const outputName = $("#lstOutputName") ? $("#lstOutputName").value : "";
  const preview = $("#lstSchemePreview");
  
  if (exePath && outputName && preview) {
    preview.style.display = "block";
    if ($("#lstPreviewName")) $("#lstPreviewName").textContent = "将生成: " + outputName;
    const dir = exePath.substring(0, exePath.lastIndexOf("\\")) || exePath.substring(0, exePath.lastIndexOf("/"));
    if ($("#lstPreviewDir")) $("#lstPreviewDir").textContent = dir || exePath;
    if ($("#lstPreviewOut")) $("#lstPreviewOut").textContent = "lstoutput\\" + outputName;
  } else if (preview) {
    preview.style.display = "none";
  }
}

if ($("#lstOutputName")) $("#lstOutputName").addEventListener("input", updateLstPreview);
if ($("#lstExePath")) $("#lstExePath").addEventListener("input", updateLstPreview);

if ($("#clearLstBaseBtn")) $("#clearLstBaseBtn").addEventListener("click", () => {
  if ($("#lstBasePath")) $("#lstBasePath").value = "";
  updateLstPreview();
});

if ($("#generateLstBtnPage")) $("#generateLstBtnPage").addEventListener("click", () => {
  const exePath = $("#lstExePath") ? $("#lstExePath").value : "";
  const baseLst = $("#lstBasePath") ? $("#lstBasePath").value : "";
  const outputName = $("#lstOutputName") ? $("#lstOutputName").value : "";
  
  if (!exePath) return alert("请先选择游戏主程序 (EXE)！");
  if (!outputName) return alert("请输入输出文件名！");
  
  if ($("#logModal") && $("#logModal").showModal) $("#logModal").showModal();
  if ($("#logOutput")) $("#logOutput").textContent = "开始提取参数并生成 LST...\n";
  if ($("#lstPageLogOutput")) $("#lstPageLogOutput").textContent = "开始提取参数并生成 LST...\n";
  if ($("#closeLogModal")) $("#closeLogModal").style.display = "none";
  
  post({
    type: "generateLst",
    exePath: exePath,
    baseLst: baseLst,
    outputName: outputName
  });
});

if ($("#closeLogModal")) $("#closeLogModal").addEventListener("click", () => {
  if ($("#logModal") && $("#logModal").close) $("#logModal").close();
});

// Initialization
document.addEventListener("DOMContentLoaded", () => {
  renderSchemes();
  renderQueue();
  post({ type: "ready" });
});
