 // Lightweight canvas charts — no external libraries required.
    function setupCanvas(canvas) {
      const ratio = window.devicePixelRatio || 1;
      const rect = canvas.getBoundingClientRect();
      canvas.width = rect.width * ratio;
      canvas.height = rect.height * ratio;
      const ctx = canvas.getContext("2d");
      ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
      return { ctx, w: rect.width, h: rect.height };
    }

    function drawLineChart(canvasId, data, labels) {
      const canvas = document.getElementById(canvasId);
      const {ctx, w, h} = setupCanvas(canvas);
      const pad = {l: 38, r: 12, t: 18, b: 30};
      const chartW = w - pad.l - pad.r;
      const chartH = h - pad.t - pad.b;
      const max = Math.ceil(Math.max(...data) / 500) * 500;

      ctx.clearRect(0,0,w,h);
      ctx.font = "10px Inter, sans-serif";
      ctx.lineWidth = 1;

      // Grid
      for (let i = 0; i <= 4; i++) {
        const y = pad.t + chartH * i / 4;
        ctx.strokeStyle = "#223047";
        ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(w-pad.r, y); ctx.stroke();
        ctx.fillStyle = "#718097";
        ctx.fillText(String(Math.round(max - max*i/4)), 2, y+3);
      }

      // X labels
      labels.forEach((label, i) => {
        const x = pad.l + chartW * i / (labels.length-1);
        ctx.fillStyle = "#718097";
        ctx.fillText(label, x-9, h-8);
      });

      // Area
      const points = data.map((v,i) => ({
        x: pad.l + chartW * i / (data.length-1),
        y: pad.t + chartH - (v/max)*chartH
      }));

      ctx.beginPath();
      ctx.moveTo(points[0].x, pad.t+chartH);
      points.forEach(p => ctx.lineTo(p.x,p.y));
      ctx.lineTo(points.at(-1).x,pad.t+chartH);
      ctx.closePath();
      ctx.fillStyle = "rgba(79,140,255,.09)";
      ctx.fill();

      ctx.beginPath();
      points.forEach((p,i) => i ? ctx.lineTo(p.x,p.y) : ctx.moveTo(p.x,p.y));
      ctx.strokeStyle = "#5b8ff9";
      ctx.lineWidth = 2;
      ctx.stroke();

      points.forEach(p => {
        ctx.beginPath();
        ctx.arc(p.x,p.y,3,0,Math.PI*2);
        ctx.fillStyle = "#8fb5ff";
        ctx.fill();
      });
    }

    function showToast(message) {
      const toast = document.getElementById("toast");
      toast.textContent = message;
      toast.classList.add("show");
      clearTimeout(window.toastTimer);
      window.toastTimer = setTimeout(() => toast.classList.remove("show"), 2400);
    }

    const hours = ["00","02","04","06","08","10","12","14","16","18","20","22"];
    drawLineChart("eventsChart", [620,710,540,830,1180,1420,1160,1740,2210,1980,2410,1850], hours);

    const days = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"];
    drawLineChart("riskChart", [34,39,44,51,63,69,72], days);

    window.addEventListener("resize", () => {
      drawLineChart("eventsChart", [620,710,540,830,1180,1420,1160,1740,2210,1980,2410,1850], hours);
      drawLineChart("riskChart", [34,39,44,51,63,69,72], days);
    });

    document.querySelectorAll(".nav a").forEach(link => {
      link.addEventListener("click", e => {
        e.preventDefault();
        document.querySelectorAll(".nav a").forEach(x => x.classList.remove("active"));
        link.classList.add("active");
        showToast(link.dataset.page + " module selected");
      });
    });

    document.getElementById("dateBtn").addEventListener("click", () => {
      showToast("Time filter: Last 24 hours");
    });

    document.getElementById("notifyBtn").addEventListener("click", () => {
      showToast("You have 4 active security alerts");
    });

    document.getElementById("searchInput").addEventListener("input", e => {
      const query = e.target.value.toLowerCase().trim();
      document.querySelectorAll(".alert").forEach(alert => {
        alert.style.display = !query || alert.dataset.search.includes(query) ? "grid" : "none";
      });
    });

    document.querySelectorAll("[data-ai]").forEach(button => {
      button.addEventListener("click", () => {
        const action = button.dataset.ai;
        const box = document.getElementById("aiBox");

        if (action === "Explain this alert") {
          box.innerHTML = "<strong>AI explanation:</strong><br>Repeated failed authentication attempts from one source can indicate credential guessing or brute-force activity. Correlate the source IP with other accounts, timestamps, and successful logins.";
        } else if (action === "Summarize recent threats") {
          box.innerHTML = "<strong>Threat summary:</strong><br>Current alerts are dominated by authentication anomalies, suspicious IP activity, and privilege-related signals. Critical alerts should be prioritized for investigation.";
        } else {
          box.innerHTML = "<strong>Suggested investigation:</strong><br>Review the source IP, inspect related authentication events, check whether another account was targeted, examine successful logins, and compare activity with the risk score.";
        }
        showToast("AI assistant response generated");
      });
    });