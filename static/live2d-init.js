// Live2D 看板娘初始化 - Miku 模型
(function () {
    if (screen.width < 768) return;

    var live2d_path = "https://fastly.jsdelivr.net/gh/stevenjoezhang/live2d-widget@latest/";
    var miku_model = "https://unpkg.com/live2d-widget-model-miku@1.0.5/assets/miku.model.json";

    // 加载 CSS
    var link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = live2d_path + "waifu.css";
    document.head.appendChild(link);

    // 加载 live2d.min.js
    var script = document.createElement("script");
    script.src = live2d_path + "live2d.min.js";
    script.onload = function () {
        // 创建 canvas
        var canvas = document.createElement("canvas");
        canvas.id = "live2d";
        canvas.width = 300;
        canvas.height = 400;
        canvas.style.cssText = "position:fixed;bottom:0;left:0;z-index:999;pointer-events:none;";
        document.body.appendChild(canvas);

        // 加载 Miku 模型
        loadlive2d("live2d", miku_model);
    };
    document.head.appendChild(script);
})();
